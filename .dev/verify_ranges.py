"""Script to verify IP ranges of third party servers."""  # pylint: disable=too-many-lines

import argparse
import ast
import contextlib
import ipaddress
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

import geoip2.database
import geoip2.errors
import requests
from rich import box
from rich.columns import Columns
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# Add src/ folder to path so it can import session_sniffer
SOURCE_PATH = str(Path(__file__).resolve().parent.parent / 'src')
if SOURCE_PATH not in sys.path:
    sys.path.insert(0, SOURCE_PATH)

from session_sniffer.networking.http_session import HEADERS  # pylint: disable=wrong-import-position  # noqa: E402

# Dedicated session for ip-api.com with NO automatic retries.
# The shared `session` from http_session.py has urllib3 Retry(total=3) which silently
# retries failed POSTs 3x before the RateLimitClient even sees the error — causing
# 4x the actual traffic and triggering server-side connection drops.
_ip_api_session = requests.Session()
_ip_api_session.headers.update(HEADERS)

try:
    from session_sniffer.utils import get_app_dir
except ImportError:

    def get_app_dir(*, scope: Literal['roaming', 'local']) -> Path:
        """Get the application directory."""
        del scope
        base_path = Path(os.getenv('LOCALAPPDATA', str(Path.home() / 'AppData' / 'Local')))
        application_directory = base_path / 'Session Sniffer'
        application_directory.mkdir(parents=True, exist_ok=True)
        return application_directory


console = Console()

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Mapping

    from rich.console import RenderableType
    from rich.status import Status

IP_API_BATCH_URL = 'http://ip-api.com/batch'
THROTTLING_RATE_LIMIT_THRESHOLD = 3
COOLDOWN_HTTP_STATUS = 429
EXPECTED_ARGS_COUNT = 2
MIN_WORD_LENGTH = 4
MAX_SAMPLES = 20
API_BATCH_LIMIT = 100
SUBNET_BLOCK_SIZE = 256  # /24 boundary alignment
MAX_DISPLAYED_OWNERS = 3
STALE_CONNECTION_THRESHOLD = 10  # seconds; close pooled connections after sleeps longer than this
MAX_ERROR_BACKOFF = 120


class RateLimitClient:  # pylint: disable=too-few-public-methods
    """Client for querying the IP API with rate limiting."""

    session: requests.Session
    min_interval: float
    last_request_time: float
    cooldown_until: float
    last_rate_limit: int | None
    capacity: int
    window: int
    tokens: float
    last_refill: float
    consecutive_errors: int
    cache: dict[str, dict[str, Any]]
    sleep_callback: Callable[[float, str], None] | None

    def __init__(self, session: requests.Session) -> None:
        """Initialize the RateLimitClient."""
        self.session = session
        self.min_interval = 60 / 14  # slightly conservative (14 req/min instead of 15)
        self.last_request_time = 0.0
        self.cooldown_until = 0.0
        self.last_rate_limit = None
        self.capacity = 14  # leave 1 token headroom vs the 15 API limit
        self.window = 60
        self.tokens = float(self.capacity)
        self.last_refill = time.time()
        self.consecutive_errors = 0
        self.cache = {}
        self.sleep_callback = None

    def _refill(self) -> None:
        """Refill the token bucket gradually based on elapsed time."""
        now = time.time()
        elapsed_seconds = now - self.last_refill

        if elapsed_seconds > 0:
            # Gradual refill: tokens accrue proportionally over time
            tokens_to_add = elapsed_seconds * (self.capacity / self.window)
            self.tokens = min(self.tokens + tokens_to_add, float(self.capacity))
            self.last_refill = now

    def _wait_for_cooldown(self) -> None:
        """Block until any active cooldown period has expired."""
        now = time.time()
        if now < self.cooldown_until:
            wait = self.cooldown_until - now
            console.print(f'[yellow]\\[COOLDOWN] waiting[/yellow] → [yellow]sleeping {int(wait) + 1}s[/yellow]')
            self._sleep(wait + 1, 'COOLDOWN waiting')
            self._close_stale_connections(wait + 1)
            # Rate window has passed — reset tokens
            self.tokens = float(self.capacity)
            self.last_refill = time.time()
            self.cooldown_until = 0.0

    def _close_stale_connections(self, sleep_duration: float) -> None:
        """Close pooled TCP connections if the sleep was long enough to make them stale."""
        if sleep_duration >= STALE_CONNECTION_THRESHOLD:
            self.session.close()

    def _respect_min_interval(self) -> None:
        """Ensure requests are spaced out by at least the minimum interval."""
        now = time.time()
        wait = self.min_interval - (now - self.last_request_time)
        if wait > 0:
            self._sleep(wait, 'API spacing')

    def _apply_headers(self, headers: Mapping[str, str]) -> None:
        """Apply rate limit headers from the API response.

        This method does NOT sleep. It records the rate-limit state so that
        ``_consume`` / ``_wait_for_cooldown`` will pause before the **next**
        request, avoiding double-sleeps when recovering from a 429.
        """
        rate_limit_str = headers.get('X-Rl')

        rate_limit: int | None = None
        if rate_limit_str is not None:
            with contextlib.suppress(ValueError):
                rate_limit = int(rate_limit_str)

        self.last_rate_limit = rate_limit

        # Sync internal token count with server-reported remaining requests
        if rate_limit is not None:
            self.tokens = min(float(rate_limit), float(self.capacity))

    def _sleep(self, seconds: float, reason: str) -> None:
        """Sleep for the specified duration, using the sleep callback if registered."""
        callback = self.sleep_callback
        if callback is not None:
            try:
                callback(seconds, reason)
            except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001, S110
                pass
            else:
                return
        time.sleep(seconds)

    def _consume(self) -> None:
        """Consume a token from the bucket, throttling if necessary."""
        self._wait_for_cooldown()

        while True:
            self._refill()

            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return

            # Calculate wait based on gradual refill rate, not the full window
            tokens_needed = 1.0 - self.tokens
            refill_rate = self.capacity / self.window  # tokens per second
            sleep_time = max(tokens_needed / refill_rate, 1.0)

            console.print(f'[yellow]\\[RATE] throttling[/yellow] → [yellow]sleeping {int(sleep_time)}s[/yellow]')
            self._sleep(sleep_time, 'RATE throttling')

    def post_batch(self, payload: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Post a batch of IPs to the rate-limited API."""
        self._consume()
        self._respect_min_interval()

        while True:
            try:
                response = self.session.post(
                    IP_API_BATCH_URL,
                    json=payload,
                    timeout=30,
                )

                self.last_request_time = time.time()
                self.consecutive_errors = 0  # reset on successful connection

                if response.status_code == COOLDOWN_HTTP_STATUS:
                    time_to_live_str = response.headers.get('X-Ttl')

                    try:
                        time_to_live = int(time_to_live_str) if time_to_live_str else 60
                    except ValueError:
                        time_to_live = 60

                    # always use fresh TTL, minimum 1s
                    wait_time = max(time_to_live + 1, 1)

                    # track cooldown deadline and drain tokens
                    self.cooldown_until = time.time() + wait_time
                    self.tokens = 0.0

                    console.print(f'[yellow]\\[429] cooldown[/yellow] → [yellow]sleeping {wait_time}s[/yellow]')

                    self._sleep(wait_time, '429 cooldown')
                    self._close_stale_connections(wait_time)

                    # After cooldown, refill tokens
                    self.tokens = float(self.capacity)
                    self.last_refill = time.time()
                    continue

                response.raise_for_status()

                self._apply_headers(response.headers)

                return cast('list[dict[str, Any]]', response.json())

            except requests.RequestException as e:
                self.consecutive_errors += 1
                # Exponential backoff: 10s, 20s, 40s, 80s, 120s (capped)
                backoff = min(10 * (2 ** (self.consecutive_errors - 1)), MAX_ERROR_BACKOFF)
                console.print(f'[red]\\[ERROR] Request failed (attempt {self.consecutive_errors}): {e}[/red]')
                console.print(f'[yellow]\\[BACKOFF] sleeping {backoff}s[/yellow]')
                self._sleep(backoff, 'BACKOFF retry')
                self._close_stale_connections(backoff)


class GeoLite2Client:
    """Offline lookup client using local GeoLite2 database."""

    reader: geoip2.database.Reader
    cache: dict[str, dict[str, Any]]
    sleep_callback: Callable[[float, str], None] | None

    def __init__(self, db_path: Path) -> None:
        """Initialize the GeoLite2Client database reader."""
        self.reader = geoip2.database.Reader(db_path)
        self.cache = {}
        self.sleep_callback = None

    def post_batch(self, payload: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Look up IP details from local GeoLite2 ASN database."""
        results: list[dict[str, Any]] = []
        for item in payload:
            ip = item['query']
            lookup_result = {
                'query': ip,
                'status': 'fail',
                'message': 'address not found',
                'isp': '',
                'org': '',
                'as': '',
                'asname': '',
            }
            try:
                record = self.reader.asn(ip)
                organization = record.autonomous_system_organization or ''
                autonomous_system_number = f'AS{record.autonomous_system_number}' if record.autonomous_system_number else ''
                lookup_result.update(
                    {
                        'status': 'success',
                        'message': '',
                        'isp': organization,
                        'org': organization,
                        'as': autonomous_system_number,
                        'asname': organization,
                    },
                )
            except geoip2.errors.AddressNotFoundError:
                pass
            except Exception as e:  # pylint: disable=broad-exception-caught  # noqa: BLE001
                lookup_result['message'] = str(e)
            results.append(lookup_result)
        return results

    def close(self) -> None:
        """Close the database reader."""
        self.reader.close()


def lookup_ips_batch(client: RateLimitClient | GeoLite2Client, ip_addresses: list[str]) -> dict[str, dict[str, Any]]:
    """Look up details for a batch of IP addresses, chunking to respect API limits."""
    results: dict[str, dict[str, Any]] = {}
    missing_ips: list[str] = []

    for ip in ip_addresses:
        if ip in client.cache:
            results[ip] = client.cache[ip]
        else:
            missing_ips.append(ip)

    if missing_ips:
        for batch in chunked(missing_ips, API_BATCH_LIMIT):
            payload: list[dict[str, Any]] = [{'query': ip, 'fields': 'status,message,query,isp,org,as,asname'} for ip in batch]
            batch_results = client.post_batch(payload)
            batch_dict = {cast('str', result.get('query')): result for result in batch_results}
            client.cache.update(batch_dict)
            results.update(batch_dict)

    return results


def extract_ranges(file_path: str) -> list[tuple[str, str, int]]:
    """Extract NamedRange definitions from a python source file using AST."""
    with Path(file_path).open(encoding='utf-8') as f:
        tree = ast.parse(f.read())
    extracted_ranges: list[tuple[str, str, int]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'NamedRange' and len(node.args) == EXPECTED_ARGS_COUNT:
            arg_a, arg_b = node.args
            if isinstance(arg_a, ast.Constant) and isinstance(arg_a.value, str) and isinstance(arg_b, ast.Constant) and isinstance(arg_b.value, str):
                extracted_ranges.append((arg_a.value, arg_b.value, node.lineno))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'create_named_ranges' and len(node.args) >= EXPECTED_ARGS_COUNT:
            owner_node = node.args[0]
            if isinstance(owner_node, ast.Constant) and isinstance(owner_node.value, str):
                owner = owner_node.value
                for arg in node.args[1:]:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        line_number = getattr(arg, 'lineno', None) or node.lineno
                        extracted_ranges.append((owner, arg.value, line_number))

    return extracted_ranges


def sample_ips(network: ipaddress.IPv4Network, max_samples: int = MAX_SAMPLES) -> list[str]:
    """Generate representative IP samples from an IPv4 network.

    Always includes boundaries and evenly-distributed /24-aligned IPs,
    capped at max_samples total.
    """
    samples: set[ipaddress.IPv4Address] = set()

    # ALWAYS include boundaries
    samples.add(network.network_address)
    samples.add(network.broadcast_address)

    start = int(network.network_address)
    end = int(network.broadcast_address)
    total_range = end - start

    # calculate step to distribute remaining samples evenly across the range
    interior_count = max(max_samples - len(samples), 1)
    step = max(total_range // interior_count, 1)

    # align step to /24 boundary
    step = max(step - (step % SUBNET_BLOCK_SIZE), SUBNET_BLOCK_SIZE) if step >= SUBNET_BLOCK_SIZE else max(step, 1)

    current = start
    while current <= end and len(samples) < max_samples:
        ip_int = current - (current % 256)  # align to .0
        aligned = ipaddress.IPv4Address(ip_int)

        if network.network_address <= aligned <= network.broadcast_address:
            samples.add(aligned)

        current += step

    return sorted(map(str, samples))


def normalize(text: str) -> str:
    """Normalize text by converting to lowercase and replacing punctuation with spaces."""
    return text.lower().replace(',', ' ').replace('(', ' ').replace(')', ' ').replace('-', ' ')


def _tokenize_owner(owner: str) -> set[str]:
    """Extract distinctive match tokens from an owner name.

    Unlike ``normalize()``, this also splits on dots so that legal-suffix
    abbreviations (``S.A.`` → ``s`` ``a``, ``B.V`` → ``b`` ``v``,
    ``s.r.l.`` → ``s`` ``r`` ``l``) collapse to single-character tokens
    that are then filtered out by the ``MIN_WORD_LENGTH`` check — no need
    to enumerate every international company-form abbreviation.
    """
    # Replace dots (and other punctuation) with spaces before splitting
    text = re.sub(r'[.()/]', ' ', owner.lower()).replace(',', ' ').replace('-', ' ')
    words = {word.strip('.,/') for word in text.split()}
    words = {word for word in words if len(word) >= MIN_WORD_LENGTH}
    words -= GENERIC_WORDS
    return words


# Custom exception list: Map an expected owner to a list of exact ISP/Org strings that
# trigger false positive matches (e.g., 'DXC' matching 'Microsoft' due to the word 'Corporation').
# These will be explicitly treated as different/unrelated ISPs.
KNOWN_FALSE_POSITIVES: dict[str, list[str]] = {
    'Microsoft Corporation': [
        'digital highway corporation',
        'dxc us latin america corporation',
        'shanghai blue cloud technology',
    ],
    'Amazon.com, Inc.': [
        'amazon data services',
        'amazon technologies',
    ],
    'Demonware Limited': [
        'datacamp limited',
        'orbit telekom sanayi',
    ],
    'Take-Two Interactive Software, Inc.': [
        'frontier communications of america',
    ],
}

# Custom aliases list: Map an expected owner to a list of exact ISP/Org strings that
# SHOULD be considered a match (e.g., 'DoD Network Information Center' for 'US Department of Defense').
KNOWN_ALIASES: dict[str, list[str]] = {
    'The Constant Company, LLC': [
        'vultr',
        'choopa',
    ],
    'OVH SAS': [
        'ovh',
    ],
    'Discord': [
        'i3d.net b.v',
    ],
    # i3D.net B.V produces empty tokens after dot-splitting (i3d/net/b/v all < 4 chars).
    # Register its own name fragments as aliases so the alias path handles it.
    'i3D.net B.V': [
        'i3d.net',
        'i3d',
    ],
}

GENERIC_WORDS: set[str] = {
    # English legal / structural words
    'association',
    'avenue',
    'building',
    'communication',
    'communications',
    'company',
    'corp',           # short form of 'corporation'
    'corporation',
    'group',
    'hosting',
    'inc',
    'incorporated',
    'interactive',
    'labs',
    'limited',
    'llp',            # Limited Liability Partnership
    'ltd',
    # Non-English legal suffixes (>= 4 chars; shorter ones like bv/nv/oy/sa/ab/sas/srl
    # are already excluded by MIN_WORD_LENGTH=4; dot-abbreviations like 's.a.' are
    # handled by _tokenize_owner() splitting on dots, yielding single-char tokens)
    'bvba',           # Belgian
    'gmbh',           # German (Gesellschaft mit beschränkter Haftung)
    'ltda',           # Brazilian Portuguese
    # Generic business-domain words
    'network',
    'networks',
    'services',
    'software',
    'solutions',
    'technologies',
    'technology',
    'telecom',
    'telecommunications',
}


def owner_matches(expected: str, data: dict[str, Any]) -> bool:
    """Check if the expected owner matches the IP API response data."""
    actual = normalize(
        f'{data.get("isp", "")} {data.get("org", "")} {data.get("asname", "")} {data.get("as", "")}',
    )

    # Check custom exception list first
    for false_positive in KNOWN_FALSE_POSITIVES.get(expected, []):
        if normalize(false_positive) in actual:
            return False

    # Check custom alias list next
    for alias in KNOWN_ALIASES.get(expected, []):
        if normalize(alias) in actual:
            return True

    words = _tokenize_owner(expected)
    if not words:
        # Fallback: include all tokens that survive the length filter, even generic ones
        text = re.sub(r'[.()/]', ' ', expected.lower()).replace(',', ' ').replace('-', ' ')
        words = {word.strip('.,/') for word in text.split()}
        words = {word for word in words if len(word) >= MIN_WORD_LENGTH}

    if not words:
        # Cannot determine ownership from an empty token set — treat as no match
        return False

    # Use whole-word (word-boundary) matching to avoid substring false-positives.
    # Example: 'cloud' must NOT match inside 'Cloudflare'; 'take' must NOT match
    # inside 'Stakelogic'.  re.search with \b anchors enforces this.
    return any(bool(re.search(r'\b' + re.escape(word) + r'\b', actual)) for word in words)


def chunked(list_to_chunk: list[Any], chunk_size: int) -> Generator[list[Any]]:
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(list_to_chunk), chunk_size):
        yield list_to_chunk[i : i + chunk_size]


def _block_to_ip(block_index: int) -> str:
    """Convert a /24 block index to its .0 IP address string."""
    return str(ipaddress.IPv4Address(block_index * SUBNET_BLOCK_SIZE))


def _ip_to_block(ip_str: str) -> int:
    """Convert an IP address string to its /24 block index."""
    return int(ipaddress.IPv4Address(ip_str)) // SUBNET_BLOCK_SIZE


def _check_block_owner(
    client: RateLimitClient | GeoLite2Client,
    owner: str,
    block_index: int,
    cache: dict[int, bool],
) -> bool:
    """Check if a /24 block's .0 IP belongs to the expected owner. Results are cached."""
    if block_index in cache:
        return cache[block_index]

    ip = _block_to_ip(block_index)
    results = lookup_ips_batch(client, [ip])
    lookup_result = results.get(ip) or {}

    is_match = lookup_result.get('status') == 'success' and owner_matches(owner, lookup_result)
    cache[block_index] = is_match
    return is_match


def _binary_search_transition(
    client: RateLimitClient | GeoLite2Client,
    owner: str,
    low_index: int,
    high_index: int,
    cache: dict[int, bool],
) -> None:
    """Binary search between two /24 block indices with different owner classifications.

    Populates cache entries to pinpoint the exact transition boundary.
    Precondition: cache[lo] != cache[hi] and hi > lo.
    """
    while high_index - low_index > 1:
        middle_index = (low_index + high_index) // 2
        _check_block_owner(client, owner, middle_index, cache)

        if cache[middle_index] == cache[low_index]:
            low_index = middle_index
        else:
            high_index = middle_index


def scan_network_geolite2(
    client: GeoLite2Client,
    owner: str,
    network: ipaddress.IPv4Network,
) -> tuple[list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address, str]], list[ipaddress.IPv4Network]]:
    """Scan the entire IPv4 network block using GeoLite2 mmdb, returning mismatches and matching subnets."""
    current_ip = network.network_address
    end_ip = network.broadcast_address

    mismatches: list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address, str]] = []
    matching_ranges: list[ipaddress.IPv4Network] = []

    while current_ip <= end_ip:
        try:
            record = client.reader.asn(str(current_ip))
            organization = record.autonomous_system_organization or ''
            database_network = record.network

            # Check if this database network is an IPv4Network
            if not isinstance(database_network, ipaddress.IPv4Network):
                database_network = ipaddress.IPv4Network(f'{current_ip}/24', strict=False)

            asn = f'AS{record.autonomous_system_number}' if record.autonomous_system_number else ''
            data = {'isp': organization, 'org': organization, 'asname': organization, 'as': asn}
            if not organization:
                # Not Found/empty organization - treat as matching (or neutral)
                overlap_start_address = max(current_ip, database_network.network_address)
                overlap_end_address = min(end_ip, database_network.broadcast_address)
                matching_ranges.extend(ipaddress.summarize_address_range(overlap_start_address, overlap_end_address))
            elif owner_matches(owner, data):
                overlap_start_address = max(current_ip, database_network.network_address)
                overlap_end_address = min(end_ip, database_network.broadcast_address)
                matching_ranges.extend(ipaddress.summarize_address_range(overlap_start_address, overlap_end_address))
            else:
                overlap_start_address = max(current_ip, database_network.network_address)
                overlap_end_address = min(end_ip, database_network.broadcast_address)
                mismatches.append((overlap_start_address, overlap_end_address, organization))

            if database_network.broadcast_address >= end_ip:
                break
            current_ip = database_network.broadcast_address + 1

        except geoip2.errors.AddressNotFoundError:
            # Step by /24 aligned block for addresses not found in the DB
            current_ip_int = int(current_ip)
            next_24_aligned_ip = ((current_ip_int // 256) + 1) * 256
            database_network = ipaddress.IPv4Network(f'{current_ip}/24', strict=False)

            overlap_start_address = max(current_ip, database_network.network_address)
            overlap_end_address = min(end_ip, database_network.broadcast_address)
            # Treat Not Found as matching/neutral to avoid noise
            matching_ranges.extend(ipaddress.summarize_address_range(overlap_start_address, overlap_end_address))

            if database_network.broadcast_address >= end_ip:
                break
            current_ip = ipaddress.IPv4Address(next_24_aligned_ip)
        except Exception as e:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            # Other errors
            mismatches.append((current_ip, current_ip, f'Error: {e}'))
            current_ip += 1

    return mismatches, list(ipaddress.collapse_addresses(matching_ranges))


def suggest_fix(
    client: RateLimitClient | GeoLite2Client,
    owner: str,
    network: ipaddress.IPv4Network,
    results: dict[str, dict[str, Any]],
    status: Status,
) -> tuple[RenderableType | None, str]:
    """Binary-search /24 boundaries and suggest replacement CIDRs for a mismatched range."""
    base_samples = sample_ips(network)
    if isinstance(client, GeoLite2Client):
        # Instant precise suggestion
        _, matching_networks = scan_network_geolite2(client, owner, network)
        if matching_networks:
            table = Table(title='[bold magenta]Fix Suggestion[/bold magenta] (offline GeoLite2 scan)', box=box.ROUNDED, expand=False)
            table.add_column('Replacement Range', style='green')
            table.add_column('IP Coverage', style='cyan')

            for matching_network in matching_networks:
                table.add_row(f"'{matching_network.with_prefixlen}',", f'({matching_network.network_address} - {matching_network.broadcast_address})')

            total_first_ip = matching_networks[0].network_address
            total_last_ip = matching_networks[-1].broadcast_address
            total_ip_addresses = sum(matching_network.num_addresses for matching_network in matching_networks)

            table.add_section()
            table.add_row('[bold]Total[/bold]', f'[bold]{total_first_ip} - {total_last_ip} ({total_ip_addresses:,} IPs)[/bold]')
            raw_text = f'Replace with: {", ".join(f"{net.with_prefixlen}" for net in matching_networks)}'
            return table, raw_text
        raw_text = f'No matching blocks found — consider removing {network.with_prefixlen}'
        return Text(f'[FIX SUGGESTION] {raw_text}', style='red'), raw_text

    if network.prefixlen > 24:  # noqa: PLR2004
        status.update(f'[yellow]Range /{network.prefixlen} is smaller than /24 — skipping auto-fix[/yellow]')
        return None, f'Range /{network.prefixlen} is smaller than /24 — skipping auto-fix'

    start_block = int(network.network_address) // SUBNET_BLOCK_SIZE
    end_block = int(network.broadcast_address) // SUBNET_BLOCK_SIZE
    total_blocks = end_block - start_block + 1

    status.update(f'[magenta]\\[AUTO-FIX][/magenta] Scanning {total_blocks:,} /24 blocks for ownership boundaries...')

    # Seed cache from existing sample results
    cache: dict[int, bool] = {}
    for ip in base_samples:
        block_index = _ip_to_block(ip)
        if start_block <= block_index <= end_block:
            lookup_result = results.get(ip) or {}
            cache[block_index] = lookup_result.get('status') == 'success' and owner_matches(owner, lookup_result)

    # Ensure range boundaries are classified
    _check_block_owner(client, owner, start_block, cache)
    _check_block_owner(client, owner, end_block, cache)

    initial_cache_size = len(cache)

    # Iteratively binary-search all unresolved transitions
    while True:
        sorted_blocks = sorted(cache.keys())
        found_unresolved = False

        for i in range(len(sorted_blocks) - 1):
            block_index_1, block_index_2 = sorted_blocks[i], sorted_blocks[i + 1]
            if cache[block_index_1] != cache[block_index_2] and block_index_2 - block_index_1 > 1:
                steps = (block_index_2 - block_index_1).bit_length()
                status.update(f'[white]binary search[/white] {_block_to_ip(block_index_1)} .. {_block_to_ip(block_index_2)} (~{steps} queries)')
                _binary_search_transition(client, owner, block_index_1, block_index_2, cache)
                found_unresolved = True
                break  # restart scan with updated cache

        if not found_unresolved:
            break

    extra_queries = len(cache) - initial_cache_size
    title_suffix = f' ([dim]{extra_queries} API queries used[/dim])' if extra_queries > 0 else ''

    # Build runs of consecutive same-classification blocks
    sorted_blocks = sorted(cache.keys())
    good_networks: list[ipaddress.IPv4Network] = []

    i = 0
    while i < len(sorted_blocks):
        if not cache[sorted_blocks[i]]:
            i += 1
            continue

        # Start of a good run
        run_start_block = sorted_blocks[i]
        j = i
        while j < len(sorted_blocks) - 1 and cache[sorted_blocks[j + 1]]:
            j += 1
        run_end_block = sorted_blocks[j]

        # Clip to the original network boundaries
        actual_start_block = max(run_start_block, start_block)
        actual_end_block = min(run_end_block, end_block)

        first_ip = ipaddress.IPv4Address(actual_start_block * SUBNET_BLOCK_SIZE)
        last_ip = ipaddress.IPv4Address((actual_end_block + 1) * SUBNET_BLOCK_SIZE - 1)

        good_networks.extend(ipaddress.summarize_address_range(first_ip, last_ip))

        i = j + 1

    # Print suggestion
    if good_networks:
        table = Table(title=f'[bold magenta]Fix Suggestion[/bold magenta]{title_suffix}', box=box.ROUNDED, expand=False)
        table.add_column('Replacement Range', style='green')
        table.add_column('IP Coverage', style='cyan')

        for matching_network in good_networks:
            table.add_row(f"'{matching_network.with_prefixlen}',", f'({matching_network.network_address} - {matching_network.broadcast_address})')

        total_first_ip = good_networks[0].network_address
        total_last_ip = good_networks[-1].broadcast_address
        total_ip_addresses = sum(good_network.num_addresses for good_network in good_networks)

        table.add_section()
        table.add_row('[bold]Total[/bold]', f'[bold]{total_first_ip} - {total_last_ip} ({total_ip_addresses:,} IPs)[/bold]')
        raw_text = f'Replace with: {", ".join(f"{net.with_prefixlen}" for net in good_networks)}'
        return table, raw_text
    raw_text = f'No matching blocks found — consider removing {network.with_prefixlen}'
    return Text(f'[FIX SUGGESTION] {raw_text}', style='red'), raw_text


def _search_expansion_boundary(
    client: RateLimitClient | GeoLite2Client,
    owner: str,
    start_block: int,
    direction: int,
    cache: dict[int, bool],
) -> int:
    """Search outward from start_block in the given direction (+1 or -1) to find the owner boundary.

    Returns the last /24 block index (inclusive) that still belongs to the expected owner.
    """
    # Exponential probe to find an upper bound for the boundary
    step = 1
    current = start_block
    last_good_block = start_block

    while True:
        probe_block = current + step * direction

        # Don't go out of IPv4 range
        if probe_block < 0 or probe_block > 0xFFFFFF:  # noqa: PLR2004  # max /24 block index
            probe_block = max(0, min(probe_block, 0xFFFFFF))
            is_owner_match = _check_block_owner(client, owner, probe_block, cache)
            if is_owner_match:
                last_good_block = probe_block
            break

        is_owner_match = _check_block_owner(client, owner, probe_block, cache)

        if is_owner_match:
            last_good_block = probe_block
            current = probe_block
            step *= 2  # exponential growth
        else:
            # Found the first non-matching block; binary search between last_good_block and probe_block
            low_block = last_good_block
            high_block = probe_block
            if low_block > high_block:
                low_block, high_block = high_block, low_block

            while high_block - low_block > 1:
                middle_block = (low_block + high_block) // 2
                is_middle_block_owner_match = _check_block_owner(client, owner, middle_block, cache)

                if direction > 0:
                    # Searching forward: good blocks are on the low_block side
                    if is_middle_block_owner_match:
                        low_block = middle_block
                    else:
                        high_block = middle_block
                # Searching backward: good blocks are on the high_block side
                elif is_middle_block_owner_match:
                    high_block = middle_block
                else:
                    low_block = middle_block

            last_good_block = low_block if direction > 0 else high_block
            break

    return last_good_block


@dataclass(slots=True)
class RangeContext:
    """Context information for a CIDR range being verified."""

    network: ipaddress.IPv4Network
    owner_networks: list[ipaddress.IPv4Network]


def suggest_expansion(
    client: RateLimitClient | GeoLite2Client,
    owner: str,
    context: RangeContext,
    expandable_ip_addresses: list[str],
    status: Status,
) -> tuple[RenderableType | None, str]:
    """Binary-search outward from expandable adjacent blocks to find the full owner boundary."""
    start_block = int(context.network.network_address) // SUBNET_BLOCK_SIZE
    end_block = int(context.network.broadcast_address) // SUBNET_BLOCK_SIZE

    cache: dict[int, bool] = {}
    initial_cache_size = 0

    # Classify expandable IPs by direction
    expanded_start = start_block
    expanded_end = end_block

    for ip in expandable_ip_addresses:
        block_index = _ip_to_block(ip)
        cache[block_index] = True  # already confirmed as same owner

        if block_index < start_block:
            # Expansion goes backward
            status.update(f'[magenta]\\[AUTO-EXPAND][/magenta] Searching backward from {_block_to_ip(block_index)}...')
            initial_cache_size = len(cache)
            boundary = _search_expansion_boundary(client, owner, block_index, -1, cache)

            # Don't expand into already-covered ranges
            for known_network in context.owner_networks:
                known_end = int(known_network.broadcast_address) // SUBNET_BLOCK_SIZE
                if boundary <= known_end < block_index:
                    boundary = known_end + 1

            expanded_start = min(expanded_start, boundary)

        elif block_index > end_block:
            # Expansion goes forward
            status.update(f'[magenta]\\[AUTO-EXPAND][/magenta] Searching forward from {_block_to_ip(block_index)}...')
            initial_cache_size = len(cache)
            boundary = _search_expansion_boundary(client, owner, block_index, +1, cache)

            # Don't expand into already-covered ranges
            for known_network in context.owner_networks:
                known_start = int(known_network.network_address) // SUBNET_BLOCK_SIZE
                if block_index < known_start <= boundary:
                    boundary = known_start - 1

            expanded_end = max(expanded_end, boundary)

    extra_queries = len(cache) - initial_cache_size
    title_suffix = f' ([dim]{extra_queries} API queries used[/dim])' if extra_queries > 0 else ''

    # Build the expanded range
    first_ip = ipaddress.IPv4Address(expanded_start * SUBNET_BLOCK_SIZE)
    last_ip = ipaddress.IPv4Address((expanded_end + 1) * SUBNET_BLOCK_SIZE - 1)
    expanded_networks = list(ipaddress.summarize_address_range(first_ip, last_ip))

    table = Table(title=f'[bold magenta]Expand Suggestion[/bold magenta]{title_suffix}', box=box.ROUNDED, expand=False)
    table.add_column('Replacement Range', style='green')
    table.add_column('IP Coverage', style='cyan')

    for matching_network in expanded_networks:
        table.add_row(f"'{matching_network.with_prefixlen}',", f'({matching_network.network_address} - {matching_network.broadcast_address})')

    total_first = expanded_networks[0].network_address
    total_last = expanded_networks[-1].broadcast_address
    total_ip_addresses = sum(expanded_network.num_addresses for expanded_network in expanded_networks)

    table.add_section()
    table.add_row('[bold]Total[/bold]', f'[bold]{total_first} - {total_last} ({total_ip_addresses:,} IPs)[/bold]')
    raw_text = f'Expand to: {", ".join(f"{net.with_prefixlen}" for net in expanded_networks)}'
    return table, raw_text


def check_expansion(client: RateLimitClient | GeoLite2Client, owner: str, cidr_range: str) -> None:
    """Check if the IP range can be expanded to a larger subnet."""
    network = ipaddress.ip_network(cidr_range)
    if not isinstance(network, ipaddress.IPv4Network):
        message = f'Only IPv4 networks are supported: {cidr_range}'
        raise TypeError(message)

    console.print(f'\n  [cyan]\\[EXP CHECK][/cyan] {cidr_range}')

    # only 2 candidates: one up, one down
    candidates: list[ipaddress.IPv4Network] = []

    try:
        if network.prefixlen > 0:
            supernet = network.supernet(prefixlen_diff=1)
            candidates.append(supernet)
    except ValueError:
        pass

    for candidate_network in candidates:
        samples = sample_ips(candidate_network)

        console.print(f'    testing: {candidate_network.with_prefixlen}')

        try:
            results = lookup_ips_batch(client, samples[:20])

            if all(owner_matches(owner, results.get(ip) or {}) and (results.get(ip) or {}).get('status') == 'success' for ip in samples[:20]):
                console.print(f'    [magenta]\\[EXPANSION POSSIBLE][/magenta] → {candidate_network.with_prefixlen}')
            else:
                console.print('    [green]\\[NO EXPANSION][/green]')

        except Exception as e:  # noqa: BLE001  # pylint: disable=broad-exception-caught
            console.print(f'    [red]\\[ERROR][/red] {e}')


def _get_adjacent_ips(network: ipaddress.IPv4Network) -> list[str]:
    """Get the .0 IPs of the /24 blocks immediately adjacent to the network (before and after)."""
    adjacent: list[str] = []

    # block immediately before the range
    before_ip_int = int(network.network_address) - SUBNET_BLOCK_SIZE
    if before_ip_int >= 0:
        adjacent.append(str(ipaddress.IPv4Address(before_ip_int)))

    # block immediately after the range
    after_ip_int = int(network.broadcast_address) + 1
    if after_ip_int <= 0xFFFFFFFF:  # noqa: PLR2004
        # align to /24 boundary
        after_aligned_integer = after_ip_int - (after_ip_int % SUBNET_BLOCK_SIZE)
        adjacent.append(str(ipaddress.IPv4Address(after_aligned_integer)))

    return adjacent


def render_samples(samples: list[str]) -> Columns:
    """Render a grid-aligned column view of the representative sample IP addresses."""
    displayed = samples[:16]
    remaining = len(samples) - 16

    texts = [Text(ip, style='magenta') for ip in displayed]
    if remaining > 0:
        texts.append(Text(f'... (+{remaining} more)', style='dim magenta'))

    return Columns(texts, equal=True, expand=True)


def check_range(  # noqa: PLR0913  # pylint: disable=too-many-arguments
    client: RateLimitClient | GeoLite2Client,
    owner: str,
    cidr_range: str,
    owner_networks: list[ipaddress.IPv4Network],
    *,
    location: tuple[str, int | None] | None = None,
    only_detections: bool = False,
    current_index: int = 0,
    total_count: int = 0,
    detections: list[str] | None = None,
) -> bool:
    """Check the validity of the CIDR range and look for potential expansion."""
    file_path, line_number = location or ('', None)
    network = ipaddress.ip_network(cidr_range)
    if not isinstance(network, ipaddress.IPv4Network):
        message = f'Only IPv4 networks are supported: {cidr_range}'
        raise TypeError(message)

    # Use console.status to show progress while not polluting the screen
    progress_prefix = ''
    if total_count > 0 and current_index > 0:
        percent = int((current_index / total_count) * 100)
        progress_prefix = f'[cyan][{percent}%][/cyan] '

    status_message = (
        f'{progress_prefix}[bold cyan]Scanning [/bold cyan]'
        f'[bold white]{owner}[/bold white] '
        f'[bold cyan]([/bold cyan][bold magenta]{network.with_prefixlen}[/bold magenta]'
        f'[bold cyan])...[/bold cyan]'
    )
    with console.status(status_message) as status:
        # -----------------------------
        # BUILD ONE SINGLE REQUEST SET
        # -----------------------------
        base_samples = sample_ips(network)
        adjacent_ip_addresses = _get_adjacent_ips(network)
        all_ip_addresses = list(dict.fromkeys(base_samples + adjacent_ip_addresses))

        results = lookup_ips_batch(client, all_ip_addresses)

        # -----------------------------
        # VALIDATION LOGIC
        # -----------------------------
        is_valid = True

        # Base Check
        has_mismatches = False
        mismatch_lines: list[str] = []
        mismatches_raw: list[str] = []

        if isinstance(client, GeoLite2Client):
            # Thorough 100% offline GeoLite2 validation using tree-jumping
            mismatches, _ = scan_network_geolite2(client, owner, network)
            if mismatches:
                is_valid = False
                has_mismatches = True
                for start_ip, end_ip, actual_owner in mismatches:
                    if start_ip == end_ip:
                        mismatch_lines.append(f'[red]✗[/red] [magenta]{start_ip}[/magenta] → {actual_owner}')
                        mismatches_raw.append(f'✗ {cidr_range} ({start_ip}) → {actual_owner}')
                    else:
                        mismatch_lines.append(f'[red]✗[/red] [magenta]{start_ip} - {end_ip}[/magenta] → {actual_owner}')
                        mismatches_raw.append(f'✗ {cidr_range} ({start_ip} - {end_ip}) → {actual_owner}')
        else:
            # Random 20-IP rate-limited online validation (IP-API)
            for ip in base_samples:
                lookup_result = results.get(ip) or {}
                if lookup_result.get('status') != 'success':
                    is_valid = False
                    continue

                if not owner_matches(owner, lookup_result):
                    mismatch_lines.append(f'[red]✗[/red] [magenta]{ip}[/magenta] → {lookup_result.get("isp")} / {lookup_result.get("org")}')
                    mismatches_raw.append(f'✗ {cidr_range} ({ip}) → {lookup_result.get("isp")} / {lookup_result.get("org")}')
                    is_valid = False
                    has_mismatches = True

        # Expansion Check
        start_ip_int = int(network.network_address)
        expansion_found = False
        expandable_ip_addresses: list[str] = []

        backward_expansion_status = '[green]✓ Clear[/green]'
        forward_expansion_status = '[green]✓ Clear[/green]'
        backward_expansion_details: list[str] = []
        forward_expansion_details: list[str] = []

        for ip in adjacent_ip_addresses:
            ip_int = int(ipaddress.IPv4Address(ip))
            direction = 'BACKWARD' if ip_int < start_ip_int else 'FORWARD'
            ip_addr = ipaddress.IPv4Address(ip)

            details_list = backward_expansion_details if direction == 'BACKWARD' else forward_expansion_details

            def update_status(status_str: str, direction_name: str = direction) -> None:
                nonlocal backward_expansion_status, forward_expansion_status
                if direction_name == 'BACKWARD':
                    backward_expansion_status = status_str
                else:
                    forward_expansion_status = status_str

            if any(ip_addr in owner_network for owner_network in owner_networks):
                update_status('[green]✓ Already Covered[/green]')
                details_list.append(f'[magenta]{ip}[/magenta]\nStatus: [green]Already Covered[/green]')
                continue

            lookup_result = results.get(ip) or {}
            status_value = lookup_result.get('status')
            message_value = lookup_result.get('message')

            is_non_failure_fail = status_value == 'fail' and message_value in (
                'address not found',
                'private range',
                'reserved range',
            )

            if status_value != 'success' and not is_non_failure_fail:
                update_status('[yellow]! Lookup Failed[/yellow]')
                details_list.append(f'[magenta]{ip}[/magenta]\nStatus: [yellow]Lookup Failed[/yellow]')
                continue

            if owner_matches(owner, lookup_result):
                update_status('[red]✗ Expandable[/red]')
                details_list.append(f'[magenta]{ip}[/magenta]\nStatus: [magenta]Same Owner ({lookup_result.get("isp")} / {lookup_result.get("org")})[/magenta]')
                expansion_found = True
                expandable_ip_addresses.append(ip)
            else:
                update_status('[green]✓ Boundary OK[/green]')
                if is_non_failure_fail and message_value is not None:
                    description = message_value.title()
                else:
                    isp_value = lookup_result.get('isp')
                    organization_value = lookup_result.get('org')
                    description = f'{isp_value} / {organization_value}' if isp_value and organization_value else isp_value or organization_value or 'Unknown'
                details_list.append(f'[magenta]{ip}[/magenta]\nStatus: [green]Different Owner ({description})[/green]')

        # Auto-Fix / Auto-Expand checks (done silently inside status)
        if has_mismatches:
            # We capture the prints of suggest_fix? No, suggest_fix calls console.print.
            # To capture it perfectly, we should ideally refactor suggest_fix to return a renderable.
            # But console.print inside status works! It just prints above the status line.
            pass

    # -----------------------------
    # RENDER SINGLE CONTAINER
    # -----------------------------
    renderables: list[RenderableType] = []

    # 1. Sampled IPs
    renderables.append(Panel(render_samples(all_ip_addresses), title='[cyan]Sampled IPs[/cyan]', border_style='cyan', box=box.ROUNDED))
    renderables.append(Text(''))

    # 3. Validation Results, Expansion Details, Summary
    validation_table = Table.grid(padding=(0, 4))
    validation_table.add_column(style='cyan', justify='left')
    validation_table.add_column(justify='left')

    base_status = '[red]✗ Mismatches Found[/red]' if has_mismatches else '[green]✓ Pass[/green]'
    validation_table.add_row('Base Check', base_status)
    validation_table.add_row('Backward Expansion', backward_expansion_status)
    validation_table.add_row('Forward Expansion', forward_expansion_status)

    details_table = Table.grid(padding=(0, 4), expand=True)
    details_table.add_column()
    details_table.add_column()
    details_table.add_column()
    details_table.add_column()

    backward_text = '\n'.join(backward_expansion_details) if backward_expansion_details else 'N/A'
    forward_text = '\n'.join(forward_expansion_details) if forward_expansion_details else 'N/A'

    summary_parts: list[str] = []
    if is_valid:
        summary_parts.append('[green]✓ Range Verified[/green]')
        summary_parts.append('[green]✓ Ownership Consistent[/green]')
    else:
        summary_parts.append('[red]✗ Range Verification Failed[/red]')
        summary_parts.append('[red]✗ Ownership Inconsistent[/red]')

    if not expansion_found:
        summary_parts.append('[green]✓ No Expansion Opportunities[/green]')
    else:
        summary_parts.append('[yellow]! Expansion Opportunities Found[/yellow]')

    summary_text = '\n'.join(summary_parts)

    details_table.add_row(
        Panel(backward_text, title='[cyan]Backward Expansion[/cyan]', border_style='cyan', box=box.ROUNDED),
        Panel(forward_text, title='[cyan]Forward Expansion[/cyan]', border_style='cyan', box=box.ROUNDED),
        Panel(validation_table, title='[cyan]Validation Results[/cyan]', border_style='cyan', box=box.ROUNDED),
        Panel(summary_text, title='[cyan]Summary[/cyan]', border_style='cyan', box=box.ROUNDED),
    )

    renderables.append(details_table)

    # If we have auto-fix / expand tables, we append them so they show inside the master panel
    fix_raw = ''
    if has_mismatches:
        renderables.append(Text(''))
        renderables.append(Rule('[bold white]Fix Suggestion[/bold white]'))
        renderables.append(Panel('\n'.join(mismatch_lines), title='[red]Base Check Mismatches[/red]', border_style='red', box=box.ROUNDED))
        fix_renderable, fix_raw = suggest_fix(client, owner, network, results, status)
        if fix_renderable:
            renderables.append(fix_renderable)

    expansion_raw = ''
    if expansion_found:
        context = RangeContext(network, owner_networks)
        expansion_renderable, expansion_raw = suggest_expansion(client, owner, context, expandable_ip_addresses, status)
        if expansion_renderable:
            renderables.append(Text(''))
            renderables.append(Rule('[bold white]Expansion Available[/bold white]'))
            renderables.append(expansion_renderable)

    # Populate detections list for export
    clean_relative_path = os.path.relpath(file_path).replace('\\', '/') if file_path else ''
    if has_mismatches and detections is not None:
        for mismatch in mismatches_raw:
            detections.append(f'{clean_relative_path}:{line_number}: ({owner}) {mismatch} | [FIX SUGGESTION] {fix_raw}')
    if expansion_found and detections is not None:
        detections.append(f'{clean_relative_path}:{line_number}: ({owner}) [EXPANSION] {cidr_range} is expandable | [EXPAND SUGGESTION] {expansion_raw}')

    # Print the master panel
    if not only_detections or not is_valid or expansion_found:
        title = f'[bold white]{owner}[/bold white]  •  [bold magenta]{network.with_prefixlen}[/bold magenta]  •  [dim]{network.network_address} → {network.broadcast_address}[/dim]  •  [bold white]{network.num_addresses:,} IPs[/bold white]'  # pylint: disable=line-too-long  # noqa: E501
        if file_path and line_number:
            relative_path = os.path.relpath(file_path).replace('\\', '/')
            title += f'  •  [blue]{relative_path}:{line_number}[/blue]'

        console.print()
        console.print(
            Panel(
                Group(*renderables),
                title=title,
                border_style='cyan',
                box=box.ROUNDED,
            ),
        )

    return is_valid


def run_preflight_checks(
    ranges: list[tuple[str, str, int]],
    networks_by_owner: dict[str, list[ipaddress.IPv4Network]],
    *,
    ranges_file: str = '',
) -> None:
    """Run all pre-flight checks and display them in a neat panel."""
    table = Table(show_header=False, expand=True, box=None, padding=(0, 2))
    table.add_column(style='cyan', justify='left', ratio=1)
    table.add_column(justify='left', ratio=3)

    # Sorting
    warnings: list[str] = []
    for owner, networks in networks_by_owner.items():
        if networks != sorted(networks):
            warnings.append(owner)
    if warnings:
        table.add_row('CIDR Sorting', f'[yellow]⚠ {len(warnings)} owners have unsorted ranges[/yellow]')
    else:
        table.add_row('CIDR Sorting', '[green]✓ All ranges correctly sorted[/green]')

    # Overlaps
    all_networks: list[tuple[str, ipaddress.IPv4Network]] = [(owner, network) for owner, networks in networks_by_owner.items() for network in networks]
    overlaps: list[str] = []
    for i, (owner_1, network_1) in enumerate(all_networks):
        for j, (owner_2, network_2) in enumerate(all_networks):
            if i != j and network_1.subnet_of(network_2):
                if 'BattlEye' in (owner_1, owner_2):
                    continue
                overlaps.append(f'[dim]• {network_1} ({owner_1}) falls within {network_2} ({owner_2})[/dim]')
    if overlaps:
        table.add_row('Overlapping CIDRs', f'[yellow]⚠ {len(overlaps)} overlaps detected![/yellow]\n' + '\n'.join(overlaps))
    else:
        table.add_row('Overlapping CIDRs', '[green]✓ No overlapping CIDRs found[/green]')

    # Collapsible
    collapses: list[str] = []
    collapse_suggestions: list[str] = []
    clean_relative_path = os.path.relpath(ranges_file).replace('\\', '/') if ranges_file else ''

    for owner, networks in networks_by_owner.items():
        collapsed = list(ipaddress.collapse_addresses(networks))
        if len(collapsed) < len(networks):
            collapses.append(f'[dim]• {owner}: {len(networks)} ranges → {len(collapsed)}[/dim]')

            # Find lines matching this owner to help user locate it
            owner_line_numbers = [line_number for owner_name, _, line_number in ranges if owner_name == owner]
            link_str = f'  •  [blue]{clean_relative_path}:{min(owner_line_numbers)}[/blue]' if (owner_line_numbers and clean_relative_path) else ''

            to_delete = [n for n in networks if n not in collapsed]
            to_add = [n for n in collapsed if n not in networks]

            lines = [f'[bold white]{owner}[/bold white] ({len(networks)} ranges → {len(collapsed)}){link_str}']
            if to_delete:
                lines.append('  [red]❌ Delete these ranges:[/red]')
                lines.extend(f"    '{n.with_prefixlen}'," for n in to_delete)
            if to_add:
                lines.append('  [green]➕ Add these ranges instead:[/green]')  # noqa: RUF001
                lines.extend(f"    '{n.with_prefixlen}'," for n in to_add)

            collapse_suggestions.append('\n'.join(lines))

    if collapses:
        table.add_row('Collapsible CIDRs', f'[yellow]⚠ {len(collapses)} collapsible blocks found![/yellow]\n' + '\n'.join(collapses))
    else:
        table.add_row('Collapsible CIDRs', '[green]✓ No collapsible ranges found[/green]')

    renderables: list[Any] = [table]
    if collapse_suggestions:
        renderables.append(Text(''))
        renderables.append(Rule('[bold yellow]CIDR Collapse Suggestions[/bold yellow]'))
        renderables.append(Text.from_markup('[yellow]💡 Edit the ranges for the owner in your code by deleting and adding the subnets below:[/yellow]'))
        renderables.append(Text(''))
        renderables.append(Text.from_markup('\n\n'.join(collapse_suggestions)))

    console.print()
    console.print(
        Panel(
            Group(*renderables),
            title='[bold cyan]Pre-flight Validations[/bold cyan]',
            border_style='cyan',
            box=box.ROUNDED,
        ),
    )


def should_skip(owner: str, *, use_geolite2: bool) -> bool:
    """Return True if range verification should be skipped for this owner."""
    if owner in {'BattlEye', 'Tellas Greece'}:
        return True
    return not use_geolite2 and owner in {'Google LLC', 'Amazon.com, Inc.'}


def main() -> None:
    """Main entry point to parse command-line arguments and check ranges."""
    if hasattr(sys.stdout, 'reconfigure'):
        cast('Any', sys.stdout).reconfigure(encoding='utf-8')

    # Filter out empty arguments passed by VS Code task inputs
    arguments = [arg for arg in sys.argv if arg]

    parser = argparse.ArgumentParser(description='Verify IP ranges of third party servers.')
    parser.add_argument('ranges_file', help='Python file containing NamedRange definitions.')
    parser.add_argument('--geolite2', action='store_true', help='Use local GeoLite2 database instead of IP-API.')
    parser.add_argument('--only-detections', action='store_true', help='Only print blocks with mismatches or expansion opportunities.')
    parser.add_argument('--export', help='Export one-line detections to the specified text file.')

    parsed_arguments = parser.parse_args(arguments[1:])

    ranges = extract_ranges(str(parsed_arguments.ranges_file))
    networks_by_owner: dict[str, list[ipaddress.IPv4Network]] = {}
    for owner, cidr_range, _ in ranges:
        with contextlib.suppress(ValueError, TypeError):
            network = ipaddress.ip_network(cidr_range)
            if isinstance(network, ipaddress.IPv4Network):
                networks_by_owner.setdefault(owner, []).append(network)

    console.rule('[bold cyan]Session Sniffer - Range Verification Engine[/bold cyan]')
    console.print(f'  [cyan]Loaded [bold white]{len(ranges)}[/bold white] ranges for processing.[/cyan]')

    # Run all pre-flight checks
    run_preflight_checks(
        ranges,
        networks_by_owner,
        ranges_file=str(parsed_arguments.ranges_file),
    )

    if parsed_arguments.geolite2:
        application_directory = get_app_dir(scope='local')
        asn_database_path = application_directory / 'GeoLite2 Databases' / 'GeoLite2-ASN.mmdb'

        if not asn_database_path.exists():
            console.print(f'[red]Error: GeoLite2-ASN database not found at {asn_database_path.absolute()}[/red]')
            console.print('[yellow]Please download it or launch the main app first to download it automatically.[/yellow]')
            sys.exit(1)

        client: GeoLite2Client | RateLimitClient = GeoLite2Client(asn_database_path)
    else:
        client = RateLimitClient(_ip_api_session)

    # Collect all IPs to pre-fetch for non-skipped ranges
    ip_to_owners: dict[str, set[str]] = {}
    for owner, cidr_range, _ in ranges:
        if not should_skip(owner, use_geolite2=parsed_arguments.geolite2):
            with contextlib.suppress(ValueError, TypeError):
                network = ipaddress.ip_network(cidr_range)
                if isinstance(network, ipaddress.IPv4Network):
                    base_samples = sample_ips(network)
                    adjacent_ip_addresses = _get_adjacent_ips(network)
                    for ip in base_samples + adjacent_ip_addresses:
                        ip_to_owners.setdefault(ip, set()).add(owner)

    if ip_to_owners:
        ips_list = list(ip_to_owners.keys())
        batch_count = (len(ips_list) + API_BATCH_LIMIT - 1) // API_BATCH_LIMIT

        mode_suffix = ' (offline)' if parsed_arguments.geolite2 else ''
        prefetch_progress = Progress(
            SpinnerColumn(),
            TextColumn(f'[bold cyan]Pre-fetching {len(ips_list):,} IPs{mode_suffix}[/bold cyan]'),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TextColumn('[dim]•[/dim]'),
            TimeElapsedColumn(),
            TextColumn('[dim]•[/dim]'),
            TextColumn('{task.description}'),
            console=console,
            transient=True,
        )

        with prefetch_progress:
            prefetch_task = prefetch_progress.add_task('', total=batch_count)

            def prefetch_sleep_callback(seconds: float, reason: str) -> None:
                total_sleep = int(seconds)
                if total_sleep <= 0:
                    time.sleep(seconds)
                    return
                fraction = seconds - total_sleep
                if fraction > 0:
                    time.sleep(fraction)
                for remaining in range(total_sleep, 0, -1):
                    prefetch_progress.update(prefetch_task, description=f'[yellow]{reason} (sleeping {remaining}s)...[/yellow]')
                    time.sleep(1)

            if not parsed_arguments.geolite2 and isinstance(client, RateLimitClient):
                client.sleep_callback = prefetch_sleep_callback

            for i, batch in enumerate(chunked(ips_list, API_BATCH_LIMIT), 1):
                batch_owners = sorted({owner for ip in batch for owner in ip_to_owners[ip]})
                owners_str = (
                    ', '.join(batch_owners[:MAX_DISPLAYED_OWNERS]) + f' and {len(batch_owners) - MAX_DISPLAYED_OWNERS} more'
                    if len(batch_owners) > MAX_DISPLAYED_OWNERS
                    else ', '.join(batch_owners)
                )
                prefetch_progress.update(prefetch_task, completed=i, description=f'[white]{owners_str}[/white]')
                lookup_ips_batch(client, batch)

            if not parsed_arguments.geolite2 and isinstance(client, RateLimitClient):
                client.sleep_callback = None

    if not parsed_arguments.only_detections:
        console.print()  # Add a newline for visual separation before skipping/checking ranges

    # Count total non-skipped ranges first
    total_count = sum(1 for owner, _, _ in ranges if not should_skip(owner, use_geolite2=parsed_arguments.geolite2))

    detections: list[str] = []
    current_index = 0

    progress = Progress(
        SpinnerColumn(),
        TextColumn('[bold cyan]Verifying[/bold cyan]'),
        BarColumn(bar_width=30),
        MofNCompleteColumn(),
        TextColumn('[dim]•[/dim]'),
        TimeElapsedColumn(),
        TextColumn('[dim]•[/dim]'),
        TextColumn('{task.description}'),
        console=console,
        transient=True,
    )

    with progress:
        task_id = progress.add_task('', total=total_count)

        def verification_sleep_callback(seconds: float, reason: str) -> None:
            total_sleep = int(seconds)
            if total_sleep <= 0:
                time.sleep(seconds)
                return
            fraction = seconds - total_sleep
            if fraction > 0:
                time.sleep(fraction)
            task = next((t for t in progress.tasks if t.id == task_id), None)
            original_description = task.description if task else ''
            for remaining in range(total_sleep, 0, -1):
                progress.update(task_id, description=f'{original_description} [yellow]• {reason} ({remaining}s)[/yellow]')
                time.sleep(1)
            progress.update(task_id, description=original_description)

        if not parsed_arguments.geolite2 and isinstance(client, RateLimitClient):
            client.sleep_callback = verification_sleep_callback

        for owner, cidr_range, line_number in ranges:
            if should_skip(owner, use_geolite2=parsed_arguments.geolite2):
                if not parsed_arguments.only_detections:
                    clean_relative_path = os.path.relpath(str(parsed_arguments.ranges_file)).replace('\\', '/')
                    link_suffix = f'  •  [blue]{clean_relative_path}:{line_number}[/blue]' if clean_relative_path else ''
                    console.print(f'[dim]ℹ Skipping Range Verification for {owner} CIDR:[/dim] [magenta dim]{cidr_range}[/magenta dim]{link_suffix}')  # noqa: RUF001
                continue

            current_index += 1
            progress.update(task_id, completed=current_index, description=f'[white]{owner}[/white] [magenta]{cidr_range}[/magenta]')

            owner_networks = networks_by_owner.get(owner, [])
            location = (str(parsed_arguments.ranges_file), line_number)
            check_range(
                client,
                owner,
                cidr_range,
                owner_networks,
                location=location,
                only_detections=parsed_arguments.only_detections,
                current_index=current_index,
                total_count=total_count,
                detections=detections,
            )

            # Smooth visual progress sweep for cached ranges
            if total_count > 0:
                time.sleep(min(0.005, 1.0 / total_count))

    if not parsed_arguments.geolite2 and isinstance(client, RateLimitClient):
        client.sleep_callback = None

    if not parsed_arguments.only_detections:
        console.print()
    console.rule('[bold green]✓ Range Verification Complete[/bold green]')
    skipped_count = len(ranges) - total_count
    console.print(f'  [green]✓ Successfully verified [bold]{total_count}[/bold] ranges.[/green]')
    if skipped_count > 0:
        console.print(f'  [dim]ℹ Skipped [bold]{skipped_count}[/bold] ranges (ignored owners).[/dim]')  # noqa: RUF001

    if parsed_arguments.export:
        export_path = Path(parsed_arguments.export)
        try:
            with export_path.open('w', encoding='utf-8') as f:
                if detections:
                    f.write('\n'.join(detections) + '\n')
                else:
                    f.write('')
            console.print(f'\n[green]✓ Exported {len(detections)} detection(s) to {export_path.resolve()}[/green]')
        except OSError as e:
            console.print(f'\n[red]✗ Failed to export detections to {export_path.resolve()}: {e}[/red]')

    if isinstance(client, GeoLite2Client):
        client.close()


if __name__ == '__main__':
    main()
