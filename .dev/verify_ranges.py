"""Script to verify IP ranges of third party servers."""  # pylint: disable=too-many-lines

import argparse
import ast
import contextlib
import ipaddress
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

import requests
from rich import box
from rich.columns import Columns
from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# Add src/ folder to path so it can import session_sniffer
SOURCE_PATH = str(Path(__file__).resolve().parent.parent / 'src')
if SOURCE_PATH not in sys.path:
    sys.path.insert(0, SOURCE_PATH)

from session_sniffer.networking.http_session import session  # pylint: disable=wrong-import-position  # noqa: E402

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
    from collections.abc import Generator, Mapping

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


class RateLimitClient:  # pylint: disable=too-few-public-methods
    """Client for querying the IP API with rate limiting."""

    session: requests.Session
    min_interval: float
    last_request_time: float
    cooldown_until: float
    last_rate_limit: int | None
    capacity: int
    window: int
    tokens: int
    last_refill: float

    def __init__(self, session: requests.Session) -> None:
        """Initialize the RateLimitClient."""
        self.session = session
        self.min_interval = 60 / 45
        self.last_request_time = 0.0
        self.cooldown_until = 0.0
        self.last_rate_limit = None
        self.capacity = 45
        self.window = 60
        self.tokens = 45
        self.last_refill = time.time()

    def _refill(self) -> None:
        """Refill the token bucket based on elapsed time."""
        now = time.time()
        elapsed_seconds = now - self.last_refill

        if elapsed_seconds >= self.window:
            self.tokens = self.capacity
            self.last_refill = now

    def _respect_min_interval(self) -> None:
        """Ensure requests are spaced out by at least the minimum interval."""
        now = time.time()
        wait = self.min_interval - (now - self.last_request_time)
        if wait > 0:
            time.sleep(wait)

    def _apply_headers(self, headers: Mapping[str, str]) -> None:
        """Apply rate limit headers from the API response."""
        rate_limit_str = headers.get('X-Rl')
        time_to_live_str = headers.get('X-Ttl')

        rate_limit: int | None = None
        if rate_limit_str is not None:
            with contextlib.suppress(ValueError):
                rate_limit = int(rate_limit_str)

        time_to_live: int | None = None
        if time_to_live_str is not None:
            with contextlib.suppress(ValueError):
                time_to_live = int(time_to_live_str)

        self.last_rate_limit = rate_limit

        if rate_limit is not None and rate_limit == 0:  # pylint: disable=use-implicit-booleaness-not-comparison-to-zero
            wait_time = (time_to_live + 1) if time_to_live else 60
            console.print(f'[yellow]\\[RATE] exhausted[/yellow] → [yellow]sleeping {wait_time}s[/yellow]')
            time.sleep(wait_time)

        elif rate_limit is not None and rate_limit <= THROTTLING_RATE_LIMIT_THRESHOLD:
            time.sleep(2)

    def _consume(self) -> None:
        """Consume a token from the bucket, throttling if necessary."""
        while True:
            self._refill()

            if self.tokens > 0:
                self.tokens -= 1
                return

            sleep_time = self.window - (time.time() - self.last_refill)
            sleep_time = max(sleep_time, 1.0)

            console.print(f'[yellow]\\[RATE] throttling[/yellow] → [yellow]sleeping {int(sleep_time)}s[/yellow]')
            time.sleep(sleep_time)

    def post_batch(self, payload: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Post a batch of IPs to the rate-limited API."""
        self._consume()

        while True:
            try:
                response = self.session.post(
                    IP_API_BATCH_URL,
                    json=payload,
                    timeout=20,
                )

                self.last_request_time = time.time()

                if response.status_code == COOLDOWN_HTTP_STATUS:
                    time_to_live_str = response.headers.get('X-Ttl')

                    try:
                        time_to_live = int(time_to_live_str) if time_to_live_str else 60
                    except ValueError:
                        time_to_live = 60

                    # always use fresh TTL, minimum 1s
                    wait_time = max(time_to_live + 1, 1)

                    # track cooldown deadline
                    self.cooldown_until = time.time() + wait_time

                    console.print(f'[yellow]\\[429] cooldown[/yellow] → [yellow]sleeping {wait_time}s[/yellow]')

                    time.sleep(wait_time)
                    continue

                response.raise_for_status()

                self._apply_headers(response.headers)

                return cast('list[dict[str, Any]]', response.json())

            except requests.RequestException as e:
                console.print(f'[red]\\[ERROR] Request failed: {e}[/red]')
                time.sleep(5)


class GeoLite2Client:
    """Offline lookup client using local GeoLite2 database."""

    def __init__(self, db_path: Path) -> None:
        """Initialize the GeoLite2Client database reader."""
        import geoip2.database  # pylint: disable=import-outside-toplevel  # noqa: PLC0415

        self.reader = geoip2.database.Reader(db_path)

    def post_batch(self, payload: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Look up IP details from local GeoLite2 ASN database."""
        import geoip2.errors  # pylint: disable=import-outside-toplevel  # noqa: PLC0415

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

    for batch in chunked(ip_addresses, API_BATCH_LIMIT):
        payload: list[dict[str, Any]] = [{'query': ip, 'fields': 'status,message,query,isp,org,as,asname'} for ip in batch]
        batch_results = client.post_batch(payload)
        results.update({cast('str', result.get('query')): result for result in batch_results})

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


# Custom exception list: Map an expected owner to a list of exact ISP/Org strings that
# trigger false positive matches (e.g., 'DXC' matching 'Microsoft' due to the word 'Corporation').
# These will be explicitly treated as different/unrelated ISPs.
KNOWN_FALSE_POSITIVES: dict[str, list[str]] = {
    'Microsoft Corporation': [
        'digital highway corporation',
        'dxc us latin america corporation',
        'shanghai blue cloud technology',
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
}

GENERIC_WORDS: set[str] = {
    'association',
    'avenue',
    'building',
    'communication',
    'communications',
    'company',
    'corporation',
    'group',
    'hosting',
    'inc',
    'incorporated',
    'interactive',
    'limited',
    'ltd',
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

    words = {word for word in normalize(expected).split() if len(word) >= MIN_WORD_LENGTH}
    words -= GENERIC_WORDS
    if not words:
        # Fallback to original words if everything was generic
        words = {word for word in normalize(expected).split() if len(word) >= MIN_WORD_LENGTH}

    return any(word in actual for word in words)


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
    import geoip2.errors  # pylint: disable=import-outside-toplevel  # noqa: PLC0415

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
) -> RenderableType | None:
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
            return table
        return Text(f'[FIX SUGGESTION] No matching blocks found — consider removing {network.with_prefixlen}', style='red')

    if network.prefixlen > 24:  # noqa: PLR2004
        status.update(f'[yellow]Range /{network.prefixlen} is smaller than /24 — skipping auto-fix[/yellow]')
        return None

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
        return table
    return Text(f'[FIX SUGGESTION] No matching blocks found — consider removing {network.with_prefixlen}', style='red')


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
) -> RenderableType | None:
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
    return table


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

        if isinstance(client, GeoLite2Client):
            # Thorough 100% offline GeoLite2 validation using tree-jumping
            mismatches, _ = scan_network_geolite2(client, owner, network)
            if mismatches:
                is_valid = False
                has_mismatches = True
                for start_ip, end_ip, actual_owner in mismatches:
                    if start_ip == end_ip:
                        mismatch_lines.append(f'[red]✗[/red] [magenta]{start_ip}[/magenta] → {actual_owner}')
                    else:
                        mismatch_lines.append(f'[red]✗[/red] [magenta]{start_ip} - {end_ip}[/magenta] → {actual_owner}')
        else:
            # Random 20-IP rate-limited online validation (IP-API)
            for ip in base_samples:
                lookup_result = results.get(ip) or {}
                if lookup_result.get('status') != 'success':
                    is_valid = False
                    continue

                if not owner_matches(owner, lookup_result):
                    mismatch_lines.append(f'[red]✗[/red] [magenta]{ip}[/magenta] → {lookup_result.get("isp")} / {lookup_result.get("org")}')
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
    if has_mismatches:
        renderables.append(Text(''))
        renderables.append(Rule('[bold white]Fix Suggestion[/bold white]'))
        renderables.append(Panel('\n'.join(mismatch_lines), title='[red]Base Check Mismatches[/red]', border_style='red', box=box.ROUNDED))
        fix_renderable = suggest_fix(client, owner, network, results, status)
        if fix_renderable:
            renderables.append(fix_renderable)

    if expansion_found:
        context = RangeContext(network, owner_networks)
        expansion_renderable = suggest_expansion(client, owner, context, expandable_ip_addresses, status)
        if expansion_renderable:
            renderables.append(Text(''))
            renderables.append(Rule('[bold white]Expansion Available[/bold white]'))
            renderables.append(expansion_renderable)

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
    only_detections: bool = False,
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

            owner_suggestions = [f"    '{network.with_prefixlen}'," for network in collapsed]
            collapse_suggestions.append(
                f'[bold white]{owner}[/bold white] ({len(networks)} ranges → {len(collapsed)}){link_str}\n' + '\n'.join(owner_suggestions),
            )

    if collapses:
        table.add_row('Collapsible CIDRs', f'[yellow]⚠ {len(collapses)} collapsible blocks found![/yellow]\n' + '\n'.join(collapses))
    else:
        table.add_row('Collapsible CIDRs', '[green]✓ No collapsible ranges found[/green]')

    if only_detections and not (warnings or overlaps or collapses):
        return

    renderables: list[Any] = [table]
    if collapse_suggestions:
        renderables.append(Text(''))
        renderables.append(Rule('[bold white]CIDR Collapse Suggestions[/bold white]'))
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
        only_detections=parsed_arguments.only_detections,
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
        client = RateLimitClient(session)

    if not parsed_arguments.only_detections:
        console.print()  # Add a newline for visual separation before skipping/checking ranges

    # Count total non-skipped ranges first
    total_count = sum(1 for owner, _, _ in ranges if not ('google llc' in owner.lower() or 'tellas greece' in owner.lower() or 'battleye' in owner.lower()))

    current_index = 0
    for owner, cidr_range, line_number in ranges:
        if 'google llc' in owner.lower() or 'tellas greece' in owner.lower() or 'battleye' in owner.lower():
            if not parsed_arguments.only_detections:
                clean_relative_path = os.path.relpath(str(parsed_arguments.ranges_file)).replace('\\', '/')
                link_suffix = f'  •  [blue]{clean_relative_path}:{line_number}[/blue]' if clean_relative_path else ''
                console.print(f'[yellow dim]⚠ Skipping Range Verification for[/yellow dim] [dim]{owner} CIDR:[/dim] [magenta dim]{cidr_range}[/magenta dim]{link_suffix}')
            continue

        current_index += 1
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
        )

    if not parsed_arguments.only_detections:
        console.print()
    console.rule('[bold green]✓ Range Verification Complete[/bold green]')

    if isinstance(client, GeoLite2Client):
        client.close()


if __name__ == '__main__':
    main()
