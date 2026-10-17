"""Script to verify IP ranges of third party servers."""

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
from typing import TYPE_CHECKING, Any, cast

import geoip2.database
import geoip2.errors
import requests
from rich import box
from rich.columns import Columns
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TaskID, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from session_sniffer.constants.local import GEOLITE2_DATABASES_DIR_PATH
from session_sniffer.guis.utils import format_duration
from session_sniffer.networking.http_session import HEADERS
from session_sniffer.text_utils import pluralize

_ip_api_session = requests.Session()
_ip_api_session.headers.update(HEADERS)

console = Console()

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Mapping

    from rich.console import RenderableType

IP_API_BATCH_URL = 'http://ip-api.com/batch'
THROTTLING_RATE_LIMIT_THRESHOLD = 3
COOLDOWN_HTTP_STATUS = 429
EXPECTED_ARGS_COUNT = 2
MIN_WORD_LENGTH = 4
MAX_SAMPLES = 20
MAX_SAMPLE_IPS = 16
API_BATCH_LIMIT = 100
SUBNET_BLOCK_SIZE = 256  # /24 boundary alignment
MAX_DISPLAYED_OWNERS = 3
STALE_CONNECTION_THRESHOLD = 10  # seconds; close pooled connections after sleeps longer than this
MAX_ERROR_BACKOFF = 120
MAX_IP_API_SUBNET_PREFIX = 12  # Skip ranges <= /12 (>= 1M IPs) when using IP-API
MAX_AUTO_FIX_PREFIX_LEN = 24  # Skip auto-fix for subnets smaller than /24
MAX_SLASH_24_BLOCK_INDEX = 0xFFFFFF  # Maximum /24 block index in IPv4 address space
MAX_IPV4_INT = 0xFFFFFFFF  # Maximum IPv4 32-bit integer address

ALWAYS_SKIPPED_OWNERS: set[str] = {'BattlEye', 'Tellas Greece', 'Google LLC'}
IP_API_SKIPPED_OWNERS: set[str] = {'Amazon.com, Inc.', 'Microsoft Corporation', 'Level 3 Parent, LLC'}

KNOWN_FALSE_POSITIVES: dict[str, list[str]] = {
    'Microsoft Corporation': ['digital highway corporation', 'dxc us latin america corporation', 'shanghai blue cloud technology'],
    'Demonware Limited': ['datacamp limited', 'orbit telekom sanayi'],
    'Take-Two Interactive Software, Inc.': ['frontier communications of america'],
}

KNOWN_ALIASES: dict[str, list[str]] = {
    'Amazon.com, Inc.': [
        'Amazon.com, Inc.', 'Amazon Technologies Inc', 'Amazon.com, Inc. / Amazon Technologies Inc.',
        'Amazon.com, Inc. / Amazon Technologies Inc', 'Amazon Technologies Inc. / AWS EC2',
    ],
    'The Constant Company, LLC': ['vultr', 'choopa'], 'OVH SAS': ['ovh'], 'Discord': ['i3d.net b.v'], 'i3D.net B.V': ['i3d.net', 'i3d'], 'Zenlayer Inc': ['zen'],
}

GENERIC_WORDS: set[str] = {
    'association', 'avenue', 'building', 'bvba', 'communication', 'communications', 'company', 'corp', 'corporation', 'gmbh', 'group', 'hosting', 'inc', 'incorporated',
    'interactive', 'labs', 'limited', 'llp', 'ltd', 'ltda', 'network', 'networks', 'services', 'software', 'solutions', 'technologies',
    'technology', 'telecom', 'telecommunications',
}


class RateLimitClient:
    """Client for querying the IP API with rate limiting."""

    def __init__(self, session: requests.Session) -> None:
        """Initialize the RateLimitClient."""
        self.session, self.min_interval = session, 60 / 14
        self.last_request_time, self.cooldown_until, self.window_reset_at = 0.0, 0.0, 0.0
        self.last_rate_limit, self.capacity, self.window, self.consecutive_errors = cast('int | None', None), 14, 60, 0
        self.tokens, self.last_refill = float(self.capacity), time.time()
        self.cache, self.sleep_callback = cast('dict[str, dict[str, Any]]', {}), cast('Callable[[float, str], None] | None', None)

    def _refill(self) -> None:
        """Refill the token bucket gradually based on elapsed time."""
        if (elapsed_seconds := (now := time.time()) - self.last_refill) > 0:
            self.tokens, self.last_refill = min(self.tokens + elapsed_seconds * (self.capacity / self.window), float(self.capacity)), now

    def _reset_tokens(self) -> None:
        """Reset tokens to full capacity and update refill timestamp."""
        self.tokens, self.last_refill, self.last_rate_limit = float(self.capacity), time.time(), None

    def _wait_for_cooldown(self) -> None:
        """Block until any active cooldown period has expired."""
        if (wait := self.cooldown_until - time.time()) > 0:
            console.print(f'[yellow]\\[COOLDOWN] waiting[/yellow] → [yellow]sleeping {int(wait) + 1}s[/yellow]')
            self._sleep(wait + 1, 'COOLDOWN waiting')
            self._close_stale_connections(wait + 1)
            self._reset_tokens()
            self.cooldown_until = 0.0

    def _close_stale_connections(self, sleep_duration: float) -> None:
        """Close pooled TCP connections if the sleep was long enough to make them stale."""
        if sleep_duration >= STALE_CONNECTION_THRESHOLD:
            self.session.close()

    def _respect_min_interval(self) -> None:
        """Ensure requests are spaced out by at least the minimum interval (or paced when low on quota)."""
        now, interval = time.time(), self.min_interval
        if self.last_rate_limit is not None and 0 < self.last_rate_limit <= THROTTLING_RATE_LIMIT_THRESHOLD and self.window_reset_at > now:
            interval = max(interval, (self.window_reset_at - now) / self.last_rate_limit)
        if (wait := interval - (now - self.last_request_time)) > 0:
            self._sleep(wait, 'API spacing')

    def _apply_headers(self, headers: Mapping[str, str]) -> None:
        """Apply rate limit headers (`X-Rl` and `X-Ttl`) from the API response."""
        now = time.time()
        with contextlib.suppress(ValueError, TypeError):
            ttl_value = max(int(headers.get('X-Ttl', self.window)), 1)
            self.window_reset_at, self.last_rate_limit = now + ttl_value, (rate_limit_value := int(headers['X-Rl']))
            self.tokens, self.last_refill = min(float(rate_limit_value), float(self.capacity)), now
            if rate_limit_value <= 0:
                self.cooldown_until = max(self.cooldown_until, now + ttl_value + 1)

    def _sleep(self, seconds: float, reason: str) -> None:
        """Sleep for the specified duration, using the sleep callback if registered."""
        if self.sleep_callback is not None:
            self.sleep_callback(seconds, reason)
        else:
            time.sleep(seconds)

    def _consume(self) -> None:
        """Consume a token from the bucket, throttling if necessary."""
        self._wait_for_cooldown()
        while True:
            self._refill()
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
            sleep_time = max((1.0 - self.tokens) / (self.capacity / self.window), 1.0)
            console.print(f'[yellow]\\[RATE] throttling[/yellow] → [yellow]sleeping {int(sleep_time)}s[/yellow]')
            self._sleep(sleep_time, 'RATE throttling')

    def post_batch(self, payload: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Post a batch of IPs to the rate-limited API."""
        self._consume()
        self._respect_min_interval()
        while True:
            try:
                response = self.session.post(IP_API_BATCH_URL, json=payload, timeout=30)
                self.last_request_time, self.consecutive_errors = time.time(), 0
                if response.status_code == COOLDOWN_HTTP_STATUS:
                    try:
                        wait_time = max(int(response.headers.get('X-Ttl', '60')) + 1, 1)
                    except ValueError:
                        wait_time = 60
                    self.cooldown_until, self.tokens = time.time() + wait_time, 0.0
                    console.print(f'[yellow]\\[429] cooldown[/yellow] → [yellow]sleeping {wait_time}s[/yellow]')
                    self._sleep(wait_time, '429 cooldown')
                    self._close_stale_connections(wait_time)
                    self._reset_tokens()
                    continue
                response.raise_for_status()
                self._apply_headers(response.headers)
                return cast('list[dict[str, Any]]', response.json())
            except requests.RequestException as e:
                self.consecutive_errors += 1
                backoff = min(10 * (2 ** (self.consecutive_errors - 1)), MAX_ERROR_BACKOFF)
                console.print(f'[red]\\[ERROR] Request failed (attempt {self.consecutive_errors}): {e}[/red]\n[yellow]\\[BACKOFF] sleeping {backoff}s[/yellow]')
                self._sleep(backoff, 'BACKOFF retry')
                self._close_stale_connections(backoff)

    def close(self) -> None:
        """Close the underlying HTTP session and its pooled connections."""
        self.session.close()


class GeoLite2Client:
    """Offline lookup client using local GeoLite2 database."""

    def __init__(self, database_path: Path) -> None:
        """Initialize the GeoLite2Client database reader."""
        self.reader = geoip2.database.Reader(database_path)
        self.cache: dict[str, dict[str, Any]] = {}
        self.sleep_callback: Callable[[float, str], None] | None = None

    def post_batch(self, payload: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Look up IP details from local GeoLite2 ASN database."""
        results: list[dict[str, Any]] = []
        for item in payload:
            ip_address = item['query']
            lookup_result: dict[str, Any] = {'query': ip_address, 'status': 'fail', 'message': 'address not found', 'isp': '', 'org': '', 'as': '', 'asname': ''}
            try:
                record = self.reader.asn(ip_address)
                org = record.autonomous_system_organization or ''
                asn = f'AS{record.autonomous_system_number}' if bool(record.autonomous_system_number) else ''
                lookup_result.update({'status': 'success', 'message': '', 'isp': org, 'org': org, 'as': asn, 'asname': org})
            except geoip2.errors.AddressNotFoundError:
                pass
            except geoip2.errors.GeoIP2Error as e:
                lookup_result['message'] = str(e)
            results.append(lookup_result)
        return results

    def close(self) -> None:
        """Close the database reader."""
        self.reader.close()


def lookup_ips_batch(client: RateLimitClient | GeoLite2Client, ip_addresses: list[str]) -> dict[str, dict[str, Any]]:
    """Look up details for a batch of IP addresses, chunking to respect API limits."""
    results = {ip: client.cache[ip] for ip in ip_addresses if ip in client.cache}
    missing_ip_addresses = [ip for ip in ip_addresses if ip not in client.cache]
    if missing_ip_addresses:
        for batch in chunked(missing_ip_addresses, API_BATCH_LIMIT):
            batch_results = client.post_batch([{'query': ip, 'fields': 'status,message,query,isp,org,as,asname'} for ip in batch])
            batch_dict = {cast('str', item.get('query')): item for item in batch_results}
            client.cache.update(batch_dict)
            results.update(batch_dict)
    return results


def extract_ranges(file_path: str) -> list[tuple[str, str, int]]:
    """Extract NamedRange definitions from a python source file using AST."""
    with Path(file_path).open(encoding='utf-8') as file:
        tree = ast.parse(file.read())
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
    """Generate representative IP samples from an IPv4 network."""
    samples: set[ipaddress.IPv4Address] = {network.network_address, network.broadcast_address}
    start, end = int(network.network_address), int(network.broadcast_address)
    step = max((end - start) // max(max_samples - len(samples), 1), 1)
    step = max(step - (step % SUBNET_BLOCK_SIZE), SUBNET_BLOCK_SIZE) if step >= SUBNET_BLOCK_SIZE else step
    current = start
    while current <= end and len(samples) < max_samples:
        aligned = ipaddress.IPv4Address(current - (current % SUBNET_BLOCK_SIZE))
        if network.network_address <= aligned <= network.broadcast_address:
            samples.add(aligned)
        current += step
    return sorted(map(str, samples))


def normalize(text: str) -> str:
    """Normalize text by converting to lowercase and replacing punctuation with spaces."""
    return text.lower().replace(',', ' ').replace('(', ' ').replace(')', ' ').replace('-', ' ')


def _tokenize_owner(owner: str) -> set[str]:
    """Extract distinctive match tokens from an owner name."""
    words = {word for raw in re.sub(r'[.()/, -]', ' ', owner.lower()).split() if len(word := raw.strip('.,/')) >= MIN_WORD_LENGTH}
    return (words - GENERIC_WORDS) or words


def owner_matches(expected: str, data: dict[str, Any]) -> bool:
    """Check if the expected owner matches the IP API response data."""
    actual = normalize(f'{data.get("isp", "")} {data.get("org", "")} {data.get("asname", "")} {data.get("as", "")}')
    if any(normalize(false_positive) in actual for false_positive in KNOWN_FALSE_POSITIVES.get(expected, [])):
        return False
    if any(normalize(alias) in actual for alias in KNOWN_ALIASES.get(expected, [])):
        return True
    return any(bool(re.search(r'\b' + re.escape(word) + r'\b', actual)) for word in _tokenize_owner(expected))


def chunked(list_to_chunk: list[Any], chunk_size: int) -> Generator[list[Any]]:
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(list_to_chunk), chunk_size):
        yield list_to_chunk[i : i + chunk_size]


def _block_to_ip(block_index: int) -> str:
    """Convert a /24 block index to its .0 IP address string."""
    return str(ipaddress.IPv4Address(block_index * SUBNET_BLOCK_SIZE))


def _ip_to_block(ip_address: str) -> int:
    """Convert an IP address string to its /24 block index."""
    return int(ipaddress.IPv4Address(ip_address)) // SUBNET_BLOCK_SIZE


def _check_block_owner(client: RateLimitClient | GeoLite2Client, owner: str, block_index: int, cache: dict[int, bool]) -> bool:
    """Check if a /24 block's .0 IP belongs to the expected owner. Results are cached."""
    if block_index not in cache:
        ip_address = _block_to_ip(block_index)
        lookup_result = lookup_ips_batch(client, [ip_address]).get(ip_address) or {}
        cache[block_index] = bool(lookup_result.get('status') == 'success' and owner_matches(owner, lookup_result))
    return cache[block_index]


def _binary_search_transition(client: RateLimitClient | GeoLite2Client, owner: str, low_index: int, high_index: int, cache: dict[int, bool]) -> None:
    """Binary search between two /24 block indices with different owner classifications."""
    while high_index - low_index > 1:
        middle_index = (low_index + high_index) // 2
        _check_block_owner(client, owner, middle_index, cache)
        if cache[middle_index] == cache[low_index]:
            low_index = middle_index
        else:
            high_index = middle_index


def scan_network_geolite2(
    client: GeoLite2Client, owner: str, network: ipaddress.IPv4Network,
) -> tuple[list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address, str]], list[ipaddress.IPv4Network]]:
    """Scan the entire IPv4 network block using GeoLite2 mmdb, returning mismatches and matching subnets."""
    current_ip, end_ip = network.network_address, network.broadcast_address
    mismatches: list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address, str]] = []
    matching_ranges: list[ipaddress.IPv4Network] = []

    while current_ip <= end_ip:
        try:
            record = client.reader.asn(str(current_ip))
            org = record.autonomous_system_organization or ''
            db_network = record.network if isinstance(record.network, ipaddress.IPv4Network) else ipaddress.IPv4Network(f'{current_ip}/24', strict=False)
            data = {'isp': org, 'org': org, 'asname': org, 'as': f'AS{record.autonomous_system_number}' if bool(record.autonomous_system_number) else ''}
            overlap_start, overlap_end = max(current_ip, db_network.network_address), min(end_ip, db_network.broadcast_address)
            if org:
                if owner_matches(owner, data):
                    matching_ranges.extend(ipaddress.summarize_address_range(overlap_start, overlap_end))
                else:
                    mismatches.append((overlap_start, overlap_end, org))
            if db_network.broadcast_address >= end_ip:
                break
            current_ip = db_network.broadcast_address + 1
        except geoip2.errors.AddressNotFoundError as e:
            unallocated_end = e.network.broadcast_address if isinstance(e.network, ipaddress.IPv4Network) else current_ip
            if unallocated_end >= end_ip:
                break
            current_ip = unallocated_end + 1
        except geoip2.errors.GeoIP2Error as e:
            mismatches.append((current_ip, current_ip, f'Error: {e}'))
            current_ip += 1

    return mismatches, list(ipaddress.collapse_addresses(matching_ranges))


def _format_networks_table(title: str, networks: list[ipaddress.IPv4Network], action_prefix: str) -> tuple[RenderableType, str]:
    """Format matching or expanded networks into a rich Table and plain text summary."""
    table = Table(title=title, box=box.ROUNDED, expand=False)
    table.add_column('Replacement Range', style='green')
    table.add_column('IP Coverage', style='cyan')
    for matching_network in networks:
        table.add_row(f"'{matching_network.with_prefixlen}',", f'({matching_network.network_address} - {matching_network.broadcast_address})')
    total_count = sum(matching_network.num_addresses for matching_network in networks)
    table.add_section()
    table.add_row('[bold]Total[/bold]', f'[bold]{networks[0].network_address} - {networks[-1].broadcast_address} ({total_count:,} IP{pluralize(total_count)})[/bold]')
    raw_text = f'{action_prefix}: {", ".join(matching_network.with_prefixlen for matching_network in networks)}'
    return table, raw_text


def _format_geolite2_fix(network: ipaddress.IPv4Network, matching_networks: list[ipaddress.IPv4Network]) -> tuple[RenderableType, str]:
    """Format an offline GeoLite2 fix suggestion from already-scanned matching networks."""
    if matching_networks:
        return _format_networks_table('[bold magenta]Fix Suggestion[/bold magenta] (offline GeoLite2 scan)', matching_networks, 'Replace with')
    raw_text = f'No matching blocks found — consider removing {network.with_prefixlen}'
    return Text(f'[FIX SUGGESTION] {raw_text}', style='red'), raw_text


def suggest_fix(
    client: RateLimitClient, owner: str, network: ipaddress.IPv4Network, results: dict[str, dict[str, Any]], status_callback: Callable[[str], None] | None = None,
) -> tuple[RenderableType | None, str]:
    """Binary-search /24 boundaries and suggest replacement CIDRs for a mismatched range."""
    if network.prefixlen > MAX_AUTO_FIX_PREFIX_LEN:
        if status_callback is not None:
            status_callback(f'[yellow]Range /{network.prefixlen} is smaller than /{MAX_AUTO_FIX_PREFIX_LEN} — skipping auto-fix[/yellow]')
        return None, f'Range /{network.prefixlen} is smaller than /{MAX_AUTO_FIX_PREFIX_LEN} — skipping auto-fix'

    start_block, end_block = int(network.network_address) // SUBNET_BLOCK_SIZE, int(network.broadcast_address) // SUBNET_BLOCK_SIZE
    block_count = end_block - start_block + 1
    if status_callback is not None:
        status_callback(f'[magenta]\\[AUTO-FIX][/magenta] Scanning {block_count:,} /24 block{pluralize(block_count)} for ownership boundaries...')

    cache = {
        block_index: (results.get(ip_address) or {}).get('status') == 'success' and owner_matches(owner, results.get(ip_address) or {})
        for ip_address in sample_ips(network)
        if start_block <= (block_index := _ip_to_block(ip_address)) <= end_block
    }
    _check_block_owner(client, owner, start_block, cache)
    _check_block_owner(client, owner, end_block, cache)
    initial_cache_size = len(cache)

    changed = True
    while changed:
        changed, sorted_blocks = False, sorted(cache.keys())
        for i in range(len(sorted_blocks) - 1):
            block_index_1, block_index_2 = sorted_blocks[i], sorted_blocks[i + 1]
            if cache[block_index_1] != cache[block_index_2] and block_index_2 - block_index_1 > 1:
                steps = (block_index_2 - block_index_1).bit_length()
                if status_callback is not None:
                    ip_1, ip_2 = _block_to_ip(block_index_1), _block_to_ip(block_index_2)
                    status_callback(f'[white]binary search[/white] {ip_1} .. {ip_2} (~{steps} quer{pluralize(steps, "y", "ies")})')
                _binary_search_transition(client, owner, block_index_1, block_index_2, cache)
                changed = True
                break

    extra_queries = len(cache) - initial_cache_size
    title_suffix = f' ([dim]{extra_queries} API quer{pluralize(extra_queries, "y", "ies")} used[/dim])' if extra_queries > 0 else ''

    sorted_blocks, good_networks, i = sorted(cache.keys()), cast('list[ipaddress.IPv4Network]', []), 0
    while i < len(sorted_blocks):
        if not cache[sorted_blocks[i]]:
            i += 1
            continue
        j = i
        while j < len(sorted_blocks) - 1 and cache[sorted_blocks[j + 1]]:
            j += 1
        first_ip = ipaddress.IPv4Address(max(sorted_blocks[i], start_block) * SUBNET_BLOCK_SIZE)
        last_ip = ipaddress.IPv4Address((min(sorted_blocks[j], end_block) + 1) * SUBNET_BLOCK_SIZE - 1)
        good_networks.extend(ipaddress.summarize_address_range(first_ip, last_ip))
        i = j + 1

    if good_networks:
        return _format_networks_table(f'[bold magenta]Fix Suggestion[/bold magenta]{title_suffix}', good_networks, 'Replace with')
    raw_text = f'No matching blocks found — consider removing {network.with_prefixlen}'
    return Text(f'[FIX SUGGESTION] {raw_text}', style='red'), raw_text


@dataclass(slots=True)
class RangeContext:
    """Context information for a CIDR range being verified."""

    network: ipaddress.IPv4Network
    owner_networks: list[ipaddress.IPv4Network]
    fallback_client: RateLimitClient | None = None


def _clamp_expansion_ip(
    candidate: ipaddress.IPv4Address, current: ipaddress.IPv4Address, owner_networks: list[ipaddress.IPv4Network], *, is_backward: bool,
) -> tuple[ipaddress.IPv4Address, bool]:
    """Clamp a candidate expansion boundary IP against already-known networks for the same owner."""
    overlaps = (
        [known.broadcast_address + 1 for known in owner_networks if candidate <= known.broadcast_address < current] if is_backward
        else [known.network_address - 1 for known in owner_networks if current < known.network_address <= candidate]
    )
    return ((max(overlaps) if is_backward else min(overlaps)), True) if overlaps else (candidate, False)


def _search_expansion_blocks(client: RateLimitClient, owner: str, start_block: int, direction: int, cache: dict[int, bool]) -> int:
    """Search outward from start_block in direction (+1 or -1) using /24 exponential and binary search."""
    step, current, last_good = 1, start_block, start_block
    while True:
        probe = max(0, min(current + step * direction, MAX_SLASH_24_BLOCK_INDEX))
        if _check_block_owner(client, owner, probe, cache):
            last_good = current = probe
            if probe in (0, MAX_SLASH_24_BLOCK_INDEX):
                break
            step *= 2
        else:
            low, high = (last_good, probe) if direction > 0 else (probe, last_good)
            _binary_search_transition(client, owner, low, high, cache)
            matching = [block for block, is_match in cache.items() if low <= block <= high and is_match]
            return max(matching) if direction > 0 else min(matching)
    return last_good


def _search_expansion_boundary(
    client: GeoLite2Client, owner: str, context: RangeContext, *, is_backward: bool, cache: dict[int, bool],
) -> tuple[ipaddress.IPv4Address, int]:
    """Search outward from context.network using GeoLite2 prefix boundaries (with optional IP-API fallback)."""
    boundary_ip, queries = context.network.network_address if is_backward else context.network.broadcast_address, 0
    while (int(boundary_ip) > 0) if is_backward else (int(boundary_ip) < MAX_IPV4_INT):
        probe_ip = boundary_ip - 1 if is_backward else boundary_ip + 1
        if any(probe_ip in known_network for known_network in context.owner_networks):
            break
        try:
            queries += 1
            record = client.reader.asn(str(probe_ip))
        except geoip2.errors.AddressNotFoundError:
            if context.fallback_client and owner not in IP_API_SKIPPED_OWNERS and _check_block_owner(context.fallback_client, owner, _ip_to_block(str(probe_ip)), cache):
                end_block = _search_expansion_blocks(context.fallback_client, owner, _ip_to_block(str(probe_ip)), -1 if is_backward else 1, cache)
                candidate = ipaddress.IPv4Address(end_block * SUBNET_BLOCK_SIZE if is_backward else (end_block + 1) * SUBNET_BLOCK_SIZE - 1)
                boundary_ip, _ = _clamp_expansion_ip(candidate, boundary_ip, context.owner_networks, is_backward=is_backward)
            break
        except geoip2.errors.GeoIP2Error:
            break
        org, asn = record.autonomous_system_organization or '', f'AS{record.autonomous_system_number}' if bool(record.autonomous_system_number) else ''
        if not org or not owner_matches(owner, {'isp': org, 'org': org, 'asname': org, 'as': asn}):
            break
        db_network = record.network if isinstance(record.network, ipaddress.IPv4Network) else ipaddress.IPv4Network(f'{probe_ip}/32')
        candidate = db_network.network_address if is_backward else db_network.broadcast_address
        boundary_ip, clamped = _clamp_expansion_ip(candidate, boundary_ip, context.owner_networks, is_backward=is_backward)
        if clamped:
            break
    return boundary_ip, queries


def suggest_expansion(
    client: RateLimitClient | GeoLite2Client, owner: str, context: RangeContext, expandable_ip_addresses: list[str], status_callback: Callable[[str], None] | None = None,
) -> tuple[RenderableType | None, str]:
    """Search outward from expandable adjacent IPs to find the full owner boundary."""
    if isinstance(client, RateLimitClient) and owner in IP_API_SKIPPED_OWNERS:
        raw_text = f'Expandable adjacent IP{pluralize(len(expandable_ip_addresses))}: {", ".join(expandable_ip_addresses)}'
        return Text(f'[EXPAND SUGGESTION] {raw_text}', style='magenta'), raw_text

    first_ip, last_ip = context.network.network_address, context.network.broadcast_address
    cache: dict[int, bool] = {_ip_to_block(ip_address): True for ip_address in expandable_ip_addresses}
    initial_cache_size, geolite_queries = len(cache), 0

    for ip_address in expandable_ip_addresses:
        is_backward = ipaddress.IPv4Address(ip_address) < context.network.network_address
        if status_callback is not None:
            status_callback(f'[magenta]\\[AUTO-EXPAND][/magenta] Searching {"backward" if is_backward else "forward"} from {ip_address}...')
        if isinstance(client, GeoLite2Client):
            boundary_ip, queries = _search_expansion_boundary(client, owner, context, is_backward=is_backward, cache=cache)
            geolite_queries += queries
        else:
            end_block = _search_expansion_blocks(client, owner, _ip_to_block(ip_address), -1 if is_backward else 1, cache)
            candidate = ipaddress.IPv4Address(end_block * SUBNET_BLOCK_SIZE if is_backward else (end_block + 1) * SUBNET_BLOCK_SIZE - 1)
            boundary_ip, _ = _clamp_expansion_ip(candidate, first_ip if is_backward else last_ip, context.owner_networks, is_backward=is_backward)
        if is_backward:
            first_ip = min(first_ip, boundary_ip)
        else:
            last_ip = max(last_ip, boundary_ip)

    api_queries = len(cache) - initial_cache_size
    title_suffix = (
        f' ([dim]{api_queries} API quer{pluralize(api_queries, "y", "ies")} used[/dim])' if api_queries > 0
        else f' ([dim]{geolite_queries} GeoLite2 lookup{pluralize(geolite_queries)} used[/dim])' if geolite_queries > 0
        else ''
    )
    return _format_networks_table(f'[bold magenta]Expand Suggestion[/bold magenta]{title_suffix}', list(ipaddress.summarize_address_range(first_ip, last_ip)), 'Expand to')


def _get_adjacent_ips(network: ipaddress.IPv4Network) -> list[str]:
    """Get the IP addresses immediately adjacent to the network (before and after)."""
    adjacent: list[str] = []
    if int(network.network_address) > 0:
        adjacent.append(str(network.network_address - 1))
    if int(network.broadcast_address) < MAX_IPV4_INT:
        adjacent.append(str(network.broadcast_address + 1))
    return adjacent


def render_samples(samples: list[str]) -> Columns:
    """Render a grid-aligned column view of representative sample IP addresses."""
    texts = [Text(ip, style='magenta') for ip in samples[:MAX_SAMPLE_IPS]]
    if len(samples) > MAX_SAMPLE_IPS:
        texts.append(Text(f'... (+{len(samples) - MAX_SAMPLE_IPS} more)', style='dim magenta'))
    return Columns(texts, equal=True, expand=True)


def _collect_sample_mismatches(
    samples: list[str], results: dict[str, dict[str, Any]], owner: str, cidr_range: str,
) -> tuple[bool, list[str], list[str]]:
    """Check sampled IPs against lookup results, collecting mismatch messages."""
    is_valid, mismatch_lines, mismatches_raw = True, cast('list[str]', []), cast('list[str]', [])
    for ip_address in samples:
        lookup_result = results.get(ip_address) or {}
        if lookup_result.get('status') != 'success':
            is_valid = False
        elif not owner_matches(owner, lookup_result):
            owner_info = f'{lookup_result.get("isp")} / {lookup_result.get("org")}'
            mismatch_lines.append(f'[red]✗[/red] [magenta]{ip_address}[/magenta] → {owner_info}')
            mismatches_raw.append(f'✗ {cidr_range} ({ip_address}) → {owner_info}')
            is_valid = False
    return is_valid, mismatch_lines, mismatches_raw


def _evaluate_expansion_boundary(
    network: ipaddress.IPv4Network, adjacent_ip_addresses: list[str], owner: str, owner_networks: list[ipaddress.IPv4Network], results: dict[str, dict[str, Any]],
) -> tuple[bool, list[str], str, str, list[str], list[str]]:
    """Evaluate adjacent IP addresses for backward and forward expansion."""
    start_ip_int, expansion_found, expandable_ip_addresses = int(network.network_address), False, cast('list[str]', [])
    statuses, details = {'BACKWARD': '[green]✓ Clear[/green]', 'FORWARD': '[green]✓ Clear[/green]'}, cast('dict[str, list[str]]', {'BACKWARD': [], 'FORWARD': []})

    for ip_address in adjacent_ip_addresses:
        direction = 'BACKWARD' if int(ipaddress.IPv4Address(ip_address)) < start_ip_int else 'FORWARD'
        if any(ipaddress.IPv4Address(ip_address) in owner_network for owner_network in owner_networks):
            statuses[direction], detail_msg = '[green]✓ Already Covered[/green]', '[green]Already Covered[/green]'
        else:
            lookup_result = results.get(ip_address) or {}
            status_val, msg_val = lookup_result.get('status'), lookup_result.get('message')
            is_non_fail = status_val == 'fail' and msg_val in ('address not found', 'private range', 'reserved range')
            if status_val != 'success' and not is_non_fail:
                statuses[direction], detail_msg = '[yellow]! Lookup Failed[/yellow]', '[yellow]Lookup Failed[/yellow]'
            elif owner_matches(owner, lookup_result):
                statuses[direction], detail_msg = '[red]✗ Expandable[/red]', f'[magenta]Same Owner ({lookup_result.get("isp")} / {lookup_result.get("org")})[/magenta]'
                expansion_found = True
                expandable_ip_addresses.append(ip_address)
            else:
                statuses[direction] = '[green]✓ Boundary OK[/green]'
                desc = msg_val.title() if msg_val and is_non_fail else (
                    f'{lookup_result.get("isp")} / {lookup_result.get("org")}' if lookup_result.get('isp') and lookup_result.get('org')
                    else lookup_result.get('isp') or lookup_result.get('org') or 'Unknown'
                )
                detail_msg = f'[green]Different Owner ({desc})[/green]'
        details[direction].append(f'[magenta]{ip_address}[/magenta]\nStatus: {detail_msg}')

    return expansion_found, expandable_ip_addresses, statuses['BACKWARD'], statuses['FORWARD'], details['BACKWARD'], details['FORWARD']


@dataclass(kw_only=True, slots=True)
class CheckRangeOptions:
    """Optional configuration and state for checking a CIDR range."""

    location: tuple[str, int | None] | None = None
    only_detections: bool = False
    detections: list[str] | None = None
    fallback_client: RateLimitClient | None = None
    status_callback: Callable[[str], None] | None = None


def check_range(
    client: RateLimitClient | GeoLite2Client, owner: str, cidr_range: str, owner_networks: list[ipaddress.IPv4Network], options: CheckRangeOptions | None = None,
) -> bool:
    """Check the validity of the CIDR range and look for potential expansion."""
    options = options or CheckRangeOptions()
    file_path, line_number = options.location or ('', None)
    network = ipaddress.ip_network(cidr_range)
    if not isinstance(network, ipaddress.IPv4Network):
        message = f'Only IPv4 networks are supported: {cidr_range}'
        raise TypeError(message)

    base_samples, adjacent_ip_addresses = sample_ips(network), _get_adjacent_ips(network)
    all_ip_addresses = list(dict.fromkeys(base_samples + adjacent_ip_addresses))
    results = lookup_ips_batch(client, adjacent_ip_addresses if isinstance(client, GeoLite2Client) else all_ip_addresses)
    is_valid, has_mismatches, active_client = True, False, client
    mismatch_lines, mismatches_raw, matching_networks = cast('list[str]', []), cast('list[str]', []), cast('list[ipaddress.IPv4Network]', [])

    if isinstance(client, GeoLite2Client):
        mismatches, matching_networks = scan_network_geolite2(client, owner, network)
        if mismatches:
            is_valid, has_mismatches = False, True
            for start_ip, end_ip, actual_owner in mismatches:
                ip_range_str = str(start_ip) if start_ip == end_ip else f'{start_ip} - {end_ip}'
                mismatch_lines.append(f'[red]✗[/red] [magenta]{ip_range_str}[/magenta] → {actual_owner}')
                mismatches_raw.append(f'✗ {cidr_range} ({ip_range_str}) → {actual_owner}')
        elif not matching_networks and options.fallback_client and owner not in IP_API_SKIPPED_OWNERS and network.prefixlen > MAX_IP_API_SUBNET_PREFIX:
            if options.status_callback is not None:
                options.status_callback('[yellow]Fallback to IP-API[/yellow]')
            fallback_results = lookup_ips_batch(options.fallback_client, all_ip_addresses)
            results.update(fallback_results)
            active_client = options.fallback_client
            sample_valid, lines, raw = _collect_sample_mismatches(base_samples, fallback_results, owner, cidr_range)
            if not sample_valid:
                is_valid, has_mismatches = False, True
                mismatch_lines.extend(lines)
                mismatches_raw.extend(raw)
        if options.fallback_client and owner not in IP_API_SKIPPED_OWNERS and (
            missing_adjacent := [ip for ip in adjacent_ip_addresses if (results.get(ip) or {}).get('message') == 'address not found']
        ):
            results.update(lookup_ips_batch(options.fallback_client, missing_adjacent))
    else:
        sample_valid, lines, raw = _collect_sample_mismatches(base_samples, results, owner, cidr_range)
        if not sample_valid:
            is_valid, has_mismatches = False, True
            mismatch_lines.extend(lines)
            mismatches_raw.extend(raw)

    expansion_found, expandable_ip_addresses, backward_status, forward_status, backward_details, forward_details = _evaluate_expansion_boundary(
        network, adjacent_ip_addresses, owner, owner_networks, results,
    )
    renderables: list[RenderableType] = [Panel(render_samples(all_ip_addresses), title='[cyan]Sampled IPs[/cyan]', border_style='cyan', box=box.ROUNDED), Text('')]
    base_status = (
        '[red]✗ Mismatches Found[/red]' if has_mismatches
        else '[yellow]! Not in GeoLite2[/yellow]' if isinstance(active_client, GeoLite2Client) and not matching_networks else '[green]✓ Pass[/green]'
    )
    validation_table = Table.grid(padding=(0, 4))
    validation_table.add_column(style='cyan', justify='left')
    validation_table.add_column(justify='left')
    validation_table.add_row('Base Check', base_status)
    validation_table.add_row('Backward Expansion', backward_status)
    validation_table.add_row('Forward Expansion', forward_status)

    details_table = Table.grid(padding=(0, 4), expand=True)
    for _ in range(4):
        details_table.add_column()
    backward_text, forward_text = '\n'.join(backward_details) if backward_details else 'N/A', '\n'.join(forward_details) if forward_details else 'N/A'
    summary_text = (
        ('[green]✓ Range Verified\n✓ Ownership Consistent[/green]' if is_valid else '[red]✗ Range Verification Failed\n✗ Ownership Inconsistent[/red]')
        + ('\n[green]✓ No Expansion Opportunities[/green]' if not expansion_found else '\n[yellow]! Expansion Opportunities Found[/yellow]')
    )
    details_table.add_row(
        Panel(backward_text, title='[cyan]Backward Expansion[/cyan]', border_style='cyan', box=box.ROUNDED),
        Panel(forward_text, title='[cyan]Forward Expansion[/cyan]', border_style='cyan', box=box.ROUNDED),
        Panel(validation_table, title='[cyan]Validation Results[/cyan]', border_style='cyan', box=box.ROUNDED),
        Panel(summary_text, title='[cyan]Summary[/cyan]', border_style='cyan', box=box.ROUNDED),
    )
    renderables.append(details_table)

    fix_raw = ''
    if has_mismatches:
        mismatch_panel = Panel('\n'.join(mismatch_lines), title='[red]Base Check Mismatches[/red]', border_style='red', box=box.ROUNDED)
        renderables.extend([Text(''), Rule('[bold white]Fix Suggestion[/bold white]'), mismatch_panel])
        fix_renderable, fix_raw = (
            _format_geolite2_fix(network, matching_networks) if isinstance(active_client, GeoLite2Client)
            else suggest_fix(active_client, owner, network, results, options.status_callback)
        )
        if fix_renderable is not None:
            renderables.append(fix_renderable)

    expansion_raw = ''
    if expansion_found:
        context = RangeContext(network, owner_networks, options.fallback_client)
        expansion_renderable, expansion_raw = suggest_expansion(active_client, owner, context, expandable_ip_addresses, options.status_callback)
        if expansion_renderable is not None:
            renderables.extend([Text(''), Rule('[bold white]Expansion Available[/bold white]'), expansion_renderable])

    clean_path = os.path.relpath(file_path).replace('\\', '/') if file_path else ''
    if has_mismatches and options.detections is not None:
        options.detections.extend(f'{clean_path}:{line_number}: ({owner}) {mismatch} | [FIX SUGGESTION] {fix_raw}' for mismatch in mismatches_raw)
    if expansion_found and options.detections is not None:
        options.detections.append(f'{clean_path}:{line_number}: ({owner}) [EXPANSION] {cidr_range} is expandable | [EXPAND SUGGESTION] {expansion_raw}')

    if not options.only_detections or not is_valid or expansion_found:
        title = (
            f'[bold white]{owner}[/bold white]  •  [bold magenta]{network.with_prefixlen}[/bold magenta]  •  '
            f'[dim]{network.network_address} → {network.broadcast_address}[/dim]  •  '
            f'[bold white]{network.num_addresses:,} IP{pluralize(network.num_addresses)}[/bold white]'
        ) + (f'  •  [blue]{clean_path}:{line_number}[/blue]' if file_path and line_number is not None else '')
        console.print()
        console.print(Panel(Group(*renderables), title=title, border_style='cyan', box=box.ROUNDED))

    return is_valid


def run_preflight_checks(
    ranges: list[tuple[str, str, int]], networks_by_owner: dict[str, list[ipaddress.IPv4Network]], *, ranges_file: str = '', detections: list[str] | None = None,
) -> None:
    """Run all pre-flight checks and display them in a neat panel."""
    table = Table(show_header=False, expand=True, box=None, padding=(0, 2))
    table.add_column(style='cyan', justify='left', ratio=1)
    table.add_column(justify='left', ratio=3)
    clean_path = os.path.relpath(ranges_file).replace('\\', '/') if ranges_file else ''
    line_by_range = {(owner, cidr_range): line for owner, cidr_range, line in reversed(ranges)}

    valid_pairs = {(owner, network.with_prefixlen) for owner, networks in networks_by_owner.items() for network in networks}
    if invalid_ranges := [(owner, cidr_range, line) for owner, cidr_range, line in ranges if (owner, cidr_range) not in valid_pairs]:
        invalid_lines = [f'[dim]• {cidr_range} ({owner})[/dim]' + (f'  [blue]{clean_path}:{line}[/blue]' if clean_path else '') for owner, cidr_range, line in invalid_ranges]
        table.add_row('Invalid CIDRs', f'[red]✗ {len(invalid_ranges)} invalid CIDR{pluralize(len(invalid_ranges))}![/red]\n' + '\n'.join(invalid_lines))
        if detections is not None:
            detections.extend(f'{clean_path}:{line}: ({owner}) [INVALID CIDR] {cidr_range}' for owner, cidr_range, line in invalid_ranges)

    unsorted_owners: list[str] = []
    for owner, networks in networks_by_owner.items():
        if networks != (sorted_networks := sorted(networks)):
            first_unsorted = next(network for network, sorted_network in zip(networks, sorted_networks, strict=True) if network != sorted_network)
            line = line_by_range.get((owner, first_unsorted.with_prefixlen), 0)
            unsorted_owners.append(f'{owner} ([blue]{clean_path}:{line}[/blue])' if clean_path and line else owner)
            if detections is not None:
                detections.append(f'{clean_path}:{line}: ({owner}) [UNSORTED] {first_unsorted.with_prefixlen} is out of order')
    unsorted_count = len(unsorted_owners)
    sort_text = (
        f'[yellow]⚠ {unsorted_count} owner{pluralize(unsorted_count)} {pluralize(unsorted_count, "has", "have")} unsorted ranges ({", ".join(unsorted_owners)})[/yellow]'
        if unsorted_owners else '[green]✓ All ranges correctly sorted[/green]'
    )
    table.add_row('CIDR Sorting', sort_text)

    all_networks = [(owner, ipaddress.IPv4Network(cidr_range), line) for owner, cidr_range, line in ranges if (owner, cidr_range) in valid_pairs]
    overlap_items = [
        (owner_1, network_1, line_1, owner_2, network_2) for i, (owner_1, network_1, line_1) in enumerate(all_networks)
        for j, (owner_2, network_2, _) in enumerate(all_networks)
        if (i < j if network_1 == network_2 else i != j) and network_1.subnet_of(network_2) and 'BattlEye' not in (owner_1, owner_2)
    ]
    overlaps = [
        f'[dim]• {network_1} ({owner_1}) falls within {network_2} ({owner_2})[/dim]' + (f'  [blue]{clean_path}:{line_1}[/blue]' if clean_path and line_1 else '')
        for owner_1, network_1, line_1, owner_2, network_2 in overlap_items
    ]
    if detections is not None:
        detections.extend(f'{clean_path}:{item[2]}: ({item[0]}) [OVERLAP] {item[1]} falls within {item[4]} ({item[3]})' for item in overlap_items)
    overlap_text = (
        f'[yellow]⚠ {len(overlaps)} overlap{pluralize(len(overlaps))} detected![/yellow]\n' + '\n'.join(overlaps)
        if overlaps else '[green]✓ No overlapping CIDRs found[/green]'
    )
    table.add_row('Overlapping CIDRs', overlap_text)

    collapses, collapse_suggestions = cast('list[str]', []), cast('list[str]', [])
    for owner, networks in networks_by_owner.items():
        collapsed = list(ipaddress.collapse_addresses(networks))
        if len(collapsed) < len(networks):
            collapses.append(f'[dim]• {owner}: {len(networks)} range{pluralize(len(networks))} → {len(collapsed)}[/dim]')
            deleted_networks = [network for network in networks if network not in collapsed]
            first_line = min((line_by_range.get((owner, network.with_prefixlen), 0) for network in deleted_networks), default=0)
            link_str = f'  •  [blue]{clean_path}:{first_line}[/blue]' if (first_line and clean_path) else ''
            to_delete = [f"    '{network.with_prefixlen}'," for network in deleted_networks]
            to_add = [f"    '{network.with_prefixlen}'," for network in collapsed if network not in networks]
            lines = [f'[bold white]{owner}[/bold white] ({len(networks)} range{pluralize(len(networks))} → {len(collapsed)}){link_str}']
            if to_delete:
                lines.extend([f'  [red]❌ Delete {pluralize(len(to_delete), "this range", "these ranges")}:[/red]', *to_delete])
            if to_add:
                lines.extend([f'  [green]➕ Add {pluralize(len(to_add), "this range", "these ranges")} instead:[/green]', *to_add])
            collapse_suggestions.append('\n'.join(lines))
            if detections is not None:
                detections.append(f'{clean_path}:{first_line}: ({owner}) [COLLAPSIBLE] {len(networks)} ranges -> {len(collapsed)}')

    collapse_text = (
        f'[yellow]⚠ {len(collapses)} collapsible block{pluralize(len(collapses))} found![/yellow]\n' + '\n'.join(collapses)
        if collapses else '[green]✓ No collapsible ranges found[/green]'
    )
    table.add_row('Collapsible CIDRs', collapse_text)
    renderables: list[Any] = [table]
    if collapse_suggestions:
        header = Text.from_markup('[yellow]💡 Edit the ranges for the owner in your code by deleting and adding the subnets below:[/yellow]')
        renderables.extend([Text(''), Rule('[bold yellow]CIDR Collapse Suggestions[/bold yellow]'), header, Text(''), Text.from_markup('\n\n'.join(collapse_suggestions))])
    console.print()
    console.print(Panel(Group(*renderables), title='[bold cyan]Pre-flight Validations[/bold cyan]', border_style='cyan', box=box.ROUNDED))


def should_skip(owner: str, cidr_range: str = '', *, use_geolite2: bool) -> bool:
    """Return True if range verification should be skipped for this owner or range."""
    if owner in ALWAYS_SKIPPED_OWNERS:
        return True
    if not use_geolite2:
        if owner in IP_API_SKIPPED_OWNERS:
            return True
        if cidr_range:
            with contextlib.suppress(ValueError, TypeError):
                network = ipaddress.ip_network(cidr_range)
                return isinstance(network, ipaddress.IPv4Network) and network.prefixlen <= MAX_IP_API_SUBNET_PREFIX
    return False


def _create_progress(description: str) -> Progress:
    """Create a standardized progress bar for prefetching or verification."""
    return Progress(
        SpinnerColumn(), TextColumn(f'[bold cyan]{description}[/bold cyan]'), BarColumn(bar_width=30),
        TaskProgressColumn(), MofNCompleteColumn(), TextColumn('[dim]•[/dim]'), TimeElapsedColumn(), TextColumn('[dim]•[/dim]'),
        TextColumn('{task.description}'), console=console, transient=True,
    )


def _make_sleep_callback(progress: Progress, task_id: TaskID, prefix: str = '') -> Callable[[float, str], None]:
    """Create a callback for rate-limit sleeps that updates the progress bar description."""
    def callback(seconds: float, reason: str) -> None:
        total_sleep = int(seconds)
        if (fraction := seconds - total_sleep) > 0 and total_sleep > 0:
            time.sleep(fraction)
        elif total_sleep <= 0:
            time.sleep(seconds)
            return
        task = next((task for task in progress.tasks if task.id == task_id), None)
        base_desc = prefix or (task.description if task else '')
        for remaining in range(total_sleep, 0, -1):
            desc_text = f'{reason} (sleeping {remaining}s)...' if prefix else f'{base_desc} [yellow]• {reason} ({remaining}s)[/yellow]'
            progress.update(task_id, description=desc_text)
            time.sleep(1)
        if not prefix:
            progress.update(task_id, description=base_desc)

    return callback


def main() -> None:
    """Main entry point to parse command-line arguments and check ranges."""
    start_time = time.time()
    if hasattr(sys.stdout, 'reconfigure'):
        cast('Any', sys.stdout).reconfigure(encoding='utf-8')

    parser = argparse.ArgumentParser(description='Verify IP ranges of third party servers.')
    parser.add_argument('ranges_file', help='Python file containing NamedRange definitions.')
    parser.add_argument('--geolite2', action='store_true', help='Use local GeoLite2 database instead of IP-API.')
    parser.add_argument('--ip-api-fallback', action='store_true', help='Allow unknown GeoLite2 ranges to fallback to IP-API.')
    parser.add_argument('--only-detections', action='store_true', help='Only print blocks with mismatches or expansion opportunities.')
    parser.add_argument('-o', '--owner', action='append', help='Only verify ranges matching the specified owner filter (repeatable or comma-separated).')
    parser.add_argument('--export', help='Export one-line detections to the specified text file.')
    parsed_arguments = parser.parse_args([arg for arg in sys.argv if arg][1:])

    raw_ranges = extract_ranges(str(parsed_arguments.ranges_file))
    if parsed_arguments.owner:
        all_owners = sorted({owner for owner, _, _ in raw_ranges})
        owner_filters = [part.strip().lower() for raw_filter in parsed_arguments.owner for part in raw_filter.split(',') if part.strip()]
        if not (raw_ranges := [(owner, cidr_range, line) for owner, cidr_range, line in raw_ranges if any(owner_filter in owner.lower() for owner_filter in owner_filters)]):
            console.print(f'[red]Error: No ranges matched --owner filter. Available owners: {", ".join(all_owners)}[/red]')
            sys.exit(1)
    parsed_ranges, networks_by_owner = cast('list[tuple[str, str, ipaddress.IPv4Network, int]]', []), cast('dict[str, list[ipaddress.IPv4Network]]', {})
    for owner, cidr_range, line_number in raw_ranges:
        with contextlib.suppress(ValueError, TypeError):
            if isinstance(network := ipaddress.ip_network(cidr_range), ipaddress.IPv4Network):
                parsed_ranges.append((owner, cidr_range, network, line_number))
                networks_by_owner.setdefault(owner, []).append(network)

    detections: list[str] = []
    console.rule('[bold cyan]Session Sniffer - Range Verification Engine[/bold cyan]')
    console.print(f'  [cyan]Loaded [bold white]{len(raw_ranges)}[/bold white] range{pluralize(len(raw_ranges))} for processing.[/cyan]')
    run_preflight_checks(raw_ranges, networks_by_owner, ranges_file=str(parsed_arguments.ranges_file), detections=detections)

    fallback_client: RateLimitClient | None = None
    if parsed_arguments.geolite2:
        database_path = GEOLITE2_DATABASES_DIR_PATH / 'GeoLite2-ASN.mmdb'
        if not database_path.exists():
            console.print(f'[red]Error: GeoLite2-ASN database not found at {database_path.absolute()}[/red]\n[yellow]Please download it or launch the main app first.[/yellow]')
            sys.exit(1)
        client: GeoLite2Client | RateLimitClient = GeoLite2Client(database_path)
        fallback_client = RateLimitClient(_ip_api_session) if parsed_arguments.ip_api_fallback else None
    else:
        client = RateLimitClient(_ip_api_session)

    if isinstance(client, RateLimitClient):
        ip_to_owners: dict[str, set[str]] = {}
        for owner, cidr_range, network, _ in parsed_ranges:
            if not should_skip(owner, cidr_range, use_geolite2=parsed_arguments.geolite2):
                for ip_address in sample_ips(network) + _get_adjacent_ips(network):
                    ip_to_owners.setdefault(ip_address, set()).add(owner)
        if ip_to_owners:
            ips_list = list(ip_to_owners.keys())
            with (prefetch_progress := _create_progress(f'Pre-fetching {len(ips_list):,} IP{pluralize(len(ips_list))}')):
                prefetch_task = prefetch_progress.add_task('', total=(len(ips_list) + API_BATCH_LIMIT - 1) // API_BATCH_LIMIT)
                client.sleep_callback = _make_sleep_callback(prefetch_progress, prefetch_task, prefix='[yellow]RATE[/yellow]')
                for i, batch in enumerate(chunked(ips_list, API_BATCH_LIMIT), 1):
                    batch_owners = sorted({owner for ip in batch for owner in ip_to_owners[ip]})
                    extra_owners_text = f' and {len(batch_owners) - MAX_DISPLAYED_OWNERS} more' if len(batch_owners) > MAX_DISPLAYED_OWNERS else ''
                    prefetch_progress.update(prefetch_task, completed=i, description=f'[white]{", ".join(batch_owners[:MAX_DISPLAYED_OWNERS])}{extra_owners_text}[/white]')
                    lookup_ips_batch(client, batch)
                client.sleep_callback = None

    if not parsed_arguments.only_detections:
        console.print()

    total_count = sum(1 for owner, cidr_range, _, _ in parsed_ranges if not should_skip(owner, cidr_range, use_geolite2=parsed_arguments.geolite2))
    current_index, base_status = 0, ''
    with (progress := _create_progress('Verifying')):
        task_id = progress.add_task('', total=total_count)
        verification_callback = _make_sleep_callback(progress, task_id)
        if isinstance(client, RateLimitClient):
            client.sleep_callback = verification_callback
        if fallback_client:
            fallback_client.sleep_callback = verification_callback

        def _update_status(description: str) -> None:
            progress.update(task_id, description=f'{base_status} [dim]•[/dim] {description}' if base_status else description)

        for owner, cidr_range, _, line_number in parsed_ranges:
            if should_skip(owner, cidr_range, use_geolite2=parsed_arguments.geolite2):
                if not parsed_arguments.only_detections:
                    clean_path = os.path.relpath(str(parsed_arguments.ranges_file)).replace('\\', '/')
                    link = f'  •  [blue]{clean_path}:{line_number}[/blue]' if clean_path else ''
                    console.print(f'[dim]ℹ Skipping Range Verification for {owner} CIDR:[/dim] [magenta dim]{cidr_range}[/magenta dim]{link}')
                continue

            current_index += 1
            base_status = f'[white]{owner}[/white] [magenta]{cidr_range}[/magenta]'
            progress.update(task_id, completed=current_index, description=base_status)
            check_range(client, owner, cidr_range, networks_by_owner.get(owner, []), CheckRangeOptions(
                location=(str(parsed_arguments.ranges_file), line_number), only_detections=parsed_arguments.only_detections,
                detections=detections, fallback_client=fallback_client, status_callback=_update_status,
            ))

    if isinstance(client, RateLimitClient):
        client.sleep_callback = None
    if fallback_client:
        fallback_client.sleep_callback = None
    if not parsed_arguments.only_detections:
        console.print()
    console.rule('[bold green]✓ Range Verification Complete[/bold green]')
    skipped_count = len(raw_ranges) - total_count
    console.print(
        f'  [green]✓ Successfully verified [bold]{total_count}[/bold] range{pluralize(total_count)} in [bold]{format_duration(time.time() - start_time)}[/bold].[/green]',
    )
    if skipped_count > 0:
        console.print(f'  [dim]ℹ Skipped [bold]{skipped_count}[/bold] range{pluralize(skipped_count)} (ignored owners / huge ranges).[/dim]')

    if parsed_arguments.export:
        export_path = Path(parsed_arguments.export)
        try:
            export_path.write_text('\n'.join(detections) + '\n' if detections else '', encoding='utf-8')
            console.print(f'\n[green]✓ Exported {len(detections)} detection{pluralize(len(detections))} to {export_path.resolve()}[/green]')
        except OSError as e:
            console.print(f'\n[red]✗ Failed to export detections to {export_path.resolve()}: {e}[/red]')

    client.close()
    if fallback_client:
        fallback_client.close()


if __name__ == '__main__':
    main()
