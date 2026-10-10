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
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TaskID, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from session_sniffer.guis.utils import format_duration
from session_sniffer.networking.http_session import HEADERS
from session_sniffer.text_utils import pluralize
from session_sniffer.utils import get_app_dir

_ip_api_session = requests.Session()
_ip_api_session.headers.update(HEADERS)

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
    'The Constant Company, LLC': ['vultr', 'choopa'],
    'OVH SAS': ['ovh'],
    'Discord': ['i3d.net b.v'],
    'i3D.net B.V': ['i3d.net', 'i3d'],
    'Zenlayer Inc': ['zen'],
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
        self.last_request_time, self.cooldown_until = 0.0, 0.0
        self.last_rate_limit: int | None = None
        self.capacity, self.window = 14, 60
        self.tokens, self.last_refill = float(self.capacity), time.time()
        self.consecutive_errors = 0
        self.cache: dict[str, dict[str, Any]] = {}
        self.sleep_callback: Callable[[float, str], None] | None = None

    def _refill(self) -> None:
        """Refill the token bucket gradually based on elapsed time."""
        now = time.time()
        if (elapsed_seconds := now - self.last_refill) > 0:
            self.tokens = min(self.tokens + elapsed_seconds * (self.capacity / self.window), float(self.capacity))
            self.last_refill = now

    def _reset_tokens(self) -> None:
        """Reset tokens to full capacity and update refill timestamp."""
        self.tokens = float(self.capacity)
        self.last_refill = time.time()

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
        """Ensure requests are spaced out by at least the minimum interval."""
        if (wait := self.min_interval - (time.time() - self.last_request_time)) > 0:
            self._sleep(wait, 'API spacing')

    def _apply_headers(self, headers: Mapping[str, str]) -> None:
        """Apply rate limit headers from the API response."""
        with contextlib.suppress(ValueError, TypeError):
            rate_limit_value = int(headers['X-Rl'])
            self.last_rate_limit = rate_limit_value
            self.tokens = min(float(rate_limit_value), float(self.capacity))

    def _sleep(self, seconds: float, reason: str) -> None:
        """Sleep for the specified duration, using the sleep callback if registered."""
        if self.sleep_callback is not None:
            with contextlib.suppress(Exception):
                self.sleep_callback(seconds, reason)
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
                self.last_request_time = time.time()
                self.consecutive_errors = 0
                if response.status_code == COOLDOWN_HTTP_STATUS:
                    try:
                        wait_time = max(int(response.headers.get('X-Ttl', '60')) + 1, 1)
                    except ValueError:
                        wait_time = 60
                    self.cooldown_until = time.time() + wait_time
                    self.tokens = 0.0
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
    text = re.sub(r'[.()/]', ' ', owner.lower()).replace(',', ' ').replace('-', ' ')
    words = {word.strip('.,/') for word in text.split()}
    return {word for word in words if len(word) >= MIN_WORD_LENGTH} - GENERIC_WORDS


def owner_matches(expected: str, data: dict[str, Any]) -> bool:
    """Check if the expected owner matches the IP API response data."""
    actual = normalize(f'{data.get("isp", "")} {data.get("org", "")} {data.get("asname", "")} {data.get("as", "")}')
    for false_positive in KNOWN_FALSE_POSITIVES.get(expected, []):
        if normalize(false_positive) in actual:
            return False
    for alias in KNOWN_ALIASES.get(expected, []):
        if normalize(alias) in actual:
            return True
    words = _tokenize_owner(expected)
    if not words:
        text = re.sub(r'[.()/]', ' ', expected.lower()).replace(',', ' ').replace('-', ' ')
        words = {word.strip('.,/') for word in text.split()}
        words = {word for word in words if len(word) >= MIN_WORD_LENGTH}
    if not words:
        return False
    return any(bool(re.search(r'\b' + re.escape(word) + r'\b', actual)) for word in words)


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
        except geoip2.errors.AddressNotFoundError:
            next_24_ip = ((int(current_ip) // 256) + 1) * 256
            if ipaddress.IPv4Network(f'{current_ip}/24', strict=False).broadcast_address >= end_ip:
                break
            current_ip = ipaddress.IPv4Address(next_24_ip)
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
    total_ip_addresses = sum(matching_network.num_addresses for matching_network in networks)
    table.add_section()
    table.add_row('[bold]Total[/bold]', f'[bold]{networks[0].network_address} - {networks[-1].broadcast_address} ({total_ip_addresses:,} IPs)[/bold]')
    raw_text = f'{action_prefix}: {", ".join(matching_network.with_prefixlen for matching_network in networks)}'
    return table, raw_text


def suggest_fix(
    client: RateLimitClient | GeoLite2Client,
    owner: str,
    network: ipaddress.IPv4Network,
    results: dict[str, dict[str, Any]],
    status: Status,
) -> tuple[RenderableType | None, str]:
    """Binary-search /24 boundaries and suggest replacement CIDRs for a mismatched range."""
    if isinstance(client, GeoLite2Client):
        _, matching_networks = scan_network_geolite2(client, owner, network)
        if matching_networks:
            return _format_networks_table('[bold magenta]Fix Suggestion[/bold magenta] (offline GeoLite2 scan)', matching_networks, 'Replace with')
        raw_text = f'No matching blocks found — consider removing {network.with_prefixlen}'
        return Text(f'[FIX SUGGESTION] {raw_text}', style='red'), raw_text

    if network.prefixlen > MAX_AUTO_FIX_PREFIX_LEN:
        status.update(f'[yellow]Range /{network.prefixlen} is smaller than /{MAX_AUTO_FIX_PREFIX_LEN} — skipping auto-fix[/yellow]')
        return None, f'Range /{network.prefixlen} is smaller than /{MAX_AUTO_FIX_PREFIX_LEN} — skipping auto-fix'

    start_block = int(network.network_address) // SUBNET_BLOCK_SIZE
    end_block = int(network.broadcast_address) // SUBNET_BLOCK_SIZE
    status.update(f'[magenta]\\[AUTO-FIX][/magenta] Scanning {end_block - start_block + 1:,} /24 blocks for ownership boundaries...')

    cache: dict[int, bool] = {}
    for ip_address in sample_ips(network):
        block_index = _ip_to_block(ip_address)
        if start_block <= block_index <= end_block:
            lookup_result = results.get(ip_address) or {}
            cache[block_index] = lookup_result.get('status') == 'success' and owner_matches(owner, lookup_result)

    _check_block_owner(client, owner, start_block, cache)
    _check_block_owner(client, owner, end_block, cache)
    initial_cache_size = len(cache)

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
                break
        if not found_unresolved:
            break

    extra_queries = len(cache) - initial_cache_size
    title_suffix = f' ([dim]{extra_queries} API queries used[/dim])' if extra_queries > 0 else ''

    sorted_blocks = sorted(cache.keys())
    good_networks: list[ipaddress.IPv4Network] = []
    i = 0
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


def _search_expansion_boundary(client: RateLimitClient | GeoLite2Client, owner: str, start_block: int, direction: int, cache: dict[int, bool]) -> int:
    """Search outward from start_block in direction (+1 or -1) to find the owner boundary."""
    step, current, last_good_block = 1, start_block, start_block
    while True:
        probe_block = max(0, min(current + step * direction, MAX_SLASH_24_BLOCK_INDEX))
        is_match = _check_block_owner(client, owner, probe_block, cache)
        if probe_block in (0, MAX_SLASH_24_BLOCK_INDEX) and not is_match:
            break
        if is_match:
            last_good_block = current = probe_block
            if probe_block in (0, MAX_SLASH_24_BLOCK_INDEX):
                break
            step *= 2
        else:
            low_block, high_block = sorted((last_good_block, probe_block))
            while high_block - low_block > 1:
                mid = (low_block + high_block) // 2
                if _check_block_owner(client, owner, mid, cache) == (direction > 0):
                    low_block = mid
                else:
                    high_block = mid
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
    if isinstance(client, RateLimitClient):
        raw_text = f'Expandable adjacent IP{pluralize(len(expandable_ip_addresses))}: {", ".join(expandable_ip_addresses)}'
        return Text(f'[EXPAND SUGGESTION] {raw_text}', style='magenta'), raw_text

    start_block = int(context.network.network_address) // SUBNET_BLOCK_SIZE
    end_block = int(context.network.broadcast_address) // SUBNET_BLOCK_SIZE
    cache: dict[int, bool] = {}
    initial_cache_size, expanded_start, expanded_end = 0, start_block, end_block

    for ip_address in expandable_ip_addresses:
        block_index = _ip_to_block(ip_address)
        cache[block_index] = True
        is_backward = block_index < start_block
        status.update(f'[magenta]\\[AUTO-EXPAND][/magenta] Searching {"backward" if is_backward else "forward"} from {_block_to_ip(block_index)}...')
        initial_cache_size = len(cache)
        boundary = _search_expansion_boundary(client, owner, block_index, -1 if is_backward else 1, cache)
        for known_network in context.owner_networks:
            if is_backward and boundary <= int(known_network.broadcast_address) // SUBNET_BLOCK_SIZE < block_index:
                boundary = int(known_network.broadcast_address) // SUBNET_BLOCK_SIZE + 1
            elif not is_backward and block_index < int(known_network.network_address) // SUBNET_BLOCK_SIZE <= boundary:
                boundary = int(known_network.network_address) // SUBNET_BLOCK_SIZE - 1
        if is_backward:
            expanded_start = min(expanded_start, boundary)
        else:
            expanded_end = max(expanded_end, boundary)

    extra_queries = len(cache) - initial_cache_size
    title_suffix = f' ([dim]{extra_queries} API queries used[/dim])' if extra_queries > 0 else ''
    first_ip = ipaddress.IPv4Address(expanded_start * SUBNET_BLOCK_SIZE)
    last_ip = ipaddress.IPv4Address((expanded_end + 1) * SUBNET_BLOCK_SIZE - 1)
    return _format_networks_table(f'[bold magenta]Expand Suggestion[/bold magenta]{title_suffix}', list(ipaddress.summarize_address_range(first_ip, last_ip)), 'Expand to')


def _get_adjacent_ips(network: ipaddress.IPv4Network) -> list[str]:
    """Get the .0 IPs of the /24 blocks immediately adjacent to the network (before and after)."""
    adjacent: list[str] = []
    if (before_ip_int := int(network.network_address) - SUBNET_BLOCK_SIZE) >= 0:
        adjacent.append(str(ipaddress.IPv4Address(before_ip_int)))
    if (after_ip_int := int(network.broadcast_address) + 1) <= MAX_IPV4_INT:
        adjacent.append(str(ipaddress.IPv4Address(after_ip_int - (after_ip_int % SUBNET_BLOCK_SIZE))))
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
    is_valid = True
    mismatch_lines: list[str] = []
    mismatches_raw: list[str] = []
    for ip_address in samples:
        lookup_result = results.get(ip_address) or {}
        if lookup_result.get('status') != 'success':
            is_valid = False
            continue
        if not owner_matches(owner, lookup_result):
            owner_info = f'{lookup_result.get("isp")} / {lookup_result.get("org")}'
            mismatch_lines.append(f'[red]✗[/red] [magenta]{ip_address}[/magenta] → {owner_info}')
            mismatches_raw.append(f'✗ {cidr_range} ({ip_address}) → {owner_info}')
            is_valid = False
    return is_valid, mismatch_lines, mismatches_raw


def _evaluate_expansion_boundary(
    network: ipaddress.IPv4Network, adjacent_ip_addresses: list[str], owner: str, owner_networks: list[ipaddress.IPv4Network], results: dict[str, dict[str, Any]],
) -> tuple[bool, list[str], str, str, list[str], list[str]]:
    """Evaluate adjacent IP addresses for backward and forward expansion."""
    start_ip_int = int(network.network_address)
    expansion_found = False
    expandable_ip_addresses: list[str] = []
    statuses = {'BACKWARD': '[green]✓ Clear[/green]', 'FORWARD': '[green]✓ Clear[/green]'}
    details: dict[str, list[str]] = {'BACKWARD': [], 'FORWARD': []}

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
    fallback_client: RateLimitClient | None = None,
) -> bool:
    """Check the validity of the CIDR range and look for potential expansion."""
    file_path, line_number = location or ('', None)
    network = ipaddress.ip_network(cidr_range)
    if not isinstance(network, ipaddress.IPv4Network):
        message = f'Only IPv4 networks are supported: {cidr_range}'
        raise TypeError(message)

    progress_prefix = f'[cyan][{int((current_index / total_count) * 100)}%][/cyan] ' if total_count > 0 and current_index > 0 else ''
    status_message = (
        f'{progress_prefix}[bold cyan]Scanning [/bold cyan][bold white]{owner}[/bold white] '
        f'[bold cyan]([/bold cyan][bold magenta]{network.with_prefixlen}[/bold magenta][bold cyan])...[/bold cyan]'
    )
    with console.status(status_message) as status:
        base_samples = sample_ips(network)
        adjacent_ip_addresses = _get_adjacent_ips(network)
        all_ip_addresses = list(dict.fromkeys(base_samples + adjacent_ip_addresses))
        results = lookup_ips_batch(client, all_ip_addresses)

        is_valid = True
        has_mismatches = False
        mismatch_lines: list[str] = []
        mismatches_raw: list[str] = []
        active_client = client

        if isinstance(client, GeoLite2Client):
            mismatches, matching_networks = scan_network_geolite2(client, owner, network)
            if mismatches:
                is_valid = False
                has_mismatches = True
                for start_ip, end_ip, actual_owner in mismatches:
                    ip_range_str = str(start_ip) if start_ip == end_ip else f'{start_ip} - {end_ip}'
                    mismatch_lines.append(f'[red]✗[/red] [magenta]{ip_range_str}[/magenta] → {actual_owner}')
                    mismatches_raw.append(f'✗ {cidr_range} ({ip_range_str}) → {actual_owner}')
            elif not matching_networks and fallback_client:
                if owner not in IP_API_SKIPPED_OWNERS and network.prefixlen > MAX_IP_API_SUBNET_PREFIX:
                    status.update(
                        f'{progress_prefix}[bold cyan]Scanning [/bold cyan][bold white]{owner}[/bold white] '
                        f'[bold cyan]([/bold cyan][bold magenta]{network.with_prefixlen}[/bold magenta]'
                        f'[bold cyan])... [yellow]Fallback to IP-API[/yellow][/bold cyan]'
                    )
                    fallback_results = lookup_ips_batch(fallback_client, all_ip_addresses)
                    results.update(fallback_results)
                    active_client = fallback_client
                    sample_valid, lines, raw = _collect_sample_mismatches(base_samples, fallback_results, owner, cidr_range)
                    if not sample_valid:
                        is_valid = False
                        has_mismatches = True
                        mismatch_lines.extend(lines)
                        mismatches_raw.extend(raw)
        else:
            sample_valid, lines, raw = _collect_sample_mismatches(base_samples, results, owner, cidr_range)
            if not sample_valid:
                is_valid = False
                has_mismatches = True
                mismatch_lines.extend(lines)
                mismatches_raw.extend(raw)

        expansion_found, expandable_ips, backward_status, forward_status, backward_details, forward_details = _evaluate_expansion_boundary(
            network, adjacent_ip_addresses, owner, owner_networks, results,
        )

    renderables: list[RenderableType] = [Panel(render_samples(all_ip_addresses), title='[cyan]Sampled IPs[/cyan]', border_style='cyan', box=box.ROUNDED), Text('')]

    validation_table = Table.grid(padding=(0, 4))
    validation_table.add_column(style='cyan', justify='left')
    validation_table.add_column(justify='left')
    validation_table.add_row('Base Check', '[red]✗ Mismatches Found[/red]' if has_mismatches else '[green]✓ Pass[/green]')
    validation_table.add_row('Backward Expansion', backward_status)
    validation_table.add_row('Forward Expansion', forward_status)

    details_table = Table.grid(padding=(0, 4), expand=True)
    for _ in range(4):
        details_table.add_column()

    backward_text = '\n'.join(backward_details) if backward_details else 'N/A'
    forward_text = '\n'.join(forward_details) if forward_details else 'N/A'
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
        fix_renderable, fix_raw = suggest_fix(active_client, owner, network, results, status)
        if fix_renderable is not None:
            renderables.append(fix_renderable)

    expansion_raw = ''
    if expansion_found:
        expansion_renderable, expansion_raw = suggest_expansion(active_client, owner, RangeContext(network, owner_networks), expandable_ips, status)
        if expansion_renderable is not None:
            renderables.extend([Text(''), Rule('[bold white]Expansion Available[/bold white]'), expansion_renderable])

    clean_path = os.path.relpath(file_path).replace('\\', '/') if file_path else ''
    if has_mismatches and detections is not None:
        for mismatch in mismatches_raw:
            detections.append(f'{clean_path}:{line_number}: ({owner}) {mismatch} | [FIX SUGGESTION] {fix_raw}')
    if expansion_found and detections is not None:
        detections.append(f'{clean_path}:{line_number}: ({owner}) [EXPANSION] {cidr_range} is expandable | [EXPAND SUGGESTION] {expansion_raw}')

    if not only_detections or not is_valid or expansion_found:
        title = (
            f'[bold white]{owner}[/bold white]  •  [bold magenta]{network.with_prefixlen}[/bold magenta]  •  '
            f'[dim]{network.network_address} → {network.broadcast_address}[/dim]  •  '
            f'[bold white]{network.num_addresses:,} IPs[/bold white]'
        )
        if file_path and line_number is not None:
            title += f'  •  [blue]{clean_path}:{line_number}[/blue]'
        console.print()
        console.print(Panel(Group(*renderables), title=title, border_style='cyan', box=box.ROUNDED))

    return is_valid


def run_preflight_checks(
    ranges: list[tuple[str, str, int]], networks_by_owner: dict[str, list[ipaddress.IPv4Network]], *, ranges_file: str = '',
) -> None:
    """Run all pre-flight checks and display them in a neat panel."""
    table = Table(show_header=False, expand=True, box=None, padding=(0, 2))
    table.add_column(style='cyan', justify='left', ratio=1)
    table.add_column(justify='left', ratio=3)

    unsorted_owners = [owner for owner, networks in networks_by_owner.items() if networks != sorted(networks)]
    sort_text = (
        f'[yellow]⚠ {len(unsorted_owners)} owners have unsorted ranges ({", ".join(unsorted_owners)})[/yellow]'
        if unsorted_owners
        else '[green]✓ All ranges correctly sorted[/green]'
    )
    table.add_row('CIDR Sorting', sort_text)

    all_networks = [(owner, network) for owner, networks in networks_by_owner.items() for network in networks]
    overlaps = [
        f'[dim]• {network_1} ({owner_1}) falls within {network_2} ({owner_2})[/dim]'
        for i, (owner_1, network_1) in enumerate(all_networks)
        for j, (owner_2, network_2) in enumerate(all_networks)
        if i != j and network_1.subnet_of(network_2) and 'BattlEye' not in (owner_1, owner_2)
    ]
    overlap_text = f'[yellow]⚠ {len(overlaps)} overlaps detected![/yellow]\n' + '\n'.join(overlaps) if overlaps else '[green]✓ No overlapping CIDRs found[/green]'
    table.add_row('Overlapping CIDRs', overlap_text)

    collapses: list[str] = []
    collapse_suggestions: list[str] = []
    clean_relative_path = os.path.relpath(ranges_file).replace('\\', '/') if ranges_file else ''

    for owner, networks in networks_by_owner.items():
        collapsed = list(ipaddress.collapse_addresses(networks))
        if len(collapsed) < len(networks):
            collapses.append(f'[dim]• {owner}: {len(networks)} ranges → {len(collapsed)}[/dim]')
            owner_line_numbers = [line for name, _, line in ranges if name == owner]
            link_str = f'  •  [blue]{clean_relative_path}:{min(owner_line_numbers)}[/blue]' if (owner_line_numbers and clean_relative_path) else ''
            to_delete = [f"    '{network.with_prefixlen}'," for network in networks if network not in collapsed]
            to_add = [f"    '{network.with_prefixlen}'," for network in collapsed if network not in networks]
            lines = [f'[bold white]{owner}[/bold white] ({len(networks)} ranges → {len(collapsed)}){link_str}']
            if to_delete:
                lines.extend(['  [red]❌ Delete these ranges:[/red]', *to_delete])
            if to_add:
                lines.extend(['  [green]➕ Add these ranges instead:[/green]', *to_add])
            collapse_suggestions.append('\n'.join(lines))

    collapse_text = f'[yellow]⚠ {len(collapses)} collapsible blocks found![/yellow]\n' + '\n'.join(collapses) if collapses else '[green]✓ No collapsible ranges found[/green]'
    table.add_row('Collapsible CIDRs', collapse_text)

    renderables: list[Any] = [table]
    if collapse_suggestions:
        renderables.extend([
            Text(''), Rule('[bold yellow]CIDR Collapse Suggestions[/bold yellow]'),
            Text.from_markup('[yellow]💡 Edit the ranges for the owner in your code by deleting and adding the subnets below:[/yellow]'),
            Text(''), Text.from_markup('\n\n'.join(collapse_suggestions)),
        ])

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
        MofNCompleteColumn(), TextColumn('[dim]•[/dim]'), TimeElapsedColumn(), TextColumn('[dim]•[/dim]'),
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
    parser.add_argument('--export', help='Export one-line detections to the specified text file.')
    parsed_arguments = parser.parse_args([arg for arg in sys.argv if arg][1:])

    raw_ranges = extract_ranges(str(parsed_arguments.ranges_file))
    parsed_ranges: list[tuple[str, str, ipaddress.IPv4Network, int]] = []
    networks_by_owner: dict[str, list[ipaddress.IPv4Network]] = {}
    for owner, cidr_range, line_number in raw_ranges:
        with contextlib.suppress(ValueError, TypeError):
            network = ipaddress.ip_network(cidr_range)
            if isinstance(network, ipaddress.IPv4Network):
                parsed_ranges.append((owner, cidr_range, network, line_number))
                networks_by_owner.setdefault(owner, []).append(network)

    console.rule('[bold cyan]Session Sniffer - Range Verification Engine[/bold cyan]')
    console.print(f'  [cyan]Loaded [bold white]{len(raw_ranges)}[/bold white] ranges for processing.[/cyan]')
    run_preflight_checks(raw_ranges, networks_by_owner, ranges_file=str(parsed_arguments.ranges_file))

    fallback_client: RateLimitClient | None = None
    if parsed_arguments.geolite2:
        database_path = get_app_dir(scope='local') / 'GeoLite2 Databases' / 'GeoLite2-ASN.mmdb'
        if not database_path.exists():
            console.print(
                f'[red]Error: GeoLite2-ASN database not found at {database_path.absolute()}[/red]\n'
                '[yellow]Please download it or launch the main app first to download it automatically.[/yellow]'
            )
            sys.exit(1)
        client: GeoLite2Client | RateLimitClient = GeoLite2Client(database_path)
        if parsed_arguments.ip_api_fallback:
            fallback_client = RateLimitClient(_ip_api_session)
    else:
        client = RateLimitClient(_ip_api_session)

    ip_to_owners: dict[str, set[str]] = {}
    for owner, cidr_range, network, _ in parsed_ranges:
        if not should_skip(owner, cidr_range, use_geolite2=parsed_arguments.geolite2):
            for ip_address in sample_ips(network) + _get_adjacent_ips(network):
                ip_to_owners.setdefault(ip_address, set()).add(owner)

    if ip_to_owners:
        ips_list = list(ip_to_owners.keys())
        prefetch_progress = _create_progress(f'Pre-fetching {len(ips_list):,} IPs{" (offline)" if parsed_arguments.geolite2 else ""}')
        with prefetch_progress:
            prefetch_task = prefetch_progress.add_task('', total=(len(ips_list) + API_BATCH_LIMIT - 1) // API_BATCH_LIMIT)
            if not parsed_arguments.geolite2 and isinstance(client, RateLimitClient):
                client.sleep_callback = _make_sleep_callback(prefetch_progress, prefetch_task, prefix='[yellow]RATE[/yellow]')
            for i, batch in enumerate(chunked(ips_list, API_BATCH_LIMIT), 1):
                batch_owners = sorted({owner for ip in batch for owner in ip_to_owners[ip]})
                extra_owners_count = len(batch_owners) - MAX_DISPLAYED_OWNERS
                extra_owners_text = f' and {extra_owners_count} more' if extra_owners_count > 0 else ''
                owners_str = f'{", ".join(batch_owners[:MAX_DISPLAYED_OWNERS])}{extra_owners_text}'
                prefetch_progress.update(prefetch_task, completed=i, description=f'[white]{owners_str}[/white]')
                lookup_ips_batch(client, batch)
            if not parsed_arguments.geolite2 and isinstance(client, RateLimitClient):
                client.sleep_callback = None

    if not parsed_arguments.only_detections:
        console.print()

    total_count = sum(1 for owner, cidr_range, _, _ in parsed_ranges if not should_skip(owner, cidr_range, use_geolite2=parsed_arguments.geolite2))
    detections: list[str] = []
    current_index = 0
    progress = _create_progress('Verifying')

    with progress:
        task_id = progress.add_task('', total=total_count)
        verification_callback = _make_sleep_callback(progress, task_id)
        if isinstance(client, RateLimitClient):
            client.sleep_callback = verification_callback
        if fallback_client:
            fallback_client.sleep_callback = verification_callback

        for owner, cidr_range, _, line_number in parsed_ranges:
            if should_skip(owner, cidr_range, use_geolite2=parsed_arguments.geolite2):
                if not parsed_arguments.only_detections:
                    clean_path = os.path.relpath(str(parsed_arguments.ranges_file)).replace('\\', '/')
                    link = f'  •  [blue]{clean_path}:{line_number}[/blue]' if clean_path else ''
                    console.print(f'[dim]ℹ Skipping Range Verification for {owner} CIDR:[/dim] [magenta dim]{cidr_range}[/magenta dim]{link}')
                continue

            current_index += 1
            progress.update(task_id, completed=current_index, description=f'[white]{owner}[/white] [magenta]{cidr_range}[/magenta]')
            check_range(
                client, owner, cidr_range, networks_by_owner.get(owner, []),
                location=(str(parsed_arguments.ranges_file), line_number),
                only_detections=parsed_arguments.only_detections,
                current_index=current_index, total_count=total_count,
                detections=detections, fallback_client=fallback_client,
            )
            if total_count > 0:
                time.sleep(min(0.005, 1.0 / total_count))

    if isinstance(client, RateLimitClient):
        client.sleep_callback = None
    if fallback_client:
        fallback_client.sleep_callback = None

    if not parsed_arguments.only_detections:
        console.print()
    console.rule('[bold green]✓ Range Verification Complete[/bold green]')
    skipped_count = len(raw_ranges) - total_count
    time_str = format_duration(time.time() - start_time)
    console.print(f'  [green]✓ Successfully verified [bold]{total_count}[/bold] ranges in [bold]{time_str}[/bold].[/green]')
    if skipped_count > 0:
        console.print(f'  [dim]ℹ Skipped [bold]{skipped_count}[/bold] ranges (ignored owners / huge ranges).[/dim]')

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
