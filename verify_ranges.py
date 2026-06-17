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

console = Console()

if TYPE_CHECKING:
    from collections.abc import Generator, Mapping

    from rich.console import RenderableType
    from rich.status import Status

IP_API_BATCH_URL = 'http://ip-api.com/batch'
THROTTLING_RL_THRESHOLD = 3
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
    last_rl: int | None
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
        self.last_rl = None
        self.capacity = 45
        self.window = 60
        self.tokens = 45
        self.last_refill = time.time()

    def _refill(self) -> None:
        """Refill the token bucket based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill

        if elapsed >= self.window:
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
        rl_str = headers.get('X-Rl')
        ttl_str = headers.get('X-Ttl')

        rl: int | None = None
        if rl_str is not None:
            with contextlib.suppress(ValueError):
                rl = int(rl_str)

        ttl: int | None = None
        if ttl_str is not None:
            with contextlib.suppress(ValueError):
                ttl = int(ttl_str)

        self.last_rl = rl

        if rl is not None and rl == 0:  # pylint: disable=use-implicit-booleaness-not-comparison-to-zero
            wait = (ttl + 1) if ttl else 60
            console.print(f'[yellow]\\[RATE] exhausted[/yellow] → [yellow]sleeping {wait}s[/yellow]')
            time.sleep(wait)

        elif rl is not None and rl <= THROTTLING_RL_THRESHOLD:
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
                    ttl_str = response.headers.get('X-Ttl')

                    try:
                        ttl = int(ttl_str) if ttl_str else 60
                    except ValueError:
                        ttl = 60

                    # always use fresh TTL, minimum 1s
                    wait = max(ttl + 1, 1)

                    # track cooldown deadline
                    self.cooldown_until = time.time() + wait

                    console.print(f'[yellow]\\[429] cooldown[/yellow] → [yellow]sleeping {wait}s[/yellow]')

                    time.sleep(wait)
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
            res = {
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
                org = record.autonomous_system_organization or ''
                asn = f'AS{record.autonomous_system_number}' if record.autonomous_system_number else ''
                res.update({
                    'status': 'success',
                    'message': '',
                    'isp': org,
                    'org': org,
                    'as': asn,
                    'asname': org,
                })
            except geoip2.errors.AddressNotFoundError:
                pass
            except Exception as e:  # pylint: disable=broad-exception-caught  # noqa: BLE001
                res['message'] = str(e)
            results.append(res)
        return results

    def close(self) -> None:
        """Close the database reader."""
        self.reader.close()


def create_session() -> requests.Session:
    """Create a configured requests Session."""
    s = requests.Session()
    s.headers.update({'User-Agent': 'Range Verifier'})
    return s


def lookup_ips_batch(client: RateLimitClient | GeoLite2Client, ips: list[str]) -> dict[str, dict[str, Any]]:
    """Look up details for a batch of IP addresses, chunking to respect API limits."""
    results: dict[str, dict[str, Any]] = {}

    for batch in chunked(ips, API_BATCH_LIMIT):
        payload: list[dict[str, Any]] = [{'query': ip, 'fields': 'status,message,query,isp,org,as,asname'} for ip in batch]
        res = client.post_batch(payload)
        results.update({cast('str', r.get('query')): r for r in res})

    return results


def extract_ranges(file_path: str) -> list[tuple[str, str, int]]:
    """Extract NamedRange definitions from a python source file using AST."""
    with Path(file_path).open(encoding='utf-8') as f:
        tree = ast.parse(f.read())
    out: list[tuple[str, str, int]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'NamedRange' and len(node.args) == EXPECTED_ARGS_COUNT:
            a, b = node.args
            if isinstance(a, ast.Constant) and isinstance(a.value, str) and isinstance(b, ast.Constant) and isinstance(b.value, str):
                out.append((a.value, b.value, node.lineno))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'create_ranges' and len(node.args) >= EXPECTED_ARGS_COUNT:
            owner_node = node.args[0]
            if isinstance(owner_node, ast.Constant) and isinstance(owner_node.value, str):
                owner = owner_node.value
                for arg in node.args[1:]:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        lineno = getattr(arg, 'lineno', None) or node.lineno
                        out.append((owner, arg.value, lineno))

    return out


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


def normalize(t: str) -> str:
    """Normalize text by converting to lowercase and replacing punctuation with spaces."""
    return t.lower().replace(',', ' ').replace('(', ' ').replace(')', ' ').replace('-', ' ')


# Custom exception list: Map an expected owner to a list of exact ISP/Org strings that
# trigger false positive matches (e.g., 'DXC' matching 'Microsoft' due to the word 'Corporation').
# These will be explicitly treated as different/unrelated ISPs.
KNOWN_FALSE_POSITIVES: dict[str, list[str]] = {
    'Microsoft Corporation': [
        'dxc us latin america corporation',
        'digital highway corporation',
        'shanghai blue cloud technology',
    ],
    'Demonware Limited': [
        'orbit telekom sanayi',
        'datacamp limited',
    ],
    'Take-Two Interactive Software, Inc.': [
        'frontier communications of america',
    ],
}

# Custom aliases list: Map an expected owner to a list of exact ISP/Org strings that
# SHOULD be considered a match (e.g., 'DoD Network Information Center' for 'US Department of Defense').
KNOWN_ALIASES: dict[str, list[str]] = {
    'US Department of Defense': [
        'dod network information center',
    ],
    'The Constant Company, LLC': [
        'vultr holdings',
        'choopa',
    ],
    'OVH SAS': [
        'ovh sas',
        'ovh',
    ],
    'Discord': [
        'i3d.net',
    ],
}


def owner_matches(expected: str, data: dict[str, Any]) -> bool:
    """Check if the expected owner matches the IP API response data."""
    actual = normalize(f"{data.get('isp', '')} {data.get('org', '')} {data.get('asname', '')}")

    # Check custom exception list first
    for false_positive in KNOWN_FALSE_POSITIVES.get(expected, []):
        if normalize(false_positive) in actual:
            return False

    # Check custom alias list next
    for alias in KNOWN_ALIASES.get(expected, []):
        if normalize(alias) in actual:
            return True

    words = {word for word in normalize(expected).split() if len(word) >= MIN_WORD_LENGTH}
    return any(word in actual for word in words)


def chunked(lst: list[Any], n: int) -> Generator[list[Any]]:
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def _block_to_ip(block_idx: int) -> str:
    """Convert a /24 block index to its .0 IP address string."""
    return str(ipaddress.IPv4Address(block_idx * SUBNET_BLOCK_SIZE))


def _ip_to_block(ip_str: str) -> int:
    """Convert an IP address string to its /24 block index."""
    return int(ipaddress.IPv4Address(ip_str)) // SUBNET_BLOCK_SIZE


def _check_block_owner(
    client: RateLimitClient | GeoLite2Client,
    owner: str,
    block_idx: int,
    cache: dict[int, bool],
) -> bool:
    """Check if a /24 block's .0 IP belongs to the expected owner. Results are cached."""
    if block_idx in cache:
        return cache[block_idx]

    ip = _block_to_ip(block_idx)
    results = lookup_ips_batch(client, [ip])
    res = results.get(ip) or {}

    is_match = res.get('status') == 'success' and owner_matches(owner, res)
    cache[block_idx] = is_match
    return is_match


def _binary_search_transition(
    client: RateLimitClient | GeoLite2Client,
    owner: str,
    lo: int,
    hi: int,
    cache: dict[int, bool],
) -> None:
    """Binary search between two /24 block indices with different owner classifications.

    Populates cache entries to pinpoint the exact transition boundary.
    Precondition: cache[lo] != cache[hi] and hi > lo.
    """
    while hi - lo > 1:
        mid = (lo + hi) // 2
        _check_block_owner(client, owner, mid, cache)

        if cache[mid] == cache[lo]:
            lo = mid
        else:
            hi = mid


def scan_network_geolite2(
    client: GeoLite2Client,
    owner: str,
    net: ipaddress.IPv4Network,
) -> tuple[list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address, str]], list[ipaddress.IPv4Network]]:
    """Scan the entire IPv4 network block using GeoLite2 mmdb, returning mismatches and matching subnets."""
    import geoip2.errors  # pylint: disable=import-outside-toplevel  # noqa: PLC0415
    current_ip = net.network_address
    end_ip = net.broadcast_address

    mismatches: list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address, str]] = []
    matching_ranges: list[ipaddress.IPv4Network] = []

    while current_ip <= end_ip:
        try:
            record = client.reader.asn(str(current_ip))
            org = record.autonomous_system_organization or ''
            db_net = record.network

            # Check if this database network is an IPv4Network
            if not isinstance(db_net, ipaddress.IPv4Network):
                db_net = ipaddress.IPv4Network(f'{current_ip}/24', strict=False)

            data = {'isp': org, 'org': org, 'asname': org}
            if not org:
                # Not Found/empty organization - treat as matching (or neutral)
                overlap_start = max(current_ip, db_net.network_address)
                overlap_end = min(end_ip, db_net.broadcast_address)
                matching_ranges.extend(ipaddress.summarize_address_range(overlap_start, overlap_end))
            elif owner_matches(owner, data):
                overlap_start = max(current_ip, db_net.network_address)
                overlap_end = min(end_ip, db_net.broadcast_address)
                matching_ranges.extend(ipaddress.summarize_address_range(overlap_start, overlap_end))
            else:
                overlap_start = max(current_ip, db_net.network_address)
                overlap_end = min(end_ip, db_net.broadcast_address)
                mismatches.append((overlap_start, overlap_end, org))

            if db_net.broadcast_address >= end_ip:
                break
            current_ip = db_net.broadcast_address + 1

        except geoip2.errors.AddressNotFoundError:
            # Step by /24 aligned block for addresses not found in the DB
            current_ip_int = int(current_ip)
            next_24_aligned = ((current_ip_int // 256) + 1) * 256
            db_net = ipaddress.IPv4Network(f'{current_ip}/24', strict=False)

            overlap_start = max(current_ip, db_net.network_address)
            overlap_end = min(end_ip, db_net.broadcast_address)
            # Treat Not Found as matching/neutral to avoid noise
            matching_ranges.extend(ipaddress.summarize_address_range(overlap_start, overlap_end))

            if db_net.broadcast_address >= end_ip:
                break
            current_ip = ipaddress.IPv4Address(next_24_aligned)
        except Exception as e:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            # Other errors
            mismatches.append((current_ip, current_ip, f'Error: {e}'))
            current_ip += 1

    return mismatches, list(ipaddress.collapse_addresses(matching_ranges))


def suggest_fix(
    client: RateLimitClient | GeoLite2Client,
    owner: str,
    net: ipaddress.IPv4Network,
    results: dict[str, dict[str, Any]],
    status: Status,
) -> RenderableType | None:
    """Binary-search /24 boundaries and suggest replacement CIDRs for a mismatched range."""
    base_samples = sample_ips(net)
    if isinstance(client, GeoLite2Client):
        # Instant precise suggestion
        _, matching_networks = scan_network_geolite2(client, owner, net)
        if matching_networks:
            table = Table(title='[bold magenta]Fix Suggestion[/bold magenta] (offline GeoLite2 scan)', box=box.ROUNDED, expand=False)
            table.add_column('Replacement Range', style='green')
            table.add_column('IP Coverage', style='cyan')

            for network in matching_networks:
                table.add_row(f"NamedRange('{owner}', '{network.with_prefixlen}'),", f'({network.network_address} - {network.broadcast_address})')

            total_first = matching_networks[0].network_address
            total_last = matching_networks[-1].broadcast_address
            total_ips = sum(n.num_addresses for n in matching_networks)

            table.add_section()
            table.add_row('[bold]Total[/bold]', f'[bold]{total_first} - {total_last} ({total_ips:,} IPs)[/bold]')
            return table
        return Text(f'[FIX SUGGESTION] No matching blocks found — consider removing {net.with_prefixlen}', style='red')

    if net.prefixlen > 24:  # noqa: PLR2004
        status.update(f'[yellow]Range /{net.prefixlen} is smaller than /24 — skipping auto-fix[/yellow]')
        return None

    start_block = int(net.network_address) // SUBNET_BLOCK_SIZE
    end_block = int(net.broadcast_address) // SUBNET_BLOCK_SIZE
    total_blocks = end_block - start_block + 1

    status.update(f'[magenta]\\[AUTO-FIX][/magenta] Scanning {total_blocks:,} /24 blocks for ownership boundaries...')

    # Seed cache from existing sample results
    cache: dict[int, bool] = {}
    for ip in base_samples:
        block_idx = _ip_to_block(ip)
        if start_block <= block_idx <= end_block:
            res = results.get(ip) or {}
            cache[block_idx] = res.get('status') == 'success' and owner_matches(owner, res)

    # Ensure range boundaries are classified
    _check_block_owner(client, owner, start_block, cache)
    _check_block_owner(client, owner, end_block, cache)

    initial_cache_size = len(cache)

    # Iteratively binary-search all unresolved transitions
    while True:
        sorted_blocks = sorted(cache.keys())
        found_unresolved = False

        for i in range(len(sorted_blocks) - 1):
            b1, b2 = sorted_blocks[i], sorted_blocks[i + 1]
            if cache[b1] != cache[b2] and b2 - b1 > 1:
                steps = (b2 - b1).bit_length()
                status.update(f'[white]binary search[/white] {_block_to_ip(b1)} .. {_block_to_ip(b2)} (~{steps} queries)')
                _binary_search_transition(client, owner, b1, b2, cache)
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
        run_start = sorted_blocks[i]
        j = i
        while j < len(sorted_blocks) - 1 and cache[sorted_blocks[j + 1]]:
            j += 1
        run_end = sorted_blocks[j]

        # Clip to the original network boundaries
        actual_start = max(run_start, start_block)
        actual_end = min(run_end, end_block)

        first_ip = ipaddress.IPv4Address(actual_start * SUBNET_BLOCK_SIZE)
        last_ip = ipaddress.IPv4Address((actual_end + 1) * SUBNET_BLOCK_SIZE - 1)

        good_networks.extend(ipaddress.summarize_address_range(first_ip, last_ip))

        i = j + 1

    # Print suggestion
    if good_networks:
        table = Table(title=f'[bold magenta]Fix Suggestion[/bold magenta]{title_suffix}', box=box.ROUNDED, expand=False)
        table.add_column('Replacement Range', style='green')
        table.add_column('IP Coverage', style='cyan')

        for network in good_networks:
            table.add_row(f"NamedRange('{owner}', '{network.with_prefixlen}'),", f'({network.network_address} - {network.broadcast_address})')

        total_first = good_networks[0].network_address
        total_last = good_networks[-1].broadcast_address
        total_ips = sum(n.num_addresses for n in good_networks)

        table.add_section()
        table.add_row('[bold]Total[/bold]', f'[bold]{total_first} - {total_last} ({total_ips:,} IPs)[/bold]')
        return table
    return Text(f'[FIX SUGGESTION] No matching blocks found — consider removing {net.with_prefixlen}', style='red')


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
    last_good = start_block

    while True:
        probe = current + step * direction

        # Don't go out of IPv4 range
        if probe < 0 or probe > 0xFFFFFF:  # noqa: PLR2004  # max /24 block index
            probe = max(0, min(probe, 0xFFFFFF))
            is_match = _check_block_owner(client, owner, probe, cache)
            if is_match:
                last_good = probe
            break

        is_match = _check_block_owner(client, owner, probe, cache)

        if is_match:
            last_good = probe
            current = probe
            step *= 2  # exponential growth
        else:
            # Found the first non-matching block; binary search between last_good and probe
            lo = last_good
            hi = probe
            if lo > hi:
                lo, hi = hi, lo

            while hi - lo > 1:
                mid = (lo + hi) // 2
                mid_match = _check_block_owner(client, owner, mid, cache)

                if direction > 0:
                    # Searching forward: good blocks are on the lo side
                    if mid_match:
                        lo = mid
                    else:
                        hi = mid
                # Searching backward: good blocks are on the hi side
                elif mid_match:
                    hi = mid
                else:
                    lo = mid

            last_good = lo if direction > 0 else hi
            break

    return last_good


@dataclass(slots=True)
class RangeContext:
    """Context information for a CIDR range being verified."""

    net: ipaddress.IPv4Network
    owner_networks: list[ipaddress.IPv4Network]


def suggest_expansion(
    client: RateLimitClient | GeoLite2Client,
    owner: str,
    ctx: RangeContext,
    expandable_ips: list[str],
    status: Status,
) -> RenderableType | None:
    """Binary-search outward from expandable adjacent blocks to find the full owner boundary."""
    start_block = int(ctx.net.network_address) // SUBNET_BLOCK_SIZE
    end_block = int(ctx.net.broadcast_address) // SUBNET_BLOCK_SIZE

    cache: dict[int, bool] = {}
    initial_cache_size = 0

    # Classify expandable IPs by direction
    expanded_start = start_block
    expanded_end = end_block

    for ip in expandable_ips:
        block_idx = _ip_to_block(ip)
        cache[block_idx] = True  # already confirmed as same owner

        if block_idx < start_block:
            # Expansion goes backward
            status.update(f'[magenta]\\[AUTO-EXPAND][/magenta] Searching backward from {_block_to_ip(block_idx)}...')
            initial_cache_size = len(cache)
            boundary = _search_expansion_boundary(client, owner, block_idx, -1, cache)

            # Don't expand into already-covered ranges
            for known_net in ctx.owner_networks:
                known_end = int(known_net.broadcast_address) // SUBNET_BLOCK_SIZE
                if boundary <= known_end < block_idx:
                    boundary = known_end + 1

            expanded_start = min(expanded_start, boundary)

        elif block_idx > end_block:
            # Expansion goes forward
            status.update(f'[magenta]\\[AUTO-EXPAND][/magenta] Searching forward from {_block_to_ip(block_idx)}...')
            initial_cache_size = len(cache)
            boundary = _search_expansion_boundary(client, owner, block_idx, +1, cache)

            # Don't expand into already-covered ranges
            for known_net in ctx.owner_networks:
                known_start = int(known_net.network_address) // SUBNET_BLOCK_SIZE
                if block_idx < known_start <= boundary:
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

    for network in expanded_networks:
        table.add_row(f"NamedRange('{owner}', '{network.with_prefixlen}'),", f'({network.network_address} - {network.broadcast_address})')

    total_first = expanded_networks[0].network_address
    total_last = expanded_networks[-1].broadcast_address
    total_ips = sum(n.num_addresses for n in expanded_networks)

    table.add_section()
    table.add_row('[bold]Total[/bold]', f'[bold]{total_first} - {total_last} ({total_ips:,} IPs)[/bold]')
    return table


def check_expansion(client: RateLimitClient | GeoLite2Client, owner: str, cidr: str) -> None:
    """Check if the IP range can be expanded to a larger subnet."""
    net = ipaddress.ip_network(cidr)
    if not isinstance(net, ipaddress.IPv4Network):
        msg = f'Only IPv4 networks are supported: {cidr}'
        raise TypeError(msg)

    console.print(f'\n  [cyan]\\[EXP CHECK][/cyan] {cidr}')

    # only 2 candidates: one up, one down
    candidates: list[ipaddress.IPv4Network] = []

    try:
        if net.prefixlen > 0:
            supernet = net.supernet(prefixlen_diff=1)
            candidates.append(supernet)
    except ValueError:
        pass

    for cand in candidates:
        samples = sample_ips(cand)

        console.print(f'    testing: {cand.with_prefixlen}')

        try:
            results = lookup_ips_batch(client, samples[:20])

            if all(owner_matches(owner, results.get(ip) or {}) and (results.get(ip) or {}).get('status') == 'success' for ip in samples[:20]):
                console.print(f'    [magenta]\\[EXPANSION POSSIBLE][/magenta] → {cand.with_prefixlen}')
            else:
                console.print('    [green]\\[NO EXPANSION][/green]')

        except Exception as e:  # noqa: BLE001  # pylint: disable=broad-exception-caught
            console.print(f'    [red]\\[ERROR][/red] {e}')


def _get_adjacent_ips(net: ipaddress.IPv4Network) -> list[str]:
    """Get the .0 IPs of the /24 blocks immediately adjacent to the network (before and after)."""
    adjacent: list[str] = []

    # block immediately before the range
    before_int = int(net.network_address) - SUBNET_BLOCK_SIZE
    if before_int >= 0:
        adjacent.append(str(ipaddress.IPv4Address(before_int)))

    # block immediately after the range
    after_int = int(net.broadcast_address) + 1
    if after_int <= 0xFFFFFFFF:  # noqa: PLR2004
        # align to /24 boundary
        after_aligned = after_int - (after_int % SUBNET_BLOCK_SIZE)
        adjacent.append(str(ipaddress.IPv4Address(after_aligned)))

    return adjacent


def render_samples(samples: list[str]) -> Columns:
    """Render a grid-aligned column view of the representative sample IP addresses."""
    displayed = samples[:16]
    remaining = len(samples) - 16

    texts = [Text(ip, style='magenta') for ip in displayed]
    if remaining > 0:
        texts.append(Text(f'... (+{remaining} more)', style='dim magenta'))

    return Columns(texts, equal=True, expand=True)


def check_range(
    client: RateLimitClient | GeoLite2Client,
    owner: str,
    cidr: str,
    owner_networks: list[ipaddress.IPv4Network],
    location: tuple[str, int | None] | None = None,
) -> bool:
    """Check the validity of the CIDR range and look for potential expansion."""
    file_path, lineno = location or ('', None)
    net = ipaddress.ip_network(cidr)
    if not isinstance(net, ipaddress.IPv4Network):
        msg = f'Only IPv4 networks are supported: {cidr}'
        raise TypeError(msg)

    # Use console.status to show progress while not polluting the screen
    with console.status(f'[bold cyan]Scanning [/bold cyan][bold magenta]{net.with_prefixlen}[/bold magenta][bold cyan]...[/bold cyan]') as status:
        # -----------------------------
        # BUILD ONE SINGLE REQUEST SET
        # -----------------------------
        base_samples = sample_ips(net)
        adjacent_ips = _get_adjacent_ips(net)
        all_ips = list(dict.fromkeys(base_samples + adjacent_ips))

        results = lookup_ips_batch(client, all_ips)

        # -----------------------------
        # VALIDATION LOGIC
        # -----------------------------
        ok = True

        # Base Check
        has_mismatches = False
        mismatch_lines: list[str] = []

        if isinstance(client, GeoLite2Client):
            # Thorough 100% offline GeoLite2 validation using tree-jumping
            mismatches, _ = scan_network_geolite2(client, owner, net)
            if mismatches:
                ok = False
                has_mismatches = True
                for start_ip, end_ip, actual_owner in mismatches:
                    if start_ip == end_ip:
                        mismatch_lines.append(f'[red]✗[/red] [magenta]{start_ip}[/magenta] → {actual_owner}')
                    else:
                        mismatch_lines.append(f'[red]✗[/red] [magenta]{start_ip} - {end_ip}[/magenta] → {actual_owner}')
        else:
            # Random 20-IP rate-limited online validation (IP-API)
            for ip in base_samples:
                res = results.get(ip) or {}
                if res.get('status') != 'success':
                    ok = False
                    continue

                if not owner_matches(owner, res):
                    mismatch_lines.append(f'[red]✗[/red] [magenta]{ip}[/magenta] → {res.get("isp")} / {res.get("org")}')
                    ok = False
                    has_mismatches = True

        # Expansion Check
        start_int = int(net.network_address)
        expansion_found = False
        expandable_ips: list[str] = []

        bw_exp_status = '[green]✓ Clear[/green]'
        fw_exp_status = '[green]✓ Clear[/green]'
        bw_exp_details: list[str] = []
        fw_exp_details: list[str] = []

        for ip in adjacent_ips:
            ip_int = int(ipaddress.IPv4Address(ip))
            direction = 'BACKWARD' if ip_int < start_int else 'FORWARD'
            ip_obj = ipaddress.IPv4Address(ip)

            details_list = bw_exp_details if direction == 'BACKWARD' else fw_exp_details

            def update_status(status_str: str, d: str = direction) -> None:
                nonlocal bw_exp_status, fw_exp_status
                if d == 'BACKWARD':
                    bw_exp_status = status_str
                else:
                    fw_exp_status = status_str

            if any(ip_obj in n for n in owner_networks):
                update_status('[green]✓ Already Covered[/green]')
                details_list.append(f'[magenta]{ip}[/magenta]\nStatus: [green]Already Covered[/green]')
                continue

            res = results.get(ip) or {}
            status_val = res.get('status')
            msg_val = res.get('message')

            is_non_failure_fail = status_val == 'fail' and msg_val in (
                'address not found',
                'private range',
                'reserved range',
            )

            if status_val != 'success' and not is_non_failure_fail:
                update_status('[yellow]! Lookup Failed[/yellow]')
                details_list.append(f'[magenta]{ip}[/magenta]\nStatus: [yellow]Lookup Failed[/yellow]')
                continue

            if owner_matches(owner, res):
                update_status('[red]✗ Expandable[/red]')
                details_list.append(f'[magenta]{ip}[/magenta]\nStatus: [magenta]Same Owner ({res.get("isp")} / {res.get("org")})[/magenta]')
                expansion_found = True
                expandable_ips.append(ip)
            else:
                update_status('[green]✓ Boundary OK[/green]')
                if is_non_failure_fail and msg_val is not None:
                    desc = msg_val.title()
                else:
                    isp_val = res.get('isp')
                    org_val = res.get('org')
                    desc = f'{isp_val} / {org_val}' if isp_val and org_val else isp_val or org_val or 'Unknown'
                details_list.append(f'[magenta]{ip}[/magenta]\nStatus: [green]Different Owner ({desc})[/green]')

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
    renderables.append(Panel(render_samples(all_ips), title='[cyan]Sampled IPs[/cyan]', border_style='cyan', box=box.ROUNDED))
    renderables.append(Text(''))

    # 3. Validation Results, Expansion Details, Summary
    val_table = Table.grid(padding=(0, 4))
    val_table.add_column(style='cyan', justify='left')
    val_table.add_column(justify='left')

    base_status = '[red]✗ Mismatches Found[/red]' if has_mismatches else '[green]✓ Pass[/green]'
    val_table.add_row('Base Check', base_status)
    val_table.add_row('Backward Expansion', bw_exp_status)
    val_table.add_row('Forward Expansion', fw_exp_status)

    details_table = Table.grid(padding=(0, 4), expand=True)
    details_table.add_column()
    details_table.add_column()
    details_table.add_column()
    details_table.add_column()

    bw_text = '\n'.join(bw_exp_details) if bw_exp_details else 'N/A'
    fw_text = '\n'.join(fw_exp_details) if fw_exp_details else 'N/A'

    summary_parts: list[str] = []
    if ok:
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
        Panel(bw_text, title='[cyan]Backward Expansion[/cyan]', border_style='cyan', box=box.ROUNDED),
        Panel(fw_text, title='[cyan]Forward Expansion[/cyan]', border_style='cyan', box=box.ROUNDED),
        Panel(val_table, title='[cyan]Validation Results[/cyan]', border_style='cyan', box=box.ROUNDED),
        Panel(summary_text, title='[cyan]Summary[/cyan]', border_style='cyan', box=box.ROUNDED),
    )

    renderables.append(details_table)

    # If we have auto-fix / expand tables, we append them so they show inside the master panel
    if has_mismatches:
        renderables.append(Text(''))
        renderables.append(Rule('[bold white]Fix Suggestion[/bold white]'))
        renderables.append(Panel('\n'.join(mismatch_lines), title='[red]Base Check Mismatches[/red]', border_style='red', box=box.ROUNDED))
        fix_r = suggest_fix(client, owner, net, results, status)
        if fix_r:
            renderables.append(fix_r)

    if expansion_found:
        ctx = RangeContext(net, owner_networks)
        exp_r = suggest_expansion(client, owner, ctx, expandable_ips, status)
        if exp_r:
            renderables.append(Text(''))
            renderables.append(Rule('[bold white]Expansion Available[/bold white]'))
            renderables.append(exp_r)

    # Print the master panel
    title = f'[bold white]{owner}[/bold white]  •  [bold magenta]{net.with_prefixlen}[/bold magenta]  •  [dim]{net.network_address} → {net.broadcast_address}[/dim]  •  [bold white]{net.num_addresses:,} IPs[/bold white]'  # pylint: disable=line-too-long  # noqa: E501
    if file_path and lineno:
        rel_path = os.path.relpath(file_path).replace('\\', '/')
        title += f'  •  [blue]{rel_path}:{lineno}[/blue]'

    console.print()
    console.print(
        Panel(
            Group(*renderables),
            title=title,
            border_style='cyan',
            box=box.ROUNDED,
        ),
    )

    return ok


def run_preflight_checks(
    ranges: list[tuple[str, str, int]],
    networks_by_owner: dict[str, list[ipaddress.IPv4Network]],
    ranges_file: str = '',
) -> None:
    """Run all pre-flight checks and display them in a neat panel."""
    table = Table(show_header=False, expand=True, box=None, padding=(0, 2))
    table.add_column(style='cyan', justify='left', ratio=1)
    table.add_column(justify='left', ratio=3)

    # Sorting
    warnings: list[str] = []
    for owner, nets in networks_by_owner.items():
        if nets != sorted(nets):
            warnings.append(owner)
    if warnings:
        table.add_row('CIDR Sorting', f'[yellow]⚠ {len(warnings)} owners have unsorted ranges[/yellow]')
    else:
        table.add_row('CIDR Sorting', '[green]✓ All ranges correctly sorted[/green]')

    # Overlaps
    all_nets: list[tuple[str, ipaddress.IPv4Network]] = [(owner, net) for owner, nets in networks_by_owner.items() for net in nets]
    overlaps: list[str] = []
    for i, (o1, n1) in enumerate(all_nets):
        for j, (o2, n2) in enumerate(all_nets):
            if i != j and n1.subnet_of(n2):
                overlaps.append(f'[dim]• {n1} ({o1}) falls within {n2} ({o2})[/dim]')
    if overlaps:
        table.add_row('Overlapping CIDRs', f'[yellow]⚠ {len(overlaps)} overlaps detected![/yellow]\n' + '\n'.join(overlaps))
    else:
        table.add_row('Overlapping CIDRs', '[green]✓ No overlapping CIDRs found[/green]')

    # Collapsible
    collapses: list[str] = []
    collapse_suggestions: list[str] = []
    rel_path_clean = os.path.relpath(ranges_file).replace('\\', '/') if ranges_file else ''

    for owner, nets in networks_by_owner.items():
        collapsed = list(ipaddress.collapse_addresses(nets))
        if len(collapsed) < len(nets):
            collapses.append(f'[dim]• {owner}: {len(nets)} ranges → {len(collapsed)}[/dim]')

            # Find lines matching this owner to help user locate it
            owner_linenos = [lineno for o, _, lineno in ranges if o == owner]
            link_str = f'  •  [blue]{rel_path_clean}:{min(owner_linenos)}[/blue]' if (owner_linenos and rel_path_clean) else ''

            owner_suggestions = [f"    NamedRange('{owner}', '{net.with_prefixlen}')," for net in collapsed]
            collapse_suggestions.append(
                f'[bold white]{owner}[/bold white] ({len(nets)} ranges → {len(collapsed)}){link_str}\n' + '\n'.join(owner_suggestions),
            )

    if collapses:
        table.add_row('Collapsible CIDRs', f'[yellow]⚠ {len(collapses)} collapsible blocks found![/yellow]\n' + '\n'.join(collapses))
    else:
        table.add_row('Collapsible CIDRs', '[green]✓ No collapsible ranges found[/green]')

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
    args = [arg for arg in sys.argv if arg]

    parser = argparse.ArgumentParser(description='Verify IP ranges of third party servers.')
    parser.add_argument('ranges_file', help='Python file containing NamedRange definitions.')
    parser.add_argument('--geolite2', action='store_true', help='Use local GeoLite2 database instead of IP-API.')

    parsed_args = parser.parse_args(args[1:])

    ranges = extract_ranges(str(parsed_args.ranges_file))
    networks_by_owner: dict[str, list[ipaddress.IPv4Network]] = {}
    for owner, cidr, _ in ranges:
        with contextlib.suppress(ValueError, TypeError):
            net = ipaddress.ip_network(cidr)
            if isinstance(net, ipaddress.IPv4Network):
                networks_by_owner.setdefault(owner, []).append(net)

    console.rule('[bold cyan]Session Sniffer - Range Verification Engine[/bold cyan]')
    console.print(f'  [cyan]Loaded [bold white]{len(ranges)}[/bold white] ranges for processing.[/cyan]')

    # Run all pre-flight checks
    run_preflight_checks(ranges, networks_by_owner, ranges_file=str(parsed_args.ranges_file))

    if parsed_args.geolite2:
        try:
            # Add src/ folder to path if running verify_ranges.py directly so it can import session_sniffer
            src_path = str(Path(__file__).resolve().parent / 'src')
            if src_path not in sys.path:
                sys.path.insert(0, src_path)
            from session_sniffer.utils import get_app_dir  # pylint: disable=import-outside-toplevel  # noqa: PLC0415
        except ImportError:
            def get_app_dir(*, scope: Literal['roaming', 'local']) -> Path:
                del scope
                base = Path(os.getenv('LOCALAPPDATA', str(Path.home() / 'AppData' / 'Local')))
                app_dir = base / 'Session Sniffer'
                app_dir.mkdir(parents=True, exist_ok=True)
                return app_dir

        app_dir = get_app_dir(scope='local')
        asn_db_path = app_dir / 'GeoLite2 Databases' / 'GeoLite2-ASN.mmdb'

        if not asn_db_path.exists():
            console.print(f'[red]Error: GeoLite2-ASN database not found at {asn_db_path.absolute()}[/red]')
            console.print('[yellow]Please download it or launch the main app first to download it automatically.[/yellow]')
            sys.exit(1)

        client: GeoLite2Client | RateLimitClient = GeoLite2Client(asn_db_path)
    else:
        client = RateLimitClient(create_session())

    console.print()  # Add a newline for visual separation before skipping/checking ranges

    for owner, cidr, lineno in ranges:
        if 'google llc' in owner.lower() or 'tellas greece' in owner.lower() or 'battleye' in owner.lower():
            rel_path_clean = os.path.relpath(str(parsed_args.ranges_file)).replace('\\', '/')
            link_suffix = f'  •  [blue]{rel_path_clean}:{lineno}[/blue]' if rel_path_clean else ''
            console.print(f'[yellow dim]⚠ Skipping Range Verification for[/yellow dim] [dim]{owner} CIDR:[/dim] [magenta dim]{cidr}[/magenta dim]{link_suffix}')
            continue

        owner_networks = networks_by_owner.get(owner, [])
        location = (str(parsed_args.ranges_file), lineno)
        check_range(client, owner, cidr, owner_networks, location=location)

    if isinstance(client, GeoLite2Client):
        client.close()


if __name__ == '__main__':
    main()
