"""Background core loops for IP lookup, hostname resolution, and ping."""

import logging
import time
from collections import deque
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from http import HTTPStatus
from itertools import chain
from threading import Event, RLock, Thread
from threading import enumerate as enumerate_threads
from typing import TYPE_CHECKING, cast

import requests
from pydantic import ValidationError

from session_sniffer.background.events import gui_closed__event
from session_sniffer.core import ScriptControl
from session_sniffer.guis.dialogs import show_ipapi_unavailable_dialog
from session_sniffer.guis.looky_text import LOOKY_LOG_API_KEY_INVALID, LOOKY_LOG_VERIFICATION_HTTP_FAILED_TEMPLATE
from session_sniffer.models import IpApiResponse
from session_sniffer.networking.exceptions import AllEndpointsExhaustedError
from session_sniffer.networking.http_session import session
from session_sniffer.networking.looky_system import LookyState, extract_rate_limit_wait_seconds
from session_sniffer.networking.looky_system import lookup_ip_batch as looky_lookup_ip_batch
from session_sniffer.networking.looky_system import verify_token as looky_verify_token
from session_sniffer.networking.ping import ping_player
from session_sniffer.networking.reverse_dns import reverse_dns_lookup
from session_sniffer.networking.third_party_servers import is_third_party_server_ip
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.userip import gui_dispatcher
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings
from session_sniffer.utils import dedup_preserve_order

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.models.looky_system import LookyPlayer
    from session_sniffer.models.player import Player
    from session_sniffer.networking.endpoint_ping_manager import PingResult

logger = logging.getLogger(__name__)


class ResolutionQueue:
    """Thread-safe FIFO queue with fast set-based deduplication."""

    def __init__(self, on_empty: Callable[[], None] | None = None) -> None:
        """Initialize a ResolutionQueue instance."""
        self._deque: deque[str] = deque()
        self._queued_ip_addresses: set[str] = set()
        self._lock: RLock = RLock()
        self._has_items: Event = Event()
        self.on_empty: Callable[[], None] | None = on_empty

    def put(self, ip_address: str) -> bool:
        """Enqueue an IP address if not already queued. Returns True if added."""
        with self._lock:
            if ip_address in self._queued_ip_addresses:
                return False
            self._queued_ip_addresses.add(ip_address)
            self._deque.append(ip_address)
            self._has_items.set()
            return True

    def put_many(self, ip_addresses: list[str]) -> int:
        """Enqueue multiple IP addresses, skipping duplicates. Returns number of added IP addresses."""
        added_count = 0
        with self._lock:
            for ip_address in ip_addresses:
                if ip_address not in self._queued_ip_addresses:
                    self._queued_ip_addresses.add(ip_address)
                    self._deque.append(ip_address)
                    added_count += 1
            if added_count > 0:
                self._has_items.set()
        return added_count

    def requeue_front(self, ip_addresses: list[str]) -> None:
        """Re-enqueue IP addresses to the front of the queue maintaining relative order."""
        with self._lock:
            for ip_address in reversed(ip_addresses):
                if ip_address not in self._queued_ip_addresses:
                    self._queued_ip_addresses.add(ip_address)
                    self._deque.appendleft(ip_address)
            if self._deque:
                self._has_items.set()

    def get(self) -> str | None:
        """Pop an IP address without blocking, or None if empty."""
        with self._lock:
            if not self._deque and self.on_empty is not None:
                self.on_empty()
            if not self._deque:
                return None
            ip_address = self._deque.popleft()
            self._queued_ip_addresses.discard(ip_address)
            if not self._deque:
                self._has_items.clear()
            return ip_address

    def get_batch(self, max_items: int) -> list[str]:
        """Pop up to `max_items` IP addresses without blocking."""
        with self._lock:
            if not self._deque and self.on_empty is not None:
                self.on_empty()
            count = min(max_items, len(self._deque))
            if not count:
                return []
            items: list[str] = []
            for _ in range(count):
                ip_address = self._deque.popleft()
                self._queued_ip_addresses.discard(ip_address)
                items.append(ip_address)
            if not self._deque:
                self._has_items.clear()
            return items

    def wait(self, timeout: float) -> bool:
        """Wait until items are available or timeout expires."""
        return self._has_items.wait(timeout)

    def clear(self) -> None:
        """Clear all queued IP addresses."""
        with self._lock:
            self._deque.clear()
            self._queued_ip_addresses.clear()
            self._has_items.clear()

    def __len__(self) -> int:
        """Return the number of IP addresses in the queue."""
        with self._lock:
            return len(self._deque)

    def __bool__(self) -> bool:
        """Return True if the queue contains any IP addresses."""
        with self._lock:
            return bool(self._deque)


# API limits taken from https://ip-api.com/docs/api:batch the 03/04/2024.
_IPAPI_MAX_REQUESTS = 15
_IPAPI_MAX_THROTTLE_TIME = 60
_IPAPI_MAX_BATCH_IPS = 100
# Stop ip-api.com lookups after this many consecutive connection failures (e.g. a VPN/firewall silently blocking it).
_IPAPI_MAX_CONSECUTIVE_FAILURES = 3
_IPAPI_FIELDS = (
    'status,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query'
)
_IPAPI_PROBE_IP = '1.1.1.1'
_PLAYER_CORE_MAX_WORKERS = 8


def _notify_ipapi_unavailable(reason: str) -> None:
    """Log and show a one-time user-facing warning that ip-api.com geolocation is unavailable.

    `reason` is a single sentence explaining why ip-api.com cannot be used (e.g. an HTTPS redirect or a
    blocked connection); it is embedded into both the log line and the user-facing dialog.
    """
    logger.warning('[ip-api.com] %s IP geolocation via ip-api.com will be unavailable until connection is restored.', reason)
    gui_dispatcher.invoke(lambda: show_ipapi_unavailable_dialog(reason))


_iplookup_wakeup_event = Event()
_hostname_wakeup_event = Event()
_pinger_wakeup_event = Event()
_looky_wakeup_event = Event()

_iplookup_queue = ResolutionQueue()
_hostname_queue = ResolutionQueue()
_pinger_queue = ResolutionQueue()
_looky_queue = ResolutionQueue()


def _is_looky_eligible(player: Player) -> bool:
    """Check whether a player is eligible for Looky System resolution."""
    if not Settings.is_gta5_feature_set():
        return False
    if player.is_third_party_server:
        return False
    return not (Settings.looky_exclusive_gta5_process and CaptureState.is_local_capture() and not player.is_gta5_process)


def enqueue_player_for_resolution(player: Player) -> None:
    """Enqueue a player for all relevant background resolutions."""
    if not player.reverse_dns.is_initialized and _hostname_queue.put(player.ip):
        _hostname_wakeup_event.set()

    if not player.iplookup.ipapi.is_initialized and _iplookup_queue.put(player.ip):
        _iplookup_wakeup_event.set()

    if not player.ping.is_initialized and not player.left_event.is_set() and _pinger_queue.put(player.ip):
        _pinger_wakeup_event.set()

    if (
        _is_looky_eligible(player)
        and (not player.looky_system.is_initialized or player.looky_system.needs_refresh)
        and _looky_queue.put(player.ip)
    ):
        _looky_wakeup_event.set()


def clear_resolution_queues() -> None:
    """Clear all pending items from resolution queues."""
    _hostname_queue.clear()
    _iplookup_queue.clear()
    _pinger_queue.clear()
    _looky_queue.clear()


def _wait_iplookup_event(timeout: float, *, ignore_wake: bool = False) -> bool:
    """Wait for _iplookup_wakeup_event or gui_closed__event up to timeout seconds.

    Returns:
        True if awakened by _iplookup_wakeup_event, False if timed out or gui_closed__event set.
    """
    deadline = time.monotonic() + timeout
    while not gui_closed__event.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        if not ignore_wake and (_iplookup_wakeup_event.wait(min(remaining, 0.5)) or _iplookup_queue.wait(min(remaining, 0.5))):
            _iplookup_wakeup_event.clear()
            return True
        if ignore_wake and gui_closed__event.wait(min(remaining, 0.5)):
            return False
    return False


def wake_iplookup_core() -> None:
    """Signal the IP-API background core loop to immediately check for pending player lookups."""
    _iplookup_wakeup_event.set()
    for player in chain(PlayersRegistry.get_connected_players(), PlayersRegistry.get_disconnected_players()):
        if not player.iplookup.ipapi.is_initialized and _iplookup_queue.put(player.ip):
            _iplookup_wakeup_event.set()


def wake_hostname_core() -> None:
    """Signal the reverse DNS background core to immediately check for pending hostnames."""
    _hostname_wakeup_event.set()
    for player in chain(PlayersRegistry.get_connected_players(), PlayersRegistry.get_disconnected_players()):
        if not player.reverse_dns.is_initialized and _hostname_queue.put(player.ip):
            _hostname_wakeup_event.set()


def wake_pinger_core() -> None:
    """Signal the pinger background core to immediately check for pending player pings."""
    _pinger_wakeup_event.set()
    for player in PlayersRegistry.get_connected_players():
        if not player.ping.is_initialized and not player.left_event.is_set() and _pinger_queue.put(player.ip):
            _pinger_wakeup_event.set()


def wake_looky_core() -> None:
    """Signal the Looky System background core to immediately check for pending player lookups."""
    _looky_wakeup_event.set()
    if Settings.is_gta5_feature_set():
        for player in chain(PlayersRegistry.get_connected_players(), PlayersRegistry.get_disconnected_players()):
            if (
                not player.is_third_party_server
                and (not player.looky_system.is_initialized or player.looky_system.needs_refresh)
                and _looky_queue.put(player.ip)
            ):
                _looky_wakeup_event.set()


def wake_all_player_cores(player: Player | None = None) -> None:
    """Signal all background enrichment cores to immediately check for pending player work."""
    if player is not None:
        enqueue_player_for_resolution(player)
        return

    _iplookup_wakeup_event.set()
    _hostname_wakeup_event.set()
    _pinger_wakeup_event.set()
    _looky_wakeup_event.set()

    for p in chain(PlayersRegistry.get_connected_players(), PlayersRegistry.get_disconnected_players()):
        enqueue_player_for_resolution(p)


def iplookup_core() -> None:
    """Populate IP lookup data in the background using batch requests."""
    requests_remaining = _IPAPI_MAX_REQUESTS
    ttl_seconds = _IPAPI_MAX_THROTTLE_TIME
    consecutive_failures = 0
    unavailability_warning_shown = False

    while not gui_closed__event.is_set():
        if ScriptControl.has_crashed():
            return

        ip_addresses_to_lookup: list[str] = []
        while len(ip_addresses_to_lookup) < _IPAPI_MAX_BATCH_IPS:
            target_ip = _iplookup_queue.get()
            if target_ip is None:
                break
            matched_player = PlayersRegistry.get_player_by_ip(target_ip)
            if matched_player is not None and not matched_player.iplookup.ipapi.is_initialized:
                ip_addresses_to_lookup.append(target_ip)

        is_probe = False
        if not ip_addresses_to_lookup:
            if not unavailability_warning_shown:
                _iplookup_wakeup_event.clear()
                if not _iplookup_queue and not gui_closed__event.is_set():
                    _iplookup_wakeup_event.wait(1.0)
                continue

            # When ip-api.com was previously unavailable, probe using a known IP to test if connectivity is restored.
            is_probe = True
            ip_addresses_to_lookup = [_IPAPI_PROBE_IP]

        try:
            response = session.post(
                'http://ip-api.com/batch',
                params={'fields': _IPAPI_FIELDS},
                headers={'Content-Type': 'application/json'},
                json=ip_addresses_to_lookup,
                timeout=3,
            )
            response.raise_for_status()
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            # ip-api.com is unreachable (no response at all) — commonly a VPN, proxy, or firewall silently
            # blocking the connection. Retry a few times in case it is a transient blip; after too many
            # consecutive failures surface a one-time warning, then probe every 60s so the lookup can
            # recover automatically if the network issue (e.g. a VPN) is resolved later.
            if not is_probe:
                _iplookup_queue.requeue_front(ip_addresses_to_lookup)
            if unavailability_warning_shown:
                _wait_iplookup_event(60, ignore_wake=True)
                continue
            consecutive_failures += 1
            if consecutive_failures >= _IPAPI_MAX_CONSECUTIVE_FAILURES:
                unavailability_warning_shown = True
                _notify_ipapi_unavailable(
                    f'Could not reach ip-api.com after {consecutive_failures} consecutive attempts (a VPN, proxy, or firewall may be blocking the connection).',
                )
                _wait_iplookup_event(60, ignore_wake=True)
            else:
                _wait_iplookup_event(1)
            continue
        except requests.exceptions.HTTPError as e:
            if isinstance(e.response, requests.Response):
                if not is_probe:
                    _iplookup_queue.requeue_front(ip_addresses_to_lookup)
                # ip-api.com's free tier is HTTP-only. Some networks (notably VPNs/proxies) force our plain-HTTP
                # request onto HTTPS, so ip-api.com answers with a 301 redirect to its HTTPS URL. `requests`
                # follows that redirect and, per the HTTP spec, downgrades our POST to a GET — but the /batch
                # endpoint only accepts POST, so the redirected request comes back as 405 Method Not Allowed.
                # That 301-then-405 chain uniquely identifies this situation, so warn and wait for the condition
                # to clear (e.g. VPN disconnected) rather than permanently killing the thread.
                if e.response.status_code == HTTPStatus.METHOD_NOT_ALLOWED and any(redirect.status_code == HTTPStatus.MOVED_PERMANENTLY for redirect in e.response.history):
                    if not unavailability_warning_shown:
                        unavailability_warning_shown = True
                        _notify_ipapi_unavailable(
                            'Requests to ip-api.com are being redirected to HTTPS (commonly caused by a VPN or proxy), which the free ip-api.com service does not support.',
                        )
                    _wait_iplookup_event(60, ignore_wake=True)
                    continue

                # Handle rate limiting.
                if e.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                    requests_remaining = int(e.response.headers.get('X-Rl') or '0')
                    ttl_seconds = int(e.response.headers.get('X-Ttl') or str(_IPAPI_MAX_THROTTLE_TIME))
                    _wait_iplookup_event(ttl_seconds)
                    requests_remaining = _IPAPI_MAX_REQUESTS
                    ttl_seconds = _IPAPI_MAX_THROTTLE_TIME
                    continue

                # Transient server-side errors — wait and retry.
                if HTTPStatus(e.response.status_code).is_server_error:
                    logger.warning('ip-api.com returned %s, retrying in 5 seconds...', e.response.status_code)
                    _wait_iplookup_event(5)
                    continue

            raise  # Re-raise unexpected HTTP errors (4xx, etc.)

        # A successful response means the network path to ip-api.com is working — reset the failure counter.
        if unavailability_warning_shown:
            unavailability_warning_shown = False
            logger.info('[ip-api.com] Connection to ip-api.com has been restored. IP geolocation lookups will resume.')
        consecutive_failures = 0

        if is_probe:
            continue

        requests_remaining = int(response.headers.get('X-Rl') or str(_IPAPI_MAX_REQUESTS - 1))
        ttl_seconds = int(response.headers.get('X-Ttl') or str(_IPAPI_MAX_THROTTLE_TIME))

        iplookup_results_data: object = response.json()
        if not isinstance(iplookup_results_data, list):
            logger.warning('ip-api.com returned unexpected response shape (expected list): %s', type(iplookup_results_data).__name__)
            continue
        iplookup_results: list[IpApiResponse] = []

        for raw_item in cast('list[object]', iplookup_results_data):
            if not isinstance(raw_item, dict):
                logger.warning('ip-api.com batch response contained a non-dict item: %r', raw_item)
                continue
            item = cast('dict[str, object]', raw_item)
            try:
                iplookup_results.append(IpApiResponse.model_validate(item))
            except ValidationError:
                # Mark IPs with a failed status as initialized so they are never retried.
                if item.get('status') == 'fail':
                    query_raw = item.get('query', '')
                    failed_player = PlayersRegistry.get_player_by_ip(query_raw if isinstance(query_raw, str) else '')
                    if failed_player is not None:
                        failed_player.iplookup.ipapi.is_initialized = True
                        logger.debug(
                            'ip-api returned fail for %s (%s) — marking as initialized',
                            item.get('query'),
                            item.get('message', ''),
                        )
                else:
                    logger.warning('Failed to validate ip-api response item: %s', item)

                continue

        for iplookup in iplookup_results:
            matched_player = PlayersRegistry.get_player_by_ip(iplookup.query)
            if matched_player is None:
                continue

            matched_player.iplookup.ipapi.update_fields(iplookup.model_dump(exclude={'status', 'query'}))
            matched_player.iplookup.ipapi.is_initialized = True

        if requests_remaining <= 1:
            gui_closed__event.wait(max(ttl_seconds, 1))
            requests_remaining = _IPAPI_MAX_REQUESTS
            ttl_seconds = _IPAPI_MAX_THROTTLE_TIME
            continue

        gui_closed__event.wait(min(ttl_seconds / requests_remaining, 0.5))


def _run_player_future_core[T](
    *,
    worker: Callable[[str], T],
    should_submit: Callable[[Player], bool],
    apply_result: Callable[[Player, T], None],
    queue: ResolutionQueue,
    handle_exception: Callable[[str, Exception], bool] | None = None,
) -> None:
    """Run a background player task using one future per pending IP from the resolution queue."""
    is_pinger = worker is ping_player
    thread_name_prefix = 'Pinger' if is_pinger else 'Hostname'
    with ThreadPoolExecutor(max_workers=_PLAYER_CORE_MAX_WORKERS, thread_name_prefix=thread_name_prefix) as executor:
        futures: dict[Future[T], str] = {}  # Maps futures to their corresponding IP addresses
        in_flight_ip_addresses: set[str] = set()

        while not gui_closed__event.is_set():
            if ScriptControl.has_crashed():
                return

            while len(futures) < _PLAYER_CORE_MAX_WORKERS * 2:
                if gui_closed__event.is_set():
                    return

                target_ip = queue.get()
                if target_ip is None:
                    break

                if target_ip in in_flight_ip_addresses:
                    continue

                matched_player = PlayersRegistry.get_player_by_ip(target_ip)
                if matched_player is None or not should_submit(matched_player):
                    continue

                future = executor.submit(worker, target_ip)
                futures[future] = target_ip
                in_flight_ip_addresses.add(target_ip)

            if not futures:
                queue.wait(1.0)
                continue

            done, _ = wait(futures.keys(), timeout=0.1, return_when=FIRST_COMPLETED)

            for future in done:
                target_ip = futures.pop(future)
                in_flight_ip_addresses.discard(target_ip)

                try:
                    result = future.result()
                except Exception as e:
                    if handle_exception is not None and handle_exception(target_ip, e):
                        continue

                    raise

                matched_player = PlayersRegistry.get_player_by_ip(target_ip)
                if matched_player is None:
                    continue

                apply_result(matched_player, result)


def hostname_core() -> None:
    """Resolve reverse DNS hostnames for players in the background."""

    def should_submit(player: Player) -> bool:
        return not player.reverse_dns.is_initialized

    def apply_result(player: Player, hostname: str) -> None:
        player.reverse_dns.hostname = hostname
        player.reverse_dns.is_initialized = True

    _run_player_future_core(
        worker=reverse_dns_lookup,
        should_submit=should_submit,
        apply_result=apply_result,
        queue=_hostname_queue,
    )


def pinger_core() -> None:
    """Fetch and parse ping data for players in the background."""
    exhausted_ip_addresses: dict[str, float] = {}  # Maps IP addresses to their retry-after timestamp

    def should_submit(player: Player) -> bool:
        if player.left_event.is_set() or player.ping.is_initialized:
            return False

        retry_after = exhausted_ip_addresses.get(player.ip)
        return retry_after is None or time.monotonic() >= retry_after

    def apply_result(player: Player, ping_result: PingResult) -> None:
        exhausted_ip_addresses.pop(player.ip, None)

        player.ping.update_fields(ping_result._asdict())
        player.ping.is_pinging = ping_result.packets_received is not None and ping_result.packets_received > 0
        player.ping.is_initialized = True

    def handle_exception(ip_address: str, exception: Exception) -> bool:
        if isinstance(exception, AllEndpointsExhaustedError):
            exhausted_ip_addresses[ip_address] = time.monotonic() + 30.0
            return True

        return False

    def check_exhausted_ip_addresses() -> None:
        if not exhausted_ip_addresses:
            return
        current_time = time.monotonic()
        retry_ip_addresses = [ip_address for ip_address, retry_at in exhausted_ip_addresses.items() if current_time >= retry_at]
        for ip_address in retry_ip_addresses:
            del exhausted_ip_addresses[ip_address]
            player = PlayersRegistry.get_player_by_ip(ip_address)
            if player is not None and not player.left_event.is_set() and not player.ping.is_initialized and _pinger_queue.put(ip_address):
                _pinger_wakeup_event.set()

    _pinger_queue.on_empty = check_exhausted_ip_addresses
    _run_player_future_core(
        worker=ping_player,
        should_submit=should_submit,
        apply_result=apply_result,
        queue=_pinger_queue,
        handle_exception=handle_exception,
    )


_LOOKY_REFRESH_INTERVAL = 60.0
_LOOKY_CORE_THREAD_NAME = 'looky_core'


def looky_core() -> None:
    """Resolve player names via the Looky System API in the background.

    Sends batched requests of up to 32 IPs at a time.  Skips all work when no
    API key is configured.
    """
    _batch_size = 32
    _verified_api_key: str | None = None
    _failed_verification_api_key: str | None = None
    server_error_consecutive_failures = 0

    while not gui_closed__event.is_set():
        if ScriptControl.has_crashed():
            return

        if Settings.looky_api_key is None or not Settings.looky_api_key or not Settings.looky_enabled or not Settings.is_gta5_feature_set():
            if _verified_api_key is not None:
                _verified_api_key = None
                LookyState.reset()
            if not Settings.is_gta5_feature_set():
                return
            gui_closed__event.wait(5)
            continue

        if Settings.looky_api_key == _failed_verification_api_key:
            LookyState.reset()
            gui_closed__event.wait(30)
            continue

        if _failed_verification_api_key is not None and Settings.looky_api_key != _failed_verification_api_key:
            _failed_verification_api_key = None

        if Settings.looky_api_key != _verified_api_key:
            try:
                response = looky_verify_token(Settings.looky_api_key)
                LookyState.set(response)
                if LookyState.api_access:
                    _verified_api_key = Settings.looky_api_key
                    _failed_verification_api_key = None
                    server_error_consecutive_failures = 0
            except requests.HTTPError as e:
                status = e.response.status_code if e.response is not None else '?'
                reason = e.response.reason if e.response is not None else 'Unknown'
                LookyState.reset()

                if e.response is not None and e.response.status_code == HTTPStatus.UNAUTHORIZED:
                    logger.warning(LOOKY_LOG_API_KEY_INVALID)
                    _failed_verification_api_key = Settings.looky_api_key
                elif e.response is not None and HTTPStatus(e.response.status_code).is_server_error:
                    server_error_consecutive_failures += 1
                    cooldown_duration = min(30 * (2 ** (server_error_consecutive_failures - 1)), 300)
                    logger.warning(
                        '[Looky System] Server error during token verification (HTTP %s %s). Entering %ss cooldown.',
                        status,
                        reason,
                        cooldown_duration,
                    )
                    gui_closed__event.wait(cooldown_duration)
                    continue
                else:
                    logger.warning(LOOKY_LOG_VERIFICATION_HTTP_FAILED_TEMPLATE, status, reason)
            except requests.RequestException as e:
                server_error_consecutive_failures += 1
                cooldown_duration = min(30 * (2 ** (server_error_consecutive_failures - 1)), 300)
                logger.warning('[Looky System] Token verification failed: %s. Entering %ss cooldown.', e, cooldown_duration)
                LookyState.reset()
                gui_closed__event.wait(cooldown_duration)
                continue

        if not LookyState.api_access:
            gui_closed__event.wait(30)
            continue

        if (
            Settings.looky_exclusive_gta5_process
            and CaptureState.is_local_capture()
            and not CaptureState.gta5_is_running
        ):
            gui_closed__event.wait(1.0)
            continue

        pending_ip_addresses: list[str] = []
        while len(pending_ip_addresses) < _batch_size:
            target_ip = _looky_queue.get()
            if target_ip is None:
                break
            if is_third_party_server_ip(target_ip):
                continue
            matched_player = PlayersRegistry.get_player_by_ip(target_ip)
            if matched_player is None:
                continue
            if (
                Settings.looky_exclusive_gta5_process
                and CaptureState.is_local_capture()
                and not matched_player.is_gta5_process
            ):
                continue
            if (
                not matched_player.looky_system.is_initialized
                or matched_player.looky_system.needs_refresh
                or (time.monotonic() - matched_player.looky_system.last_fetched_at) >= _LOOKY_REFRESH_INTERVAL
            ):
                pending_ip_addresses.append(target_ip)

        if not pending_ip_addresses:
            # Check if any connected players need periodic refresh
            current_time = time.monotonic()
            for player in PlayersRegistry.get_connected_players():
                if (
                    player.looky_system.is_initialized
                    and _is_looky_eligible(player)
                    and (player.looky_system.needs_refresh or (current_time - player.looky_system.last_fetched_at) >= _LOOKY_REFRESH_INTERVAL)
                    and _looky_queue.put(player.ip)
                ):
                    pending_ip_addresses.append(player.ip)
                    if len(pending_ip_addresses) >= _batch_size:
                        break

        if not pending_ip_addresses:
            _looky_wakeup_event.wait(1)
            _looky_wakeup_event.clear()
            continue

        resolved_any = False
        rate_limited = False
        cooldown_active = False

        for batch_start in range(0, len(pending_ip_addresses), _batch_size):
            if gui_closed__event.is_set():
                return
            if batch_start > 0:
                gui_closed__event.wait(0.5)

            batch = pending_ip_addresses[batch_start : batch_start + _batch_size]

            try:
                results = looky_lookup_ip_batch(batch, Settings.looky_api_key, Settings.looky_game_version.lower())
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                    _looky_queue.requeue_front(batch)
                    wait_seconds = extract_rate_limit_wait_seconds(e)
                    logger.warning('[Looky System] Rate limited — waiting %s seconds', wait_seconds)
                    gui_closed__event.wait(wait_seconds)
                    rate_limited = True
                    break
                if e.response is not None and HTTPStatus(e.response.status_code).is_server_error:
                    _looky_queue.requeue_front(batch)
                    server_error_consecutive_failures += 1
                    cooldown_duration = min(30 * (2 ** (server_error_consecutive_failures - 1)), 300)
                    logger.warning('[Looky System] Server error for batch %s: %s. Entering %ss cooldown.', batch, e, cooldown_duration)
                    gui_closed__event.wait(cooldown_duration)
                    cooldown_active = True
                    break
                logger.debug('[Looky System] HTTP error for batch %s: %s', batch, e)
                for ip in batch:
                    matched_player = PlayersRegistry.get_player_by_ip(ip)
                    if matched_player is not None:
                        with matched_player.looky_system.lock:
                            matched_player.looky_system.needs_refresh = False
                            matched_player.looky_system.last_fetched_at = time.monotonic()
                            matched_player.looky_system.is_initialized = True
            except requests.RequestException as e:
                _looky_queue.requeue_front(batch)
                server_error_consecutive_failures += 1
                cooldown_duration = min(30 * (2 ** (server_error_consecutive_failures - 1)), 300)
                logger.warning('[Looky System] Request error for batch %s: %s. Entering %ss cooldown.', batch, e, cooldown_duration)
                gui_closed__event.wait(cooldown_duration)
                cooldown_active = True
                break
            except ValidationError as e:
                logger.warning('[Looky System] Validation error for batch %s: %s', batch, e)
                for ip in batch:
                    matched_player = PlayersRegistry.get_player_by_ip(ip)
                    if matched_player is not None:
                        with matched_player.looky_system.lock:
                            matched_player.looky_system.needs_refresh = False
                            matched_player.looky_system.last_fetched_at = time.monotonic()
                            matched_player.looky_system.is_initialized = True
            else:
                for ip in batch:
                    matched_player = PlayersRegistry.get_player_by_ip(ip)
                    if matched_player is not None:
                        players = results.get(ip, [])
                        unique_players: list[LookyPlayer] = []
                        seen_pairs: set[tuple[str, int]] = set()
                        for looky_player in players:
                            pair = (looky_player.name, looky_player.rockstarid)
                            if pair not in seen_pairs:
                                seen_pairs.add(pair)
                                unique_players.append(looky_player)
                        with matched_player.looky_system.lock:
                            matched_player.looky_system.usernames = [
                                looky_player.name.strip() for looky_player in unique_players if looky_player.name and looky_player.name.strip()
                            ]
                            matched_player.looky_system.rockstarids = [looky_player.rockstarid for looky_player in unique_players]
                            matched_player.looky_system.last_seens = [looky_player.lastSeen for looky_player in unique_players]
                            matched_player.looky_system.needs_refresh = False
                            matched_player.looky_system.last_fetched_at = time.monotonic()
                            matched_player.looky_system.is_initialized = True
                        if matched_player.looky_system.usernames:
                            matched_player.usernames = dedup_preserve_order(
                                matched_player.usernames,
                                matched_player.looky_system.usernames,
                            )
                resolved_any = True
                server_error_consecutive_failures = 0

        if not resolved_any and not rate_limited and not cooldown_active:
            _looky_wakeup_event.wait(1)
            _looky_wakeup_event.clear()
        else:
            gui_closed__event.wait(0.1)


def ensure_looky_core_running() -> None:
    """Start the `looky_core` thread if the GTA5 feature set is active and it is not already running."""
    if not Settings.is_gta5_feature_set():
        return
    for thread in enumerate_threads():
        if thread.name == _LOOKY_CORE_THREAD_NAME and thread.is_alive():
            return
    Thread(target=looky_core, name=_LOOKY_CORE_THREAD_NAME, daemon=True).start()
