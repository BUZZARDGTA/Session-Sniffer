"""Background core loops for IP lookup, hostname resolution, and ping."""

import time
from concurrent.futures import Future, ThreadPoolExecutor
from http import HTTPStatus
from threading import Thread
from threading import enumerate as enumerate_threads
from typing import TYPE_CHECKING, cast

import requests
from pydantic import ValidationError

from session_sniffer import msgbox
from session_sniffer.background.events import gui_closed__event
from session_sniffer.constants.standalone import TITLE
from session_sniffer.core import ScriptControl
from session_sniffer.guis.looky_text import LOOKY_LOG_API_KEY_INVALID, LOOKY_LOG_VERIFICATION_HTTP_FAILED_TEMPLATE
from session_sniffer.logging_setup import get_logger
from session_sniffer.models import IpApiResponse
from session_sniffer.networking.endpoint_ping_manager import PingResult, fetch_and_parse_ping
from session_sniffer.networking.exceptions import AllEndpointsExhaustedError
from session_sniffer.networking.http_session import session
from session_sniffer.networking.looky_system import LookyState, extract_rate_limit_wait_seconds
from session_sniffer.networking.looky_system import lookup_ip_batch as looky_lookup_ip_batch
from session_sniffer.networking.looky_system import verify_token as looky_verify_token
from session_sniffer.networking.reverse_dns import reverse_dns_lookup
from session_sniffer.networking.third_party_servers import is_third_party_server_ip
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.models.player import Player

logger = get_logger(__name__)


# API limits taken from https://ip-api.com/docs/api:batch the 03/04/2024.
_IPAPI_MAX_REQUESTS = 15
_IPAPI_MAX_THROTTLE_TIME = 60
_IPAPI_MAX_BATCH_IPS = 100
# Stop ip-api.com lookups after this many consecutive connection failures (e.g. a VPN/firewall silently blocking it).
_IPAPI_MAX_CONSECUTIVE_FAILURES = 5
_IPAPI_FIELDS = (
    'status,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query'
)


def _notify_ipapi_unavailable(reason: str) -> None:
    """Log and show a one-time user-facing warning that ip-api.com geolocation is unavailable this session.

    `reason` is a single sentence explaining why ip-api.com cannot be used (e.g. an HTTPS redirect or a
    blocked connection); it is embedded into both the log line and the user-facing message box.
    """
    logger.warning('[ip-api.com] %s IP geolocation via ip-api.com will be unavailable for this session.', reason)
    msgbox.show(
        TITLE,
        'IP geolocation via ip-api.com is unavailable for this session.\n\n'
        f'{reason}\n\n'
        'Country, City, ISP, ASN and related ip-api.com fields will not be populated until the issue is '
        'resolved and Session Sniffer is restarted.',
        msgbox.Style.MB_OK | msgbox.Style.MB_ICONWARNING,
    )


def iplookup_core() -> None:
    """Populate IP lookup data in the background using batch requests."""

    def throttle_until(requests_remaining: int, throttle_time: int) -> None:
        # Spread remaining requests evenly across the reset window to stay within the rate limit.
        sleep_time = throttle_time / requests_remaining
        gui_closed__event.wait(sleep_time)

    requests_remaining = _IPAPI_MAX_REQUESTS
    ttl_seconds = _IPAPI_MAX_THROTTLE_TIME
    consecutive_failures = 0

    while not gui_closed__event.is_set():
        if ScriptControl.has_crashed():
            return

        ips_to_lookup: list[str] = []

        for player in PlayersRegistry.get_default_sorted_players():
            if player.iplookup.ipapi.is_initialized:
                continue

            ips_to_lookup.append(player.ip)

            if len(ips_to_lookup) == _IPAPI_MAX_BATCH_IPS:
                break

        if not ips_to_lookup:
            gui_closed__event.wait(1)
            continue

        try:
            response = session.post(
                'http://ip-api.com/batch',
                params={'fields': _IPAPI_FIELDS},
                headers={'Content-Type': 'application/json'},
                json=ips_to_lookup,
                timeout=3,
            )
            response.raise_for_status()
        except requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout:
            # ip-api.com is unreachable (no response at all) — commonly a VPN, proxy, or firewall silently
            # blocking the connection. Retry a few times in case it is a transient blip, but give up after
            # too many consecutive failures so we surface a warning instead of hammering the network forever.
            consecutive_failures += 1
            if consecutive_failures >= _IPAPI_MAX_CONSECUTIVE_FAILURES:
                _notify_ipapi_unavailable(
                    f'Could not reach ip-api.com after {consecutive_failures} consecutive attempts (a VPN, proxy, or firewall may be blocking the connection).',
                )
                return
            gui_closed__event.wait(1)
            continue
        except requests.exceptions.HTTPError as e:
            if isinstance(e.response, requests.Response):
                # ip-api.com's free tier is HTTP-only. Some networks (notably VPNs/proxies) force our plain-HTTP
                # request onto HTTPS, so ip-api.com answers with a 301 redirect to its HTTPS URL. `requests`
                # follows that redirect and, per the HTTP spec, downgrades our POST to a GET — but the /batch
                # endpoint only accepts POST, so the redirected request comes back as 405 Method Not Allowed.
                # That 301-then-405 chain uniquely identifies this situation, so warn and stop this background
                # thread gracefully; the rest of the sniffer keeps running normally.
                if e.response.status_code == HTTPStatus.METHOD_NOT_ALLOWED and any(redirect.status_code == HTTPStatus.MOVED_PERMANENTLY for redirect in e.response.history):
                    _notify_ipapi_unavailable(
                        'Requests to ip-api.com are being redirected to HTTPS (commonly caused by a VPN or proxy), which the free ip-api.com service does not support.',
                    )
                    return

                # Handle rate limiting.
                if e.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                    requests_remaining = int(e.response.headers.get('X-Rl') or '0')
                    ttl_seconds = int(e.response.headers.get('X-Ttl') or str(_IPAPI_MAX_THROTTLE_TIME))
                    gui_closed__event.wait(ttl_seconds)
                    requests_remaining = _IPAPI_MAX_REQUESTS
                    ttl_seconds = _IPAPI_MAX_THROTTLE_TIME
                    continue

                # Transient server-side errors — wait and retry.
                if HTTPStatus(e.response.status_code).is_server_error:
                    logger.warning('ip-api.com returned %s, retrying in 5 seconds...', e.response.status_code)
                    gui_closed__event.wait(5)
                    continue

            raise  # Re-raise unexpected HTTP errors (4xx, etc.)

        # A successful response means the network path to ip-api.com is working — reset the failure counter.
        consecutive_failures = 0

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

        if requests_remaining <= 0:
            throttle_until(1, ttl_seconds)
            requests_remaining = _IPAPI_MAX_REQUESTS
            ttl_seconds = _IPAPI_MAX_THROTTLE_TIME
            continue

        throttle_until(requests_remaining, ttl_seconds)


def _run_player_future_core[T](
    *,
    worker: Callable[[str], T],
    should_submit: Callable[[Player], bool],
    apply_result: Callable[[Player, T], None],
    handle_exception: Callable[[str, Exception], bool] | None = None,
    max_workers: int = 32,
) -> None:
    """Run a background player task using one future per pending IP."""
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures: dict[Future[T], str] = {}  # Maps futures to their corresponding IPs
        pending_ips: set[str] = set()  # Tracks IPs currently being processed

        while not gui_closed__event.is_set():
            if ScriptControl.has_crashed():
                return

            submitted_new = False

            for player in PlayersRegistry.get_default_sorted_players():
                if gui_closed__event.is_set():
                    return

                if player.ip in pending_ips or not should_submit(player):
                    continue

                if gui_closed__event.is_set():
                    return

                future = executor.submit(worker, player.ip)
                futures[future] = player.ip
                pending_ips.add(player.ip)
                submitted_new = True

            if not futures:
                gui_closed__event.wait(1)
                continue

            done_futures = [(future, ip) for future, ip in futures.items() if future.done()]

            for future, ip in done_futures:
                futures.pop(future)
                pending_ips.remove(ip)

                try:
                    result = future.result()
                except Exception as e:
                    if handle_exception is not None and handle_exception(ip, e):
                        continue

                    raise

                matched_player = PlayersRegistry.get_player_by_ip(ip)
                if matched_player is None:
                    continue

                apply_result(matched_player, result)

            resolved_any = bool(done_futures)

            # Only poll quickly if there's active work; otherwise wait longer.
            if not submitted_new and not resolved_any:
                gui_closed__event.wait(1)
            else:
                gui_closed__event.wait(0.1)


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
    )


def pinger_core() -> None:
    """Fetch and parse ping data for players in the background."""
    exhausted_ips: dict[str, float] = {}  # Maps IPs to their retry-after timestamp

    def should_submit(player: Player) -> bool:
        if player.ping.is_initialized:
            return False

        retry_after = exhausted_ips.get(player.ip)
        return retry_after is None or time.monotonic() >= retry_after

    def apply_result(player: Player, ping_result: PingResult) -> None:
        exhausted_ips.pop(player.ip, None)

        player.ping.update_fields(ping_result._asdict())
        player.ping.is_pinging = ping_result.packets_received is not None and ping_result.packets_received > 0
        player.ping.is_initialized = True

    def handle_exception(ip: str, exception: Exception) -> bool:
        if isinstance(exception, AllEndpointsExhaustedError):
            exhausted_ips[ip] = time.monotonic() + 30.0
            return True

        return False

    _run_player_future_core(
        worker=fetch_and_parse_ping,
        should_submit=should_submit,
        apply_result=apply_result,
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

        if not Settings.looky_api_key or not Settings.looky_enabled or not Settings.is_gta5_preset():
            if _verified_api_key is not None:
                _verified_api_key = None
                LookyState.reset()
            if not Settings.is_gta5_preset():
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
            except requests.HTTPError as e:
                status = e.response.status_code if e.response is not None else '?'
                reason = e.response.reason if e.response is not None else 'Unknown'
                if e.response is not None and e.response.status_code == HTTPStatus.UNAUTHORIZED:
                    logger.warning(LOOKY_LOG_API_KEY_INVALID)
                else:
                    logger.warning(LOOKY_LOG_VERIFICATION_HTTP_FAILED_TEMPLATE, status, reason)
                LookyState.reset()

                if e.response is not None and e.response.status_code == HTTPStatus.UNAUTHORIZED:
                    _failed_verification_api_key = Settings.looky_api_key
            except requests.RequestException as e:
                logger.warning('[Looky System] Token verification failed: %s', e)
                LookyState.reset()

        if not Settings.looky_auto_resolve or not LookyState.api_access:
            if not LookyState.api_access:
                gui_closed__event.wait(30)
            else:
                gui_closed__event.wait(5)
            continue

        pending_ips = [
            player.ip
            for player in PlayersRegistry.get_default_sorted_players()
            if not is_third_party_server_ip(player.ip)
            and (
                not player.looky_system.is_initialized
                or player.looky_system.needs_refresh
                or (time.monotonic() - player.looky_system.last_fetched_at) >= _LOOKY_REFRESH_INTERVAL
            )
        ]

        if not pending_ips:
            gui_closed__event.wait(1)
            continue

        resolved_any = False
        rate_limited = False
        cooldown_active = False

        for batch_start in range(0, len(pending_ips), _batch_size):
            if gui_closed__event.is_set():
                return
            if batch_start > 0:
                gui_closed__event.wait(0.5)

            batch = pending_ips[batch_start : batch_start + _batch_size]

            try:
                results = looky_lookup_ip_batch(batch, Settings.looky_api_key, Settings.looky_game_version.lower())
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                    wait_seconds = extract_rate_limit_wait_seconds(e)
                    logger.warning('[Looky System] Rate limited — waiting %s seconds', wait_seconds)
                    gui_closed__event.wait(wait_seconds)
                    rate_limited = True
                    break
                if e.response is not None and HTTPStatus(e.response.status_code).is_server_error:
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
                        with matched_player.looky_system.lock:
                            matched_player.looky_system.usernames = [player.name for player in players]
                            matched_player.looky_system.rockstarids = [player.rockstarid for player in players]
                            matched_player.looky_system.needs_refresh = False
                            matched_player.looky_system.last_fetched_at = time.monotonic()
                            matched_player.looky_system.is_initialized = True
                resolved_any = True
                server_error_consecutive_failures = 0

        if not resolved_any and not rate_limited and not cooldown_active:
            gui_closed__event.wait(1)
        else:
            gui_closed__event.wait(0.1)


def ensure_looky_core_running() -> None:
    """Start the `looky_core` thread if the GTA5 preset is active and it is not already running."""
    if not Settings.is_gta5_preset():
        return
    for thread in enumerate_threads():
        if thread.name == _LOOKY_CORE_THREAD_NAME and thread.is_alive():
            return
    Thread(target=looky_core, name=_LOOKY_CORE_THREAD_NAME, daemon=True).start()
