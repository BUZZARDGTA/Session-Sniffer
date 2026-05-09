"""Background core loops for IP lookup, hostname resolution, and ping."""

import time
from concurrent.futures import Future, ThreadPoolExecutor
from http import HTTPStatus

import requests
from pydantic import ValidationError

from session_sniffer.background.tasks import gui_closed__event
from session_sniffer.core import ScriptControl, ThreadsExceptionHandler
from session_sniffer.diagnostics import SlowdownDetector
from session_sniffer.logging_setup import get_logger
from session_sniffer.models import IpApiResponse
from session_sniffer.networking.endpoint_ping_manager import PingResult, fetch_and_parse_ping
from session_sniffer.networking.exceptions import AllEndpointsExhaustedError
from session_sniffer.networking.http_session import session
from session_sniffer.networking.reverse_dns import reverse_dns_lookup
from session_sniffer.player.registry import PlayersRegistry

logger = get_logger(__name__)

# API limits taken from https://ip-api.com/docs/api:batch the 03/04/2024.
_IPAPI_MAX_REQUESTS = 15
_IPAPI_MAX_THROTTLE_TIME = 60
_IPAPI_MAX_BATCH_IPS = 100
_IPAPI_FIELDS = (
    'status,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,'
    'timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query'
)


def iplookup_core() -> None:
    """Populate IP lookup data in the background using batch requests."""
    with ThreadsExceptionHandler():
        _slowdown = SlowdownDetector.get('iplookup_core', baseline_floor=0.15)

        def throttle_until(requests_remaining: int, throttle_time: int) -> None:
            # Spread remaining requests evenly across the reset window to stay within the rate limit.
            sleep_time = throttle_time / requests_remaining
            gui_closed__event.wait(sleep_time)

        requests_remaining = _IPAPI_MAX_REQUESTS
        ttl_seconds = _IPAPI_MAX_THROTTLE_TIME

        while not gui_closed__event.is_set():
            _iter_start = time.monotonic()

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
            except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
                gui_closed__event.wait(1)
                continue
            except requests.exceptions.HTTPError as e:
                if isinstance(e.response, requests.Response):
                    # Handle rate limiting
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

            requests_remaining = int(response.headers.get('X-Rl') or str(_IPAPI_MAX_REQUESTS - 1))
            ttl_seconds = int(response.headers.get('X-Ttl') or str(_IPAPI_MAX_THROTTLE_TIME))

            iplookup_results_data = response.json()
            iplookup_results: list[IpApiResponse] = []

            for item in iplookup_results_data:
                try:
                    iplookup_results.append(IpApiResponse.model_validate(item))
                except ValidationError:
                    # Mark IPs with a failed status as initialized so they are never retried.
                    if item.get('status') == 'fail':
                        failed_player = PlayersRegistry.get_player_by_ip(item.get('query', ''))
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

            _slowdown.check(time.monotonic() - _iter_start, 'iplookup_core')

            if requests_remaining <= 0:
                throttle_until(1, ttl_seconds)
                requests_remaining = _IPAPI_MAX_REQUESTS
                ttl_seconds = _IPAPI_MAX_THROTTLE_TIME
                continue

            throttle_until(requests_remaining, ttl_seconds)


def hostname_core() -> None:
    """Resolve reverse DNS hostnames for players in the background."""
    with ThreadsExceptionHandler(), ThreadPoolExecutor(max_workers=32) as executor:
        futures: dict[Future[str], str] = {}  # Maps futures to their corresponding IPs
        pending_ips: set[str] = set()   # Tracks IPs currently being processed

        _slowdown = SlowdownDetector.get('hostname_core')

        while not gui_closed__event.is_set():
            _iter_start = time.monotonic()

            if ScriptControl.has_crashed():
                return

            submitted_new = False

            for player in PlayersRegistry.get_default_sorted_players():
                if player.reverse_dns.is_initialized or player.ip in pending_ips:
                    continue

                future = executor.submit(reverse_dns_lookup, player.ip)
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

                hostname = future.result()

                matched_player = PlayersRegistry.get_player_by_ip(ip)
                if matched_player is None:
                    continue

                matched_player.reverse_dns.hostname = hostname
                matched_player.reverse_dns.is_initialized = True

            resolved_any = bool(done_futures)

            # Only poll quickly if there's active work; otherwise wait longer
            _slowdown.check(time.monotonic() - _iter_start, 'hostname_core')

            if not submitted_new and not resolved_any:
                gui_closed__event.wait(1)
            else:
                gui_closed__event.wait(0.1)


def pinger_core() -> None:
    """Fetch and parse ping data for players in the background."""
    with ThreadsExceptionHandler(), ThreadPoolExecutor(max_workers=32) as executor:
        futures: dict[Future[PingResult], str] = {}  # Maps futures to their corresponding IPs
        pending_ips: set[str] = set()   # Tracks IPs currently being processed
        exhausted_ips: dict[str, float] = {}  # Maps IPs to their retry-after timestamp
        _slowdown = SlowdownDetector.get('pinger_core')

        while not gui_closed__event.is_set():
            _iter_start = time.monotonic()

            if ScriptControl.has_crashed():
                return

            now = time.monotonic()
            submitted_new = False

            for player in PlayersRegistry.get_default_sorted_players():
                if player.ping.is_initialized or player.ip in pending_ips:
                    continue

                retry_after = exhausted_ips.get(player.ip)
                if retry_after is not None and now < retry_after:
                    continue

                future = executor.submit(fetch_and_parse_ping, player.ip)
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
                    ping_result = future.result()
                except AllEndpointsExhaustedError:
                    exhausted_ips[ip] = time.monotonic() + 30.0
                    continue

                exhausted_ips.pop(ip, None)

                matched_player = PlayersRegistry.get_player_by_ip(ip)
                if matched_player is None:
                    continue

                matched_player.ping.update_fields(ping_result._asdict())
                matched_player.ping.is_pinging = (
                    ping_result.packets_received is not None
                    and ping_result.packets_received > 0
                )
                matched_player.ping.is_initialized = True

            resolved_any = bool(done_futures)

            # Only poll quickly if there's active work; otherwise wait longer
            _slowdown.check(time.monotonic() - _iter_start, 'pinger_core')

            if not submitted_new and not resolved_any:
                gui_closed__event.wait(1)
            else:
                gui_closed__event.wait(0.1)
