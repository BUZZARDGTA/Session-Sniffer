"""Background core loops for IP lookup, hostname resolution, and ping."""

import time
from concurrent.futures import Future, ThreadPoolExecutor
from http import HTTPStatus
from typing import TYPE_CHECKING, TypeVar, cast

import requests
from pydantic import ValidationError

from session_sniffer.background.tasks import gui_closed__event
from session_sniffer.core import ScriptControl
from session_sniffer.logging_setup import get_logger
from session_sniffer.models import IpApiResponse
from session_sniffer.networking.endpoint_ping_manager import PingResult, fetch_and_parse_ping
from session_sniffer.networking.exceptions import AllEndpointsExhaustedError
from session_sniffer.networking.http_session import session
from session_sniffer.networking.reverse_dns import reverse_dns_lookup
from session_sniffer.player.registry import PlayersRegistry

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.models.player import Player

logger = get_logger(__name__)

T = TypeVar('T')


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
    def throttle_until(requests_remaining: int, throttle_time: int) -> None:
        # Spread remaining requests evenly across the reset window to stay within the rate limit.
        sleep_time = throttle_time / requests_remaining
        gui_closed__event.wait(sleep_time)

    requests_remaining = _IPAPI_MAX_REQUESTS
    ttl_seconds = _IPAPI_MAX_THROTTLE_TIME

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
        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
            gui_closed__event.wait(1)
            continue
        except requests.exceptions.HTTPError as e:
            if isinstance(e.response, requests.Response):
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
) -> None:
    """Run a background player task using one future per pending IP."""
    with ThreadPoolExecutor(max_workers=32) as executor:
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
        player.ping.is_pinging = (
            ping_result.packets_received is not None
            and ping_result.packets_received > 0
        )
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
