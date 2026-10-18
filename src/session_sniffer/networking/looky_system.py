"""Looky System IP-to-player lookup API client."""

import logging
import math
import re
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC
from http import HTTPStatus
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, ClassVar, cast
from urllib.parse import quote

import requests
from pydantic import TypeAdapter

from session_sniffer.constants.standalone import LOOKY_BASE_HOST
from session_sniffer.models.looky_system import (
    LookyInstructionStatus,
    LookyInstructionStatusEvent,
    LookyInstructionStatusInitialResponse,
    LookyIpBatchResult,
    LookyPlayer,
    LookyPlayerProfile,
    LookyWhoAmI,
)
from session_sniffer.networking.http_session import session
from session_sniffer.networking.third_party_servers import is_third_party_server_ip

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

logger = logging.getLogger(__name__)

LOOKY_SEARCH_URL = f'{LOOKY_BASE_HOST}/api/search'
LOOKY_SEARCH_IP_BATCH_URL = f'{LOOKY_BASE_HOST}/api/search/ip-batch'
LOOKY_PLAYER_URL = f'{LOOKY_BASE_HOST}/api/player'
LOOKY_WHOAMI_URL = f'{LOOKY_BASE_HOST}/api/whoami'
LOOKY_INSTRUCTION_URL = f'{LOOKY_BASE_HOST}/api/instruction'
LOOKY_INSTRUCTION_STATUS_INITIAL_URL = f'{LOOKY_BASE_HOST}/api/instruction-status-initial'
LOOKY_CRAWLME_URL = f'{LOOKY_BASE_HOST}/api/instruction/crawlme'
LOOKY_INSTRUCTION_STATUS_URL = f'{LOOKY_BASE_HOST}/api/sse/instruction-status'
LOOKY_USER_URL = f'{LOOKY_BASE_HOST}/user'


def get_looky_user_url(rid: int) -> str:
    """Return the Looky System website user profile URL for `rid`."""
    return f'{LOOKY_USER_URL}/{rid}'


_RESPONSE_ADAPTER: TypeAdapter[list[LookyPlayer]] = TypeAdapter(list[LookyPlayer])
_BATCH_RESPONSE_ADAPTER: TypeAdapter[list[LookyIpBatchResult]] = TypeAdapter(list[LookyIpBatchResult])

_TERMINAL_INSTRUCTION_STATUSES = frozenset({'completed', 'failed', 'canceled'})
_TERMINAL_FAILURE_INSTRUCTION_STATUSES = frozenset({'failed', 'canceled'})


@dataclass(frozen=True, slots=True)
class LookyInstructionContext:
    """Parameters required to initialize and poll a Looky System instruction stream."""

    tracking_id: str
    api_key: str
    version: str
    rid: int | None = None


class _CancelStreamError(Exception):
    pass


class LookyState:
    """Runtime-only Looky System state derived from token verification.

    Not persisted to `settings.json` — populated by the `looky_core` background thread
    and read by the GUI to gate Looky-related actions.
    """

    api_access: ClassVar[bool] = False
    user_data: ClassVar[LookyWhoAmI | None] = None

    # Monotonic deadline of the last server-imposed crawler rate limit, so the GUI can show the
    # remaining cooldown when re-opening the crawler without needlessly re-hitting the API.
    _crawler_cooldown_until: ClassVar[float] = 0.0

    @classmethod
    def reset(cls) -> None:
        """Clear verified state (used when no/invalid API key, on errors, or when Looky is disabled)."""
        cls.api_access = False
        cls.user_data = None

    @classmethod
    def set(cls, user_data: LookyWhoAmI) -> None:
        """Apply a successful token-verification response."""
        cls.api_access = user_data.api_access
        cls.user_data = user_data

    @classmethod
    def record_crawler_cooldown(cls, wait_seconds: int) -> None:
        """Remember a server-imposed crawler rate limit so the UI can show it without re-hitting the API."""
        cls._crawler_cooldown_until = time.monotonic() + max(0, wait_seconds)

    @classmethod
    def clear_crawler_cooldown(cls) -> None:
        """Clear the local crawler rate-limit cooldown (e.g. after a successful send)."""
        cls._crawler_cooldown_until = 0.0

    @classmethod
    def crawler_cooldown_remaining(cls) -> int:
        """Return the whole seconds left on the local crawler rate-limit cooldown (0 if none)."""
        return max(0, math.ceil(cls._crawler_cooldown_until - time.monotonic()))


def _auth_headers(api_key: str) -> dict[str, str]:
    return {'Authorization': f'Bearer {api_key}'}


def _json_auth_headers(api_key: str) -> dict[str, str]:
    return {**_auth_headers(api_key), 'Content-Type': 'application/json'}


def extract_rate_limit_message(exc: requests.HTTPError) -> str:
    """Return the API error message from a 429 `HTTPError` response, falling back to `'Too Many Requests'`."""
    if exc.response is None:
        return 'Too Many Requests'
    try:
        return str(exc.response.json().get('message', 'Too Many Requests'))
    except requests.JSONDecodeError:
        return 'Too Many Requests'


def extract_api_error_message(exc: requests.HTTPError) -> str | None:
    """Return the API error message from an `HTTPError` response JSON `message` field, or `None` if not present."""
    if exc.response is None:
        return None
    try:
        body: object = exc.response.json()
    except requests.JSONDecodeError:
        return None
    if isinstance(body, dict):
        raw_message: object = cast('dict[str, object]', body).get('message')
        if isinstance(raw_message, str) and raw_message.strip():
            return raw_message.strip()
    return None


def is_terminal_instruction_status(status: str) -> bool:
    """Return `True` if the instruction status marks the end of tracking."""
    return status.strip().lower() in _TERMINAL_INSTRUCTION_STATUSES


def is_terminal_failure_instruction_status(status: str) -> bool:
    """Return `True` if the instruction status is a terminal failure."""
    return status.strip().lower() in _TERMINAL_FAILURE_INSTRUCTION_STATUSES


def extract_rate_limit_wait_seconds(exc: requests.HTTPError) -> int | None:
    """Return the number of seconds to wait before retrying after a 429 response, or `None` if not determinable.

    Checks in priority order:
    1. `Retry-After` response header (standard HTTP).
    2. Numeric JSON body fields: `retryAfter`, `waitSeconds`, `retry_after`.
    3. First integer found in the JSON `message` field.
    """
    if exc.response is None:
        return None
    retry_after_header = exc.response.headers.get('Retry-After')
    if retry_after_header is not None and retry_after_header:
        try:
            return max(1, int(float(retry_after_header)))
        except ValueError:
            pass
    try:
        body = exc.response.json()
    except requests.JSONDecodeError:
        return None
    for field in ('retryAfter', 'waitSeconds', 'retry_after'):
        value = body.get(field)
        if isinstance(value, (int, float)) and value > 0:
            return max(1, int(value))
    message = body.get('message', '')
    match = re.search(r'(\d+)\s+second', str(message))
    if match:
        return max(1, int(match.group(1)))
    return None


def verify_token(api_key: str) -> LookyWhoAmI:
    """Verify a Looky System API key via `GET /api/whoami`.

    Args:
        api_key: Looky System Bearer API key.

    Returns:
        `LookyWhoAmI` populated from the API response.

    Raises:
        requests.HTTPError: On a non-2xx response (e.g. 401 for invalid key).
        requests.RequestException: On connection/timeout errors.
        pydantic.ValidationError: If the response JSON shape is unexpected.
    """
    response = session.get(
        LOOKY_WHOAMI_URL,
        headers=_auth_headers(api_key),
        timeout=(3.0, 10.0),
    )
    response.raise_for_status()
    return LookyWhoAmI.model_validate(response.json())


_CACHE_LOCK = threading.Lock()
_RID_BY_USERNAME_CF_CACHE: dict[str, int | None] = {}
_PROFILE_BY_RID_CACHE: dict[int, LookyPlayerProfile | None] = {}


def _cache_looky_players(players: list[LookyPlayer]) -> None:
    """Populate `_RID_BY_USERNAME_CF_CACHE` with resolved `(username, rockstarid)` pairs."""
    with _CACHE_LOCK:
        for player in players:
            if player.rockstarid > 0 and (stripped_name := player.name.strip()):
                _RID_BY_USERNAME_CF_CACHE[stripped_name.casefold()] = player.rockstarid


def lookup_ip(ip: str, api_key: str, version: str = 'both') -> list[LookyPlayer]:
    """Query the Looky System API for players associated with `ip`.

    Args:
        ip: The IPv4 address to look up.
        api_key: Looky System Bearer API key.
        version: Game version filter sent to the API (`'both'`, `'legacy'`, or `'enhanced'`).

    Returns:
        A (possibly empty) list of `LookyPlayer` entries.

    Raises:
        requests.HTTPError: On a non-2xx response.
        requests.RequestException: On connection/timeout errors.
        pydantic.ValidationError: If the response JSON shape is unexpected.
    """
    response = session.get(f'{LOOKY_SEARCH_URL}/{ip}', headers=_auth_headers(api_key), params={'version': version}, timeout=(3.0, 10.0))
    response.raise_for_status()
    results = _RESPONSE_ADAPTER.validate_json(response.content)
    _cache_looky_players(results)
    return _sort_looky_players(results)


def _sort_looky_players(players: list[LookyPlayer]) -> list[LookyPlayer]:
    """Sort Looky players from most recent to oldest by `last_seen`."""
    return sorted(
        players,
        key=lambda player: player.last_seen.astimezone(UTC) if player.last_seen.tzinfo is not None else player.last_seen.replace(tzinfo=UTC),
        reverse=True,
    )


def lookup_ip_batch(ip_addresses: list[str], api_key: str, version: str = 'both') -> dict[str, list[LookyPlayer]]:
    """Query the Looky System batch endpoint for players associated with multiple IPs in one request.

    Args:
        ip_addresses: List of IPv4 addresses to look up (max 32 per call).
        api_key: Looky System Bearer API key.
        version: Game version filter sent to the API (`'both'`, `'legacy'`, or `'enhanced'`).

    Returns:
        A dict mapping each IP address to its (possibly empty) list of `LookyPlayer` entries.
        IPs that have no data in the response are not included in the returned dict.

    Raises:
        requests.HTTPError: On a non-2xx response.
        requests.RequestException: On connection/timeout errors.
        pydantic.ValidationError: If the response JSON shape is unexpected.
    """
    response = session.post(
        LOOKY_SEARCH_IP_BATCH_URL,
        headers=_json_auth_headers(api_key),
        json={'ips': ip_addresses, 'version': version},
        timeout=(3.0, 10.0),
    )
    response.raise_for_status()
    parsed = _BATCH_RESPONSE_ADAPTER.validate_json(response.content)
    for item in parsed:
        _cache_looky_players(item.players)
    return {item.ip: _sort_looky_players(item.players) for item in parsed}


_AUTH_HTTP_STATUSES = frozenset({HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN})
_NOT_FOUND_SEARCH_STATUSES = frozenset({
    HTTPStatus.BAD_REQUEST,
    HTTPStatus.NOT_FOUND,
    HTTPStatus.INTERNAL_SERVER_ERROR,
})
_MIN_USERNAME_SEARCH_LEN = 2


def get_rid_by_username(username: str, api_key: str) -> int | None:
    """Resolve `username` to its Rockstar ID via `GET /api/search/{username}` exact case-insensitive match.

    Looky's `/api/scapi/getrid` endpoint is currently unavailable (`503`), whereas `/api/search/{username}`
    queries Looky's indexed player database directly and returns `200` with `LookyPlayer` entries when found
    (or `404`/`500` when no matching player exists in Looky).

    Args:
        username: The Rockstar Social Club username to look up.
        api_key: Looky System Bearer API key.

    Returns:
        The integer Rockstar ID if found in Looky, or `None` if the username is not indexed.

    Raises:
        requests.HTTPError: On a non-2xx response other than 400/404/500 (e.g. 401, 403, 429, 502, 503).
        requests.RequestException: On connection/timeout errors.
    """
    stripped = username.strip()
    if len(stripped) < _MIN_USERNAME_SEARCH_LEN:
        return None
    name_cf = stripped.casefold()
    with _CACHE_LOCK:
        if name_cf in _RID_BY_USERNAME_CF_CACHE:
            return _RID_BY_USERNAME_CF_CACHE[name_cf]
    encoded_name = quote(stripped, safe='')
    headers = _auth_headers(api_key)
    headers['Referer'] = f'{LOOKY_BASE_HOST}/'
    response = session.get(
        f'{LOOKY_SEARCH_URL}/{encoded_name}',
        headers=headers,
        params={'version': 'both'},
        timeout=(3.0, 6.0),
    )
    if response.status_code in _NOT_FOUND_SEARCH_STATUSES:
        with _CACHE_LOCK:
            _RID_BY_USERNAME_CF_CACHE[name_cf] = None
        return None
    response.raise_for_status()
    results = _RESPONSE_ADAPTER.validate_json(response.content)
    _cache_looky_players(results)
    resolved_rid = next(
        (player.rockstarid for player in results if player.name.strip().casefold() == name_cf and player.rockstarid > 0),
        None,
    )
    with _CACHE_LOCK:
        _RID_BY_USERNAME_CF_CACHE[name_cf] = resolved_rid
    return resolved_rid


def lookup_player_by_rid(rid: int, api_key: str) -> LookyPlayerProfile | None:
    """Query `GET /api/player/{rid}` for a player's profile and session IP history.

    Args:
        rid: The integer Rockstar ID to look up.
        api_key: Looky System Bearer API key.

    Returns:
        `LookyPlayerProfile` if found, or `None` if the player does not exist in Looky.

    Raises:
        requests.HTTPError: On a non-2xx/non-404 response (e.g. 401, 403, 429, 5xx).
        requests.RequestException: On connection/timeout errors.
        pydantic.ValidationError: If the response JSON shape is unexpected.
    """
    with _CACHE_LOCK:
        if rid in _PROFILE_BY_RID_CACHE:
            return _PROFILE_BY_RID_CACHE[rid]
    headers = _auth_headers(api_key)
    headers['Referer'] = get_looky_user_url(rid)
    response = session.get(f'{LOOKY_PLAYER_URL}/{rid}', headers=headers, timeout=(3.0, 8.0))
    if response.status_code == HTTPStatus.NOT_FOUND:
        with _CACHE_LOCK:
            _PROFILE_BY_RID_CACHE[rid] = None
        return None
    response.raise_for_status()
    profile = LookyPlayerProfile.model_validate_json(response.content)
    resolved_rid = profile.rockstarid or rid
    with _CACHE_LOCK:
        _PROFILE_BY_RID_CACHE[rid] = profile
        if resolved_rid > 0:
            for sighting in profile.users_by_rockstar_id:
                if stripped_name := sighting.name.strip():
                    _RID_BY_USERNAME_CF_CACHE[stripped_name.casefold()] = resolved_rid
    return profile


def _is_valid_player_ipv4(ip: str) -> bool:
    """Return True if `ip` is a valid single IPv4 address that is not a third-party server."""
    try:
        IPv4Address(ip)
    except ValueError:
        return False
    return not is_third_party_server_ip(ip)


_USERNAME_LOOKUP_MAX_WORKERS = 16


def _wait_for_rate_limit(deadline_holder: list[float], should_cancel: Callable[[], bool] | None) -> bool:
    """Sleep until `deadline_holder[0]` passes, returning `False` if canceled."""
    while (remaining := deadline_holder[0] - time.monotonic()) > 0:
        if should_cancel is not None and should_cancel():
            return False
        time.sleep(min(0.2, remaining))
    return should_cancel is None or not should_cancel()


def _record_rate_limit(exc: requests.HTTPError, deadline_holder: list[float], lock: threading.Lock) -> None:
    """Extend `deadline_holder[0]` using `Retry-After` from `exc`."""
    wait_seconds = min(extract_rate_limit_wait_seconds(exc) or 4, 15)
    with lock:
        deadline_holder[0] = max(deadline_holder[0], time.monotonic() + wait_seconds + 0.25)


def _resolve_usernames_to_rids(
    usernames: list[str],
    api_key: str,
    *,
    should_cancel: Callable[[], bool] | None = None,
    on_progress: Callable[[str, int, int], None] | None = None,
) -> dict[int, list[str]]:
    """Resolve `usernames` to a mapping of `rid -> list[username]` using cache and `GET /api/search/{username}`."""
    usernames_by_rid: dict[int, list[str]] = defaultdict(list)
    seen_username_cfs: set[str] = set()
    usernames_to_query: list[str] = []
    with _CACHE_LOCK:
        for raw_username in usernames:
            stripped = raw_username.strip()
            name_cf = stripped.casefold()
            if len(stripped) < _MIN_USERNAME_SEARCH_LEN or name_cf == 'n/a' or name_cf in seen_username_cfs:
                continue
            seen_username_cfs.add(name_cf)
            if name_cf in _RID_BY_USERNAME_CF_CACHE:
                cached_rid = _RID_BY_USERNAME_CF_CACHE[name_cf]
                if cached_rid is not None and cached_rid > 0:
                    usernames_by_rid[cached_rid].append(stripped)
            else:
                usernames_to_query.append(stripped)

    if not usernames_to_query:
        return usernames_by_rid

    total_to_query = len(usernames_to_query)
    if on_progress is not None:
        on_progress('Resolving usernames to Rockstar IDs', 0, total_to_query)
    search_unavailable = threading.Event()
    rate_limit_lock = threading.Lock()
    rate_limit_deadline = [0.0]

    def _resolve_one(name: str) -> tuple[str, int | None]:
        for _ in range(4):
            if not _wait_for_rate_limit(rate_limit_deadline, should_cancel) or search_unavailable.is_set():
                return name, None
            try:
                return name, get_rid_by_username(name, api_key)
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code in _AUTH_HTTP_STATUSES:
                    raise
                if e.response is not None and e.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                    _record_rate_limit(e, rate_limit_deadline, rate_limit_lock)
                    continue
                search_unavailable.set()
                logger.debug('Looky username search unavailable for username=%s: %s', name, e)
                return name, None
            except requests.RequestException as e:
                logger.debug('Looky username search request failed for username=%s: %s', name, e)
                return name, None
        return name, None

    completed = 0
    with ThreadPoolExecutor(max_workers=min(_USERNAME_LOOKUP_MAX_WORKERS, total_to_query)) as executor:
        futures = [executor.submit(_resolve_one, name) for name in usernames_to_query]
        for future in as_completed(futures):
            name, resolved_rid = future.result()
            completed += 1
            if on_progress is not None:
                on_progress('Resolving usernames to Rockstar IDs', completed, total_to_query)
            if should_cancel is not None and should_cancel():
                return {}
            if resolved_rid is not None and resolved_rid > 0:
                usernames_by_rid[resolved_rid].append(name)
    return usernames_by_rid


def _fetch_profiles_by_rid(
    rids: list[int],
    api_key: str,
    *,
    should_cancel: Callable[[], bool] | None = None,
    on_progress: Callable[[str, int, int], None] | None = None,
) -> dict[int, LookyPlayerProfile]:
    """Fetch `LookyPlayerProfile` objects for `rids` concurrently via `GET /api/player/{rid}`."""
    if not rids:
        return {}
    total_rids = len(rids)
    if on_progress is not None:
        on_progress('Fetching player IP histories', 0, total_rids)
    player_unavailable = threading.Event()
    rate_limit_lock = threading.Lock()
    rate_limit_deadline = [0.0]

    def _fetch_one(target_rid: int) -> tuple[int, LookyPlayerProfile | None]:
        for _ in range(4):
            if not _wait_for_rate_limit(rate_limit_deadline, should_cancel) or player_unavailable.is_set():
                return target_rid, None
            try:
                return target_rid, lookup_player_by_rid(target_rid, api_key)
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code in _AUTH_HTTP_STATUSES:
                    raise
                if e.response is not None and e.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                    _record_rate_limit(e, rate_limit_deadline, rate_limit_lock)
                    continue
                player_unavailable.set()
                logger.debug('Looky player lookup unavailable for rid=%s: %s', target_rid, e)
                return target_rid, None
            except requests.RequestException as e:
                logger.debug('Looky player lookup request failed for rid=%s: %s', target_rid, e)
                return target_rid, None
        return target_rid, None

    profiles_by_rid: dict[int, LookyPlayerProfile] = {}
    completed = 0
    with ThreadPoolExecutor(max_workers=min(_USERNAME_LOOKUP_MAX_WORKERS, total_rids)) as executor:
        futures = [executor.submit(_fetch_one, target_rid) for target_rid in rids]
        for future in as_completed(futures):
            target_rid, profile = future.result()
            completed += 1
            if on_progress is not None:
                on_progress('Fetching player IP histories', completed, total_rids)
            if should_cancel is not None and should_cancel():
                return {}
            if profile is not None:
                profiles_by_rid[target_rid] = profile
    return profiles_by_rid


def lookup_username_ips(
    usernames: list[str],
    api_key: str,
    version: str = 'both',
    *,
    should_cancel: Callable[[], bool] | None = None,
    on_progress: Callable[[str, int, int], None] | None = None,
) -> tuple[dict[str, list[LookyPlayer]], dict[str, list[str]]]:
    """Resolve `usernames` to Rockstar IDs and fetch their recorded session IPs via `GET /api/player/{rid}`.

    Returns:
        A tuple `(players_by_ip, ips_by_username_cf)` where `players_by_ip` maps each discovered IP
        to its `LookyPlayer` entries and `ips_by_username_cf` maps each lowercased username to its
        ordered list of discovered IPv4 addresses (most recent first).
    """
    usernames_by_rid = _resolve_usernames_to_rids(usernames, api_key, should_cancel=should_cancel, on_progress=on_progress)
    if (should_cancel is not None and should_cancel()) or not usernames_by_rid:
        return {}, {}
    profiles_by_rid = _fetch_profiles_by_rid(list(usernames_by_rid), api_key, should_cancel=should_cancel, on_progress=on_progress)
    if should_cancel is not None and should_cancel():
        return {}, {}

    players_by_ip: dict[str, list[LookyPlayer]] = defaultdict(list)
    seen_names_by_ip: dict[str, set[str]] = defaultdict(set)
    ips_by_username_cf: dict[str, list[str]] = defaultdict(list)
    seen_ips_by_username_cf: dict[str, set[str]] = defaultdict(set)

    for rid, rid_usernames in usernames_by_rid.items():
        profile = profiles_by_rid.get(rid)
        if profile is None:
            continue
        sorted_sightings = sorted(
            profile.users_by_rockstar_id,
            key=lambda item: item.datetimestamp.astimezone(UTC) if item.datetimestamp.tzinfo is not None else item.datetimestamp.replace(tzinfo=UTC),
            reverse=True,
        )
        resolved_rid = profile.rockstarid or rid
        for sighting in sorted_sightings:
            if sighting.relay or not _is_valid_player_ipv4(sighting.ip):
                continue
            if (version == 'enhanced' and not sighting.enhanced) or (version == 'legacy' and sighting.enhanced):
                continue
            candidate_names = [*rid_usernames, *([sighting.name.strip()] if sighting.name.strip() else [])]
            for queried_name in rid_usernames:
                queried_cf = queried_name.casefold()
                if sighting.ip not in seen_ips_by_username_cf[queried_cf]:
                    seen_ips_by_username_cf[queried_cf].add(sighting.ip)
                    ips_by_username_cf[queried_cf].append(sighting.ip)
            for candidate_name in candidate_names:
                cand_cf = candidate_name.casefold()
                if cand_cf not in seen_names_by_ip[sighting.ip]:
                    seen_names_by_ip[sighting.ip].add(cand_cf)
                    players_by_ip[sighting.ip].append(
                        LookyPlayer(
                            rockstarid=resolved_rid,
                            name=candidate_name,
                            last_seen=sighting.datetimestamp,
                            last_country=sighting.country,
                            is_modder=profile.is_modder,
                            is_enhanced=sighting.enhanced,
                            is_legacy=not sighting.enhanced,
                            is_vpn=sighting.vpn,
                        ),
                    )

    return dict(players_by_ip), dict(ips_by_username_cf)


def send_crawlme_instruction(api_key: str, version: str) -> str:
    """POST a crawlme instruction to the Looky System API to request the crawler for the current session.

    Args:
        api_key: Looky System Bearer API key.
        version: Game version filter sent to the API (`'both'`, `'legacy'`, or `'enhanced'`).

    Returns:
        The instruction tracking ID (UUID string) for polling status via `watch_instruction_status`.

    Raises:
        requests.HTTPError: On a non-2xx response.
        requests.RequestException: On connection/timeout errors.
        KeyError: If the response JSON does not contain a `'trackingId'` field.
    """
    headers = _json_auth_headers(api_key)
    headers['Referer'] = 'https://looky-gta.cc/'
    try:
        response = session.post(
            LOOKY_CRAWLME_URL,
            headers=headers,
            json={'target': version},
            timeout=(3.0, 10.0),
        )
        response.raise_for_status()
        return str(response.json()['trackingId'])
    except requests.HTTPError as e:
        status_code = e.response.status_code if e.response is not None else '?'
        text = e.response.text if e.response is not None else ''
        logger.debug('Looky crawlme HTTP error for target=%s: HTTP %s (response: %s)', version, status_code, text)
        raise
    except Exception as e:
        logger.debug('Looky crawlme request error for target=%s: %s', version, e)
        raise


def send_crawler_instruction(rid: int, api_key: str, version: str) -> str:
    """POST a join instruction to the Looky System API to call the crawler bot for `rid`.

    Args:
        rid: The Rockstar player ID to request the crawler for.
        api_key: Looky System Bearer API key.
        version: Game version filter sent to the API (`'both'`, `'legacy'`, or `'enhanced'`).

    Returns:
        The instruction tracking ID (UUID string) for polling status via `watch_instruction_status`.

    Raises:
        requests.HTTPError: On a non-2xx response.
        requests.RequestException: On connection/timeout errors.
        KeyError: If the response JSON does not contain a `'trackingId'` field.
    """
    headers = _json_auth_headers(api_key)
    headers['Referer'] = get_looky_user_url(rid)
    try:
        response = session.post(
            LOOKY_INSTRUCTION_URL,
            headers=headers,
            json={'type': 'join', 'rid': rid, 'target': version},
            timeout=(3.0, 10.0),
        )
        response.raise_for_status()
        return str(response.json()['trackingId'])
    except requests.HTTPError as e:
        status_code = e.response.status_code if e.response is not None else '?'
        text = e.response.text if e.response is not None else ''
        logger.debug('Looky crawler HTTP error for rid=%s target=%s: HTTP %s (response: %s)', rid, version, status_code, text)
        raise
    except Exception as e:
        logger.debug('Looky crawler request error for rid=%s target=%s: %s', rid, version, e)
        raise


def send_proxy_join_instruction(rid: int, api_key: str, version: str) -> str:
    """POST an `rid_join` instruction to the Looky System API to call the proxy join bot for `rid`.

    Args:
        rid: The Rockstar player ID to proxy join.
        api_key: Looky System Bearer API key.
        version: Game version filter sent to the API (`'both'`, `'legacy'`, or `'enhanced'`).

    Returns:
        The instruction tracking ID (UUID string) for polling status via `watch_instruction_status`.

    Raises:
        requests.HTTPError: On a non-2xx response.
        requests.RequestException: On connection/timeout errors.
        KeyError: If the response JSON does not contain a `'trackingId'` field.
    """
    headers = _json_auth_headers(api_key)
    headers['Referer'] = get_looky_user_url(rid)
    try:
        response = session.post(
            LOOKY_INSTRUCTION_URL,
            headers=headers,
            json={'type': 'rid_join', 'rid': rid, 'target': version},
            timeout=(3.0, 10.0),
        )
        response.raise_for_status()
        return str(response.json()['trackingId'])
    except requests.HTTPError as e:
        status_code = e.response.status_code if e.response is not None else '?'
        text = e.response.text if e.response is not None else ''
        logger.debug('Looky proxy join HTTP error for rid=%s target=%s: HTTP %s (response: %s)', rid, version, status_code, text)
        raise
    except Exception as e:
        logger.debug('Looky proxy join request error for rid=%s target=%s: %s', rid, version, e)
        raise


def watch_instruction_status(
    context: LookyInstructionContext,
    *,
    should_cancel: Callable[[], bool] | None = None,
    on_reconnect: Callable[[int], None] | None = None,
    on_response: Callable[[requests.Response], None] | None = None,
) -> Generator[tuple[LookyInstructionStatus, str | None]]:
    """Stream SSE status updates for a Looky System instruction until a terminal status arrives.

    Yields `(status, result)` tuples parsed from `status_update` events.
    Stops after the first terminal status (`completed`, `failed`, or `canceled`).

    Servers commonly close SSE streams after a short idle window and expect clients
    to reconnect. This function transparently reconnects to the same `tracking_id`
    URL up to 3 times whenever the stream ends before a terminal status
    is received (including `ChunkedEncodingError`).

    Args:
        context: The instruction context containing the tracking ID, API key, game version, and optional RID.
        should_cancel: Optional predicate polled before each connect and after each event; when it
            returns True the generator stops immediately without raising. Polling only happens between
            reads, so a cancel takes effect once the next event arrives, the stream drops, or the read
            times out (whichever comes first).
        on_reconnect: Optional callback invoked just before each reconnect attempt, receiving the
            1-based attempt number. Called from the streaming thread, not the GUI thread.
        on_response: Optional callback receiving the active streaming response object, allowing callers
            to abort or close the underlying socket immediately when cancelling.

    Raises:
        requests.HTTPError: On a non-2xx response.
        requests.RequestException: On connection/timeout errors after exhausting reconnects.
        pydantic.ValidationError: If an SSE event JSON does not match the expected shape.
    """

    def check_cancel() -> None:
        if should_cancel is not None and should_cancel():
            raise _CancelStreamError

    try:
        check_cancel()

        referer = get_looky_user_url(context.rid) if context.rid is not None else f'{LOOKY_BASE_HOST}/'
        headers = _auth_headers(context.api_key)
        headers['Referer'] = referer

        # The initial status request needs a specific priority and no-cache
        initial_headers = dict(headers)
        initial_headers['Priority'] = 'u=4'
        initial_headers['Pragma'] = 'no-cache'
        initial_headers['Cache-Control'] = 'no-cache'

        try:
            initial_response = session.get(
                f'{LOOKY_INSTRUCTION_STATUS_INITIAL_URL}/{context.tracking_id}',
                headers=initial_headers,
                timeout=(3.0, 10.0),
            )
            initial_response.raise_for_status()
        except requests.HTTPError as e:
            status_code = e.response.status_code if e.response is not None else '?'
            text = e.response.text if e.response is not None else ''
            logger.debug('Looky initial status HTTP error for %s: HTTP %s (response: %s)', context.tracking_id, status_code, text)
            raise
        except Exception as e:
            logger.debug('Looky initial status request error for %s: %s', context.tracking_id, e)
            raise

        initial_data = LookyInstructionStatusInitialResponse.model_validate(initial_response.json())
        yield initial_data.instruction.status, initial_data.instruction.result
        if is_terminal_instruction_status(initial_data.instruction.status):
            return

        max_reconnects = 3
        reconnect_delay = 0
        for attempt in range(max_reconnects + 1):
            check_cancel()
            if attempt > 0:
                if on_reconnect is not None:
                    on_reconnect(attempt)
                time.sleep(reconnect_delay)
            reconnect_delay = 2
            completed = False
            try:
                sse_headers = dict(headers)
                sse_headers['Accept'] = 'text/event-stream'
                sse_headers['Cache-Control'] = 'no-cache'
                sse_headers['Pragma'] = 'no-cache'
                sse_headers['Priority'] = 'u=4'

                with session.get(
                    f'{LOOKY_INSTRUCTION_STATUS_URL}/{context.tracking_id}',
                    headers=sse_headers,
                    params={'token': context.api_key},
                    stream=True,
                    timeout=(3.0, 300.0),
                ) as response:
                    if on_response is not None:
                        on_response(response)
                    response.raise_for_status()
                    for raw_line in response.iter_lines():
                        check_cancel()
                        if not raw_line:
                            continue
                        line = raw_line.decode('utf-8') if isinstance(raw_line, bytes) else raw_line
                        if not line.startswith('data: '):
                            continue
                        event = LookyInstructionStatusEvent.model_validate_json(line[6:])
                        yield event.data.status, event.data.result
                        if is_terminal_instruction_status(event.data.status):
                            completed = True
                            break
            except requests.HTTPError:
                check_cancel()
                logger.exception('HTTP error on SSE stream %s attempt %d/%d', context.tracking_id, attempt + 1, max_reconnects + 1)
                raise
            except requests.RequestException as e:
                check_cancel()
                if attempt >= max_reconnects:
                    raise
                logger.debug('SSE %s disconnected: %s; reconnecting (attempt %d/%d)', context.tracking_id, e, attempt + 1, max_reconnects)
                continue
            if completed:
                return
            if attempt >= max_reconnects:
                message = f'SSE stream for instruction {context.tracking_id!r} ended without a terminal status after {max_reconnects} reconnect attempts'
                raise requests.ConnectionError(message)
    except _CancelStreamError:
        return
