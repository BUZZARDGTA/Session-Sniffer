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
from session_sniffer.text_utils import pluralize

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
    return extract_api_error_message(exc) or 'Too Many Requests'


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
    """Return the number of seconds to wait before retrying after a 429 response, or `None` if not determinable."""
    if exc.response is None:
        return None
    if (retry_after_header := exc.response.headers.get('Retry-After')) is not None and retry_after_header:
        try:
            return max(1, int(float(retry_after_header)))
        except ValueError:
            pass
    try:
        body: object = exc.response.json()
    except requests.JSONDecodeError:
        return None
    if isinstance(body, dict):
        typed_body = cast('dict[str, object]', body)
        for field in ('retryAfter', 'waitSeconds', 'retry_after'):
            value = typed_body.get(field)
            if not isinstance(value, bool) and isinstance(value, (int, float)) and value > 0:
                return max(1, int(value))
        raw_message = typed_body.get('message')
        if isinstance(raw_message, str) and (match := re.search(r'(\d+)\s+second', raw_message)):
            return max(1, int(match.group(1)))
    return None


def verify_token(api_key: str) -> LookyWhoAmI:
    """Verify a Looky System API key via `GET /api/whoami`."""
    response = session.get(LOOKY_WHOAMI_URL, headers=_auth_headers(api_key), timeout=(3.0, 10.0))
    response.raise_for_status()
    return LookyWhoAmI.model_validate(response.json())


_CACHE_LOCK = threading.Lock()
_POSITIVE_RID_CACHE_TTL = 1800.0
_NEGATIVE_RID_CACHE_TTL = 300.0
_PROFILE_CACHE_TTL = 300.0
_IP_BATCH_CACHE_TTL = 300.0
_RID_BY_USERNAME_CF_CACHE: dict[str, tuple[float, int | None]] = {}
_PROFILE_BY_RID_CACHE: dict[int, tuple[float, LookyPlayerProfile | None]] = {}
_IP_PLAYERS_CACHE: dict[tuple[str, str], tuple[float, list[LookyPlayer]]] = {}


def _cache_looky_players(players: list[LookyPlayer]) -> None:
    """Populate `_RID_BY_USERNAME_CF_CACHE` with resolved `(username, rockstarid)` pairs."""
    now = time.monotonic()
    with _CACHE_LOCK:
        for player in players:
            if player.rockstarid > 0 and (stripped_name := player.name.strip()):
                _RID_BY_USERNAME_CF_CACHE[stripped_name.casefold()] = (now, player.rockstarid)


def _get_cached_rid_for_username(name_cf: str, now: float) -> tuple[bool, int | None]:
    """Return `(is_cached, rid)` from `_RID_BY_USERNAME_CF_CACHE` if still within TTL (caller must hold `_CACHE_LOCK`)."""
    if (cached_entry := _RID_BY_USERNAME_CF_CACHE.get(name_cf)) is None:
        return False, None
    cached_at, cached_rid = cached_entry
    if now - cached_at < (_POSITIVE_RID_CACHE_TTL if cached_rid is not None else _NEGATIVE_RID_CACHE_TTL):
        return True, cached_rid
    del _RID_BY_USERNAME_CF_CACHE[name_cf]
    return False, None


def lookup_ip(ip: str, api_key: str, version: str = 'both') -> list[LookyPlayer]:
    """Query the Looky System API for players associated with `ip`."""
    response = session.get(f'{LOOKY_SEARCH_URL}/{ip}', headers=_auth_headers(api_key), params={'version': version}, timeout=(3.0, 10.0))
    response.raise_for_status()
    results = _RESPONSE_ADAPTER.validate_json(response.content)
    _cache_looky_players(results)
    sorted_players = _sort_looky_players(results)
    with _CACHE_LOCK:
        _IP_PLAYERS_CACHE[(ip, version)] = (time.monotonic(), sorted_players)
    return sorted_players


def _sort_looky_players(players: list[LookyPlayer]) -> list[LookyPlayer]:
    """Sort Looky players from most recent to oldest by `last_seen`."""
    return sorted(
        players,
        key=lambda player: player.last_seen.astimezone(UTC) if player.last_seen.tzinfo is not None else player.last_seen.replace(tzinfo=UTC),
        reverse=True,
    )


def lookup_ip_batch(ip_addresses: list[str], api_key: str, version: str = 'both') -> dict[str, list[LookyPlayer]]:
    """Query the Looky System batch endpoint for players associated with multiple IPs in one request (max 32 per call)."""
    response = session.post(LOOKY_SEARCH_IP_BATCH_URL, headers=_json_auth_headers(api_key), json={'ips': ip_addresses, 'version': version}, timeout=(3.0, 12.0))
    response.raise_for_status()
    parsed = _BATCH_RESPONSE_ADAPTER.validate_json(response.content)
    for item in parsed:
        _cache_looky_players(item.players)
    results_by_ip = {item.ip: _sort_looky_players(item.players) for item in parsed}
    fetched_at = time.monotonic()
    with _CACHE_LOCK:
        for ip in ip_addresses:
            _IP_PLAYERS_CACHE[(ip, version)] = (fetched_at, results_by_ip.get(ip, []))
    return results_by_ip


_AUTH_HTTP_STATUSES = frozenset({HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN})
_NOT_FOUND_SEARCH_STATUSES = frozenset({HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND, HTTPStatus.INTERNAL_SERVER_ERROR})
_MIN_USERNAME_SEARCH_LEN = 2
_IP_BATCH_SIZE = 32
_IP_BATCH_MAX_WORKERS = 4
_IP_BATCH_MIN_INTERVAL = 0.20
_USERNAME_LOOKUP_MAX_WORKERS = 6
_USERNAME_SEARCH_MIN_INTERVAL = 0.25
_PROFILE_LOOKUP_MAX_WORKERS = 4
_PROFILE_FETCH_MIN_INTERVAL = 0.15
_MAX_TRANSIENT_RETRIES = 4
_DEFAULT_RATE_LIMIT_FALLBACK_SECONDS = 15
_MAX_RATE_LIMIT_FALLBACK_SECONDS = 120
_RATE_LIMIT_SAFETY_BUFFER_SECONDS = 1.0
_RATE_LIMIT_LOG_INTERVAL_SECONDS = 15
_FINAL_COUNTDOWN_LOG_THRESHOLD = 5


def get_rid_by_username(username: str, api_key: str) -> int | None:
    """Resolve `username` to its Rockstar ID via `GET /api/search/{username}` exact case-insensitive match."""
    stripped = username.strip()
    if len(stripped) < _MIN_USERNAME_SEARCH_LEN:
        return None
    name_cf = stripped.casefold()
    now = time.monotonic()
    with _CACHE_LOCK:
        is_cached, cached_rid = _get_cached_rid_for_username(name_cf, now)
        if is_cached:
            return cached_rid
    headers = {**_auth_headers(api_key), 'Referer': f'{LOOKY_BASE_HOST}/'}
    response = session.get(f'{LOOKY_SEARCH_URL}/{quote(stripped, safe="")}', headers=headers, params={'version': 'both'}, timeout=(3.0, 12.0))
    if response.status_code in _NOT_FOUND_SEARCH_STATUSES:
        with _CACHE_LOCK:
            _RID_BY_USERNAME_CF_CACHE[name_cf] = (time.monotonic(), None)
        return None
    response.raise_for_status()
    results = _RESPONSE_ADAPTER.validate_json(response.content)
    _cache_looky_players(results)
    resolved_rid = next((player.rockstarid for player in results if player.name.strip().casefold() == name_cf and player.rockstarid > 0), None)
    with _CACHE_LOCK:
        _RID_BY_USERNAME_CF_CACHE[name_cf] = (time.monotonic(), resolved_rid)
    return resolved_rid


def lookup_player_by_rid(rid: int, api_key: str) -> LookyPlayerProfile | None:
    """Query `GET /api/player/{rid}` for a player's profile and session IP history."""
    now = time.monotonic()
    with _CACHE_LOCK:
        if (cached_entry := _PROFILE_BY_RID_CACHE.get(rid)) is not None:
            cached_at, cached_profile = cached_entry
            if now - cached_at < _PROFILE_CACHE_TTL:
                return cached_profile
            del _PROFILE_BY_RID_CACHE[rid]
    headers = {**_auth_headers(api_key), 'Referer': get_looky_user_url(rid)}
    response = session.get(f'{LOOKY_PLAYER_URL}/{rid}', headers=headers, timeout=(3.0, 12.0))
    if response.status_code == HTTPStatus.NOT_FOUND:
        with _CACHE_LOCK:
            _PROFILE_BY_RID_CACHE[rid] = (time.monotonic(), None)
        return None
    response.raise_for_status()
    profile = LookyPlayerProfile.model_validate_json(response.content)
    resolved_rid = profile.rockstarid or rid
    fetched_at = time.monotonic()
    with _CACHE_LOCK:
        _PROFILE_BY_RID_CACHE[rid] = (fetched_at, profile)
        if resolved_rid > 0:
            for sighting in profile.users_by_rockstar_id:
                if stripped_name := sighting.name.strip():
                    _RID_BY_USERNAME_CF_CACHE[stripped_name.casefold()] = (fetched_at, resolved_rid)
    return profile


def _is_valid_player_ipv4(ip: str) -> bool:
    """Return True if `ip` is a valid single IPv4 address that is not a third-party server."""
    try:
        IPv4Address(ip)
    except ValueError:
        return False
    return not is_third_party_server_ip(ip)


def _sleep_with_cancel(duration: float, should_cancel: Callable[[], bool] | None) -> bool:
    """Sleep for `duration` seconds in short intervals, returning `False` immediately if canceled."""
    deadline = time.monotonic() + duration
    while (remaining := deadline - time.monotonic()) > 0:
        if should_cancel is not None and should_cancel():
            return False
        time.sleep(min(0.2, remaining))
    return should_cancel is None or not should_cancel()


@dataclass(frozen=True, slots=True)
class _RateLimitPhase:
    """Configuration and progress callbacks for one paced Looky API lookup phase."""

    label: str
    min_interval: float
    total_count: int
    should_cancel: Callable[[], bool] | None = None
    on_progress: Callable[[str, int, int], None] | None = None
    raise_on_exhaustion: bool = False


class _LookyRateLimiter:
    """Thread-safe coordinator for pacing Looky API requests and waiting out HTTP 429 cooldowns."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cooldown_until: float = 0.0
        self._next_dispatch_at: float = 0.0
        self._consecutive_rate_limits: int = 0
        self._total_rate_limit_hits: int = 0
        self._last_reported_remaining_sec: int = -1
        self._cooldown_active_logged: bool = False

    def record_success(self) -> None:
        """Reset the consecutive fallback rate-limit counter after a successful response."""
        with self._lock:
            if self._consecutive_rate_limits > 0 and time.monotonic() >= self._cooldown_until:
                self._consecutive_rate_limits = 0

    def record_rate_limit(self, exc: requests.HTTPError, *, context_label: str) -> int:
        """Record an HTTP 429 response, extend the shared cooldown deadline, and return wait seconds."""
        extracted_wait = extract_rate_limit_wait_seconds(exc)
        rate_limit_message = extract_rate_limit_message(exc)
        now = time.monotonic()
        with self._lock:
            self._total_rate_limit_hits += 1
            if extracted_wait is not None:
                wait_seconds = extracted_wait
            else:
                self._consecutive_rate_limits += 1
                wait_seconds = min(_DEFAULT_RATE_LIMIT_FALLBACK_SECONDS * (2 ** (self._consecutive_rate_limits - 1)), _MAX_RATE_LIMIT_FALLBACK_SECONDS)
            new_deadline = now + wait_seconds + _RATE_LIMIT_SAFETY_BUFFER_SECONDS
            extended_existing = new_deadline > self._cooldown_until + 1.5
            self._cooldown_until = max(self._cooldown_until, new_deadline)
            self._next_dispatch_at = max(self._next_dispatch_at, self._cooldown_until)
            remaining_total = max(1, math.ceil(self._cooldown_until - now))
            if extended_existing:
                self._last_reported_remaining_sec = remaining_total
                self._cooldown_active_logged = True

        if extended_existing:
            logger.warning(
                '[Looky System] Rate limited (HTTP 429) on %s: "%s". Waiting %d second%s before retrying (no items will be skipped).',
                context_label, rate_limit_message, remaining_total, pluralize(remaining_total),
            )
        else:
            logger.debug('[Looky System] Concurrent in-flight request also hit HTTP 429 on %s; already waiting %ds for active cooldown.', context_label, remaining_total)
        return remaining_total

    def wait_and_acquire_slot(self, phase: _RateLimitPhase, current_completed: int) -> bool:
        """Wait out any active HTTP 429 cooldown and reserve a paced request dispatch slot."""
        while True:
            if phase.should_cancel is not None and phase.should_cancel():
                return False

            now = time.monotonic()
            with self._lock:
                cooldown_remaining = self._cooldown_until - now
                if cooldown_remaining <= 0:
                    was_cooling_down = self._cooldown_active_logged
                    self._cooldown_active_logged = False
                    self._last_reported_remaining_sec = -1
                    slot_time = max(now, self._next_dispatch_at)
                    self._next_dispatch_at = slot_time + phase.min_interval
                    slot_wait = slot_time - now
                    remaining_sec = 0
                    should_report_tick = False
                else:
                    was_cooling_down = False
                    slot_wait = 0.0
                    remaining_sec = max(1, math.ceil(cooldown_remaining))
                    should_report_tick = remaining_sec != self._last_reported_remaining_sec
                    if should_report_tick:
                        self._last_reported_remaining_sec = remaining_sec

            if cooldown_remaining > 0:
                if should_report_tick:
                    if phase.on_progress is not None and phase.label and phase.total_count > 0:
                        phase.on_progress(f'{phase.label} (rate limited \u2014 resuming in {remaining_sec}s)', current_completed, phase.total_count)
                    if not remaining_sec % _RATE_LIMIT_LOG_INTERVAL_SECONDS or remaining_sec <= _FINAL_COUNTDOWN_LOG_THRESHOLD:
                        logger.info(
                            '[Looky System] Rate-limit cooldown active for "%s": %d second%s remaining (%d/%d completed)...',
                            phase.label or 'Looky API', remaining_sec, pluralize(remaining_sec), current_completed, phase.total_count,
                        )
                time.sleep(min(0.2, cooldown_remaining))
                continue

            if was_cooling_down and phase.label:
                logger.info('[Looky System] Rate-limit cooldown finished for "%s". Resuming requests (%d/%d completed).', phase.label, current_completed, phase.total_count)
                if phase.on_progress is not None and phase.total_count > 0:
                    phase.on_progress(phase.label, current_completed, phase.total_count)

            if slot_wait > 0:
                slot_deadline = time.monotonic() + slot_wait
                re_enter_cooldown = False
                while (remaining_slot := slot_deadline - time.monotonic()) > 0:
                    if phase.should_cancel is not None and phase.should_cancel():
                        return False
                    with self._lock:
                        if self._cooldown_until > time.monotonic():
                            re_enter_cooldown = True
                            break
                    time.sleep(min(0.05, remaining_slot))
                if re_enter_cooldown:
                    continue

            return phase.should_cancel is None or not phase.should_cancel()

    def execute_with_retry[T](self, request_fn: Callable[[], T], phase: _RateLimitPhase, current_completed: int, context_label: str) -> tuple[str, T | None, float]:
        """Execute `request_fn` with slot pacing, infinite 429 cooldown retries, and bounded transient retries."""
        transient_attempts = 0
        while True:
            if not self.wait_and_acquire_slot(phase, current_completed):
                return 'canceled', None, 0.0
            req_started_at = time.monotonic()
            try:
                result = request_fn()
            except requests.RequestException as e:
                if isinstance(e, requests.HTTPError) and e.response is not None:
                    if e.response.status_code in _AUTH_HTTP_STATUSES:
                        raise
                    if e.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                        self.record_rate_limit(e, context_label=context_label)
                        continue
                transient_attempts += 1
                if transient_attempts > _MAX_TRANSIENT_RETRIES:
                    logger.warning('[Looky System] Request failed for %s after %d transient errors: %s', context_label, _MAX_TRANSIENT_RETRIES, e)
                    if phase.raise_on_exhaustion:
                        raise
                    return 'failed', None, 0.0
                backoff_seconds = min(1.0 * (2 ** (transient_attempts - 1)), 8.0)
                logger.warning(
                    '[Looky System] Transient error on %s (attempt %d/%d): %s. Retrying in %.1fs.',
                    context_label, transient_attempts, _MAX_TRANSIENT_RETRIES, e, backoff_seconds,
                )
                if not _sleep_with_cancel(backoff_seconds, phase.should_cancel):
                    return 'canceled', None, 0.0
            else:
                self.record_success()
                return 'ok', result, time.monotonic() - req_started_at


_RATE_LIMITER = _LookyRateLimiter()

LOOKY_PHASE_IP_BATCHES = 'Looking up database IPs'
LOOKY_PHASE_RESOLVE_USERNAMES = 'Resolving usernames to Rockstar IDs'
LOOKY_PHASE_PLAYER_PROFILES = 'Looking up IPs & usernames for resolved Rockstar IDs'


def lookup_ip_batches(
    ip_addresses: list[str],
    api_key: str,
    version: str = 'both',
    *,
    should_cancel: Callable[[], bool] | None = None,
    on_progress: Callable[[str, int, int], None] | None = None,
) -> dict[str, list[LookyPlayer]]:
    """Look up multiple IPv4 addresses in paced batches of 32 with caching and automatic 429 retry."""
    unique_ips = list(dict.fromkeys(ip for ip in ip_addresses if _is_valid_player_ipv4(ip)))
    if not unique_ips:
        return {}

    combined_results: dict[str, list[LookyPlayer]] = {}
    ips_to_query: list[str] = []
    now = time.monotonic()
    with _CACHE_LOCK:
        for ip in unique_ips:
            cached_entry = _IP_PLAYERS_CACHE.get((ip, version))
            if cached_entry is not None:
                cached_at, cached_players = cached_entry
                if now - cached_at < _IP_BATCH_CACHE_TTL:
                    if cached_players:
                        combined_results[ip] = cached_players
                    continue
                del _IP_PLAYERS_CACHE[(ip, version)]
            ips_to_query.append(ip)

    cached_count = len(unique_ips) - len(ips_to_query)
    batches = [ips_to_query[i : i + _IP_BATCH_SIZE] for i in range(0, len(ips_to_query), _IP_BATCH_SIZE)]
    total_batches = len(batches)
    logger.info(
        '[Looky System] Starting IP batch lookup: %d unique IPv4%s (%d cached, %d to query in %d batch%s, version=%s).',
        len(unique_ips), pluralize(len(unique_ips)), cached_count, len(ips_to_query), total_batches, pluralize(total_batches, plural='es'), version,
    )

    if not batches:
        if on_progress is not None:
            on_progress(LOOKY_PHASE_IP_BATCHES, 1, 1)
        return combined_results

    if on_progress is not None:
        on_progress(LOOKY_PHASE_IP_BATCHES, 0, total_batches)

    started_at = time.monotonic()
    completed_holder = [0]
    phase = _RateLimitPhase(LOOKY_PHASE_IP_BATCHES, _IP_BATCH_MIN_INTERVAL, total_batches, should_cancel, on_progress, raise_on_exhaustion=True)

    def _lookup_one_batch(batch_index: int, batch_ips: list[str]) -> dict[str, list[LookyPlayer]]:
        status, batch_result, elapsed = _RATE_LIMITER.execute_with_retry(
            lambda: lookup_ip_batch(batch_ips, api_key, version),
            phase,
            completed_holder[0],
            f'IP batch {batch_index}/{total_batches} ({len(batch_ips)} IPs)',
        )
        if status != 'ok' or batch_result is None:
            return {}
        matched_in_batch = sum(1 for players in batch_result.values() if players)
        logger.debug(
            '[Looky System] IP batch %d/%d (%d IPs) completed in %.2fs: %d IP%s matched.',
            batch_index, total_batches, len(batch_ips), elapsed, matched_in_batch, pluralize(matched_in_batch),
        )
        return batch_result

    with ThreadPoolExecutor(max_workers=min(_IP_BATCH_MAX_WORKERS, total_batches)) as executor:
        futures = [executor.submit(_lookup_one_batch, idx, batch) for idx, batch in enumerate(batches, start=1)]
        for future in as_completed(futures):
            batch_result = future.result()
            completed_holder[0] += 1
            completed = completed_holder[0]
            if on_progress is not None:
                on_progress(LOOKY_PHASE_IP_BATCHES, completed, total_batches)
            if should_cancel is not None and should_cancel():
                return {}
            combined_results.update({ip: players for ip, players in batch_result.items() if players})
            if not completed % 10 or completed == total_batches:
                logger.info(
                    '[Looky System] IP batch progress: %d/%d batches (%d%%) completed (%d IP%s matched so far, %.1fs elapsed).',
                    completed, total_batches, round(completed * 100 / total_batches), len(combined_results), pluralize(len(combined_results)), time.monotonic() - started_at,
                )

    total_players = sum(len(players) for players in combined_results.values())
    logger.info(
        '[Looky System] Finished IP batch lookup in %.2fs: %d/%d IP%s matched (%d player record%s).',
        time.monotonic() - started_at, len(combined_results), len(unique_ips), pluralize(len(unique_ips)), total_players, pluralize(total_players),
    )
    return combined_results


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
    cached_positive_count = 0
    cached_negative_count = 0
    now = time.monotonic()
    with _CACHE_LOCK:
        for raw_username in usernames:
            stripped = raw_username.strip()
            name_cf = stripped.casefold()
            if len(stripped) < _MIN_USERNAME_SEARCH_LEN or name_cf == 'n/a' or name_cf in seen_username_cfs:
                continue
            seen_username_cfs.add(name_cf)
            is_cached, cached_rid = _get_cached_rid_for_username(name_cf, now)
            if is_cached:
                if cached_rid is not None and cached_rid > 0:
                    usernames_by_rid[cached_rid].append(stripped)
                    cached_positive_count += 1
                else:
                    cached_negative_count += 1
            else:
                usernames_to_query.append(stripped)

    total_unique = len(seen_username_cfs)
    total_to_query = len(usernames_to_query)
    logger.info(
        '[Looky System] Starting username-to-RID resolution: %d unique username%s (%d cached resolved, %d cached not-found, %d to query via API).',
        total_unique, pluralize(total_unique), cached_positive_count, cached_negative_count, total_to_query,
    )

    if not usernames_to_query:
        return usernames_by_rid

    if on_progress is not None:
        on_progress(LOOKY_PHASE_RESOLVE_USERNAMES, 0, total_to_query)

    started_at = time.monotonic()
    completed_holder = [0]
    api_resolved_count = 0
    api_not_found_count = 0
    api_failed_count = 0
    phase = _RateLimitPhase(LOOKY_PHASE_RESOLVE_USERNAMES, _USERNAME_SEARCH_MIN_INTERVAL, total_to_query, should_cancel, on_progress)

    def _resolve_one(name: str) -> tuple[str, int | None, bool]:
        status, resolved_rid, elapsed = _RATE_LIMITER.execute_with_retry(
            lambda: get_rid_by_username(name, api_key),
            phase,
            completed_holder[0],
            f'username={name!r}',
        )
        if status == 'ok':
            if resolved_rid is not None and resolved_rid > 0:
                logger.info('[Looky System] Resolved username %r -> Rockstar ID %d (%.2fs).', name, resolved_rid, elapsed)
            else:
                logger.debug('[Looky System] Username %r is not indexed in Looky (%.2fs).', name, elapsed)
        return name, resolved_rid, status == 'failed'

    with ThreadPoolExecutor(max_workers=min(_USERNAME_LOOKUP_MAX_WORKERS, total_to_query)) as executor:
        futures = [executor.submit(_resolve_one, name) for name in usernames_to_query]
        for future in as_completed(futures):
            name, resolved_rid, had_transient_failure = future.result()
            completed_holder[0] += 1
            completed = completed_holder[0]
            if on_progress is not None:
                on_progress(LOOKY_PHASE_RESOLVE_USERNAMES, completed, total_to_query)
            if should_cancel is not None and should_cancel():
                return {}
            if resolved_rid is not None and resolved_rid > 0:
                usernames_by_rid[resolved_rid].append(name)
                api_resolved_count += 1
            elif had_transient_failure:
                api_failed_count += 1
            else:
                api_not_found_count += 1
            if not completed % 25 or completed == total_to_query:
                logger.info(
                    '[Looky System] Username resolution progress: %d/%d (%d%%) queried (%d resolved, %d not indexed, %d failed, %.1fs elapsed).',
                    completed, total_to_query, round(completed * 100 / total_to_query), api_resolved_count, api_not_found_count,
                    api_failed_count, time.monotonic() - started_at,
                )

    logger.info(
        '[Looky System] Finished username-to-RID resolution in %.2fs: %d Rockstar ID%s resolved (%d from cache, %d from API, %d not indexed, %d failed).',
        time.monotonic() - started_at, len(usernames_by_rid), pluralize(len(usernames_by_rid)), cached_positive_count, api_resolved_count,
        cached_negative_count + api_not_found_count, api_failed_count,
    )
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
    unique_rids = list(dict.fromkeys(rids))
    profiles_by_rid: dict[int, LookyPlayerProfile] = {}
    rids_to_query: list[int] = []
    now = time.monotonic()
    with _CACHE_LOCK:
        for target_rid in unique_rids:
            cached_entry = _PROFILE_BY_RID_CACHE.get(target_rid)
            if cached_entry is not None:
                cached_at, cached_profile = cached_entry
                if now - cached_at < _PROFILE_CACHE_TTL:
                    if cached_profile is not None:
                        profiles_by_rid[target_rid] = cached_profile
                    continue
                del _PROFILE_BY_RID_CACHE[target_rid]
            rids_to_query.append(target_rid)

    total_to_query = len(rids_to_query)
    logger.info(
        '[Looky System] Starting player profile fetch: %d Rockstar ID%s (%d cached, %d to query via API).',
        len(unique_rids), pluralize(len(unique_rids)), len(unique_rids) - total_to_query, total_to_query,
    )

    if not rids_to_query:
        if on_progress is not None:
            on_progress(LOOKY_PHASE_PLAYER_PROFILES, 1, 1)
        return profiles_by_rid

    if on_progress is not None:
        on_progress(LOOKY_PHASE_PLAYER_PROFILES, 0, total_to_query)

    started_at = time.monotonic()
    completed_holder = [0]
    phase = _RateLimitPhase(LOOKY_PHASE_PLAYER_PROFILES, _PROFILE_FETCH_MIN_INTERVAL, total_to_query, should_cancel, on_progress)

    def _fetch_one(target_rid: int) -> tuple[int, LookyPlayerProfile | None]:
        status, profile, elapsed = _RATE_LIMITER.execute_with_retry(
            lambda: lookup_player_by_rid(target_rid, api_key),
            phase,
            completed_holder[0],
            f'rid={target_rid}',
        )
        if status == 'ok':
            if profile is not None:
                sightings_count = len(profile.users_by_rockstar_id)
                logger.info(
                    '[Looky System] Fetched profile for rid=%d in %.2fs (%d sighting%s, is_modder=%s).',
                    target_rid, elapsed, sightings_count, pluralize(sightings_count), profile.is_modder,
                )
            else:
                logger.debug('[Looky System] No profile found for rid=%d (%.2fs).', target_rid, elapsed)
        return target_rid, profile

    with ThreadPoolExecutor(max_workers=min(_PROFILE_LOOKUP_MAX_WORKERS, total_to_query)) as executor:
        futures = [executor.submit(_fetch_one, target_rid) for target_rid in rids_to_query]
        for future in as_completed(futures):
            target_rid, profile = future.result()
            completed_holder[0] += 1
            completed = completed_holder[0]
            if on_progress is not None:
                on_progress(LOOKY_PHASE_PLAYER_PROFILES, completed, total_to_query)
            if should_cancel is not None and should_cancel():
                return {}
            if profile is not None:
                profiles_by_rid[target_rid] = profile

    logger.info(
        '[Looky System] Finished player profile fetch in %.2fs: %d/%d profile%s retrieved.',
        time.monotonic() - started_at, len(profiles_by_rid), len(unique_rids), pluralize(len(unique_rids)),
    )
    return profiles_by_rid


def lookup_username_ips(
    usernames: list[str],
    api_key: str,
    version: str = 'both',
    *,
    should_cancel: Callable[[], bool] | None = None,
    on_progress: Callable[[str, int, int], None] | None = None,
) -> tuple[dict[str, list[LookyPlayer]], dict[str, list[str]]]:
    """Resolve `usernames` to Rockstar IDs and fetch their recorded session IPs via `GET /api/player/{rid}`."""
    usernames_by_rid = _resolve_usernames_to_rids(usernames, api_key, should_cancel=should_cancel, on_progress=on_progress)
    if (should_cancel is not None and should_cancel()) or not usernames_by_rid:
        return {}, {}
    profiles_by_rid = _fetch_profiles_by_rid(list(usernames_by_rid), api_key, should_cancel=should_cancel, on_progress=on_progress)
    if should_cancel is not None and should_cancel():
        return {}, {}

    players_by_ip, seen_names_by_ip = defaultdict[str, list[LookyPlayer]](list), defaultdict[str, set[str]](set)
    ips_by_username_cf, seen_ips_by_username_cf = defaultdict[str, list[str]](list), defaultdict[str, set[str]](set)

    for rid, rid_usernames in usernames_by_rid.items():
        if (profile := profiles_by_rid.get(rid)) is None:
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
                            rockstarid=resolved_rid, name=candidate_name, last_seen=sighting.datetimestamp, last_country=sighting.country,
                            is_modder=profile.is_modder, is_enhanced=sighting.enhanced, is_legacy=not sighting.enhanced, is_vpn=sighting.vpn,
                        ),
                    )

    logger.info(
        '[Looky System] Username IP history resolution complete: %d username%s mapped to %d unique IPv4 address%s.',
        len(ips_by_username_cf), pluralize(len(ips_by_username_cf)), len(players_by_ip), pluralize(len(players_by_ip), plural='es'),
    )
    return dict(players_by_ip), dict(ips_by_username_cf)


def _post_instruction(url: str, api_key: str, referer: str, payload: dict[str, object], context_desc: str) -> str:
    """POST an instruction payload to Looky and return the resulting `'trackingId'`."""
    headers = {**_json_auth_headers(api_key), 'Referer': referer}
    try:
        response = session.post(url, headers=headers, json=payload, timeout=(3.0, 10.0))
        response.raise_for_status()
        return str(response.json()['trackingId'])
    except requests.HTTPError as e:
        status_code = e.response.status_code if e.response is not None else '?'
        text = e.response.text if e.response is not None else ''
        logger.debug('Looky %s HTTP error: HTTP %s (response: %s)', context_desc, status_code, text)
        raise
    except (requests.RequestException, ValueError, KeyError) as e:
        logger.debug('Looky %s request error: %s', context_desc, e)
        raise


def send_crawlme_instruction(api_key: str, version: str) -> str:
    """POST a crawlme instruction to the Looky System API to request the crawler for the current session."""
    return _post_instruction(LOOKY_CRAWLME_URL, api_key, 'https://looky-gta.cc/', {'target': version}, f'crawlme for target={version}')


def send_crawler_instruction(rid: int, api_key: str, version: str) -> str:
    """POST a join instruction to the Looky System API to call the crawler bot for `rid`."""
    return _post_instruction(
        LOOKY_INSTRUCTION_URL, api_key, get_looky_user_url(rid), {'type': 'join', 'rid': rid, 'target': version}, f'crawler for rid={rid} target={version}',
    )


def send_proxy_join_instruction(rid: int, api_key: str, version: str) -> str:
    """POST an `rid_join` instruction to the Looky System API to call the proxy join bot for `rid`."""
    return _post_instruction(
        LOOKY_INSTRUCTION_URL, api_key, get_looky_user_url(rid), {'type': 'rid_join', 'rid': rid, 'target': version}, f'proxy join for rid={rid} target={version}',
    )


def watch_instruction_status(
    context: LookyInstructionContext,
    *,
    should_cancel: Callable[[], bool] | None = None,
    on_reconnect: Callable[[int], None] | None = None,
    on_response: Callable[[requests.Response], None] | None = None,
) -> Generator[tuple[LookyInstructionStatus, str | None]]:
    """Stream SSE status updates for a Looky System instruction until a terminal status arrives."""

    def check_cancel() -> None:
        if should_cancel is not None and should_cancel():
            raise _CancelStreamError

    try:
        check_cancel()
        referer = get_looky_user_url(context.rid) if context.rid is not None else f'{LOOKY_BASE_HOST}/'
        headers = {**_auth_headers(context.api_key), 'Referer': referer}
        initial_headers = {**headers, 'Priority': 'u=4', 'Pragma': 'no-cache', 'Cache-Control': 'no-cache'}

        try:
            initial_response = session.get(f'{LOOKY_INSTRUCTION_STATUS_INITIAL_URL}/{context.tracking_id}', headers=initial_headers, timeout=(3.0, 10.0))
            initial_response.raise_for_status()
        except requests.HTTPError as e:
            status_code = e.response.status_code if e.response is not None else '?'
            text = e.response.text if e.response is not None else ''
            logger.debug('Looky initial status HTTP error for %s: HTTP %s (response: %s)', context.tracking_id, status_code, text)
            raise
        except requests.RequestException as e:
            logger.debug('Looky initial status request error for %s: %s', context.tracking_id, e)
            raise

        initial_data = LookyInstructionStatusInitialResponse.model_validate(initial_response.json())
        yield initial_data.instruction.status, initial_data.instruction.result
        if is_terminal_instruction_status(initial_data.instruction.status):
            return

        max_reconnects, reconnect_delay = 3, 0
        for attempt in range(max_reconnects + 1):
            check_cancel()
            if attempt > 0:
                if on_reconnect is not None:
                    on_reconnect(attempt)
                if not _sleep_with_cancel(reconnect_delay, should_cancel):
                    return
            reconnect_delay, completed = 2, False
            try:
                sse_headers = {**headers, 'Accept': 'text/event-stream', 'Cache-Control': 'no-cache', 'Pragma': 'no-cache', 'Priority': 'u=4'}
                with session.get(
                    f'{LOOKY_INSTRUCTION_STATUS_URL}/{context.tracking_id}', headers=sse_headers, params={'token': context.api_key}, stream=True, timeout=(3.0, 300.0),
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
