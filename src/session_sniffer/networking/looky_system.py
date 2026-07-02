"""Looky System IP-to-player lookup API client."""

import re
import time
from typing import TYPE_CHECKING, ClassVar

import requests
from pydantic import TypeAdapter

from session_sniffer.constants.standalone import LOOKY_BASE_HOST
from session_sniffer.logging_setup import get_logger
from session_sniffer.models.looky_system import (
    LookyInstructionStatus,
    LookyInstructionStatusEvent,
    LookyIpBatchResult,
    LookyPlayer,
    LookyUserData,
    LookyVerifyResponse,
    LookyWhoAmI,
)
from session_sniffer.networking.http_session import session

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

logger = get_logger(__name__)

LOOKY_BASE_URL = f'{LOOKY_BASE_HOST}/api/search'
LOOKY_BATCH_URL = f'{LOOKY_BASE_HOST}/api/search/ip-batch'
LOOKY_WHOAMI_URL = f'{LOOKY_BASE_HOST}/api/whoami'
LOOKY_INSTRUCTION_URL = f'{LOOKY_BASE_HOST}/api/instruction'
LOOKY_CRAWLME_URL = f'{LOOKY_BASE_HOST}/api/instruction/crawlme'
LOOKY_SSE_URL = f'{LOOKY_BASE_HOST}/api/sse/instruction-status'

_RESPONSE_ADAPTER: TypeAdapter[list[LookyPlayer]] = TypeAdapter(list[LookyPlayer])
_BATCH_RESPONSE_ADAPTER: TypeAdapter[list[LookyIpBatchResult]] = TypeAdapter(list[LookyIpBatchResult])

_TERMINAL_INSTRUCTION_STATUSES = frozenset({'completed', 'failed', 'canceled'})
_TERMINAL_FAILURE_INSTRUCTION_STATUSES = frozenset({'failed', 'canceled'})


class LookyState:
    """Runtime-only Looky System state derived from token verification.

    Not persisted to `Settings.ini` — populated by the `looky_core` background thread
    and read by the GUI to gate Looky-related actions.
    """

    api_access: ClassVar[bool] = False
    user_data: ClassVar[LookyVerifyResponse | None] = None

    @classmethod
    def reset(cls) -> None:
        """Clear verified state (used when no/invalid API key, on errors, or when Looky is disabled)."""
        cls.api_access = False
        cls.user_data = None

    @classmethod
    def set(cls, response: LookyVerifyResponse) -> None:
        """Apply a successful token-verification response."""
        cls.api_access = response.userData.apiAccess
        cls.user_data = response


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


def is_terminal_instruction_status(status: str) -> bool:
    """Return `True` if the instruction status marks the end of tracking."""
    return status.strip().lower() in _TERMINAL_INSTRUCTION_STATUSES


def is_terminal_failure_instruction_status(status: str) -> bool:
    """Return `True` if the instruction status is a terminal failure."""
    return status.strip().lower() in _TERMINAL_FAILURE_INSTRUCTION_STATUSES


def extract_rate_limit_wait_seconds(exc: requests.HTTPError, default: int = 60) -> int:
    """Return the number of seconds to wait before retrying after a 429 response.

    Checks in priority order:
    1. `Retry-After` response header (standard HTTP).
    2. Numeric JSON body fields: `retryAfter`, `waitSeconds`, `retry_after`.
    3. First integer found in the JSON `message` field.
    4. `default` (60 seconds).
    """
    if exc.response is None:
        return default
    retry_after_header = exc.response.headers.get('Retry-After')
    if retry_after_header:
        try:
            return max(1, int(float(retry_after_header)))
        except ValueError:
            pass
    try:
        body = exc.response.json()
    except requests.JSONDecodeError:
        return default
    for field in ('retryAfter', 'waitSeconds', 'retry_after'):
        value = body.get(field)
        if isinstance(value, (int, float)) and value > 0:
            return max(1, int(value))
    message = body.get('message', '')
    match = re.search(r'(\d+)\s+second', str(message))
    if match:
        return max(1, int(match.group(1)))
    return default


def verify_token(api_key: str) -> LookyVerifyResponse:
    """Verify a Looky System API key via `GET /api/whoami`.

    Args:
        api_key: Looky System Bearer API key.

    Returns:
        `LookyVerifyResponse` with `userData` populated from the API response.

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
    whoami = LookyWhoAmI.model_validate(response.json())
    return LookyVerifyResponse(
        success=True,
        userData=LookyUserData(username=whoami.username, apiAccess=whoami.apiAccess, status=whoami.status, rid=whoami.rid),
    )


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
    url = f'{LOOKY_BASE_URL}/{ip}'
    response = session.get(url, headers=_auth_headers(api_key), params={'version': version}, timeout=(3.0, 10.0))
    response.raise_for_status()
    return _RESPONSE_ADAPTER.validate_json(response.content)


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
        LOOKY_BATCH_URL,
        headers=_json_auth_headers(api_key),
        json={'ips': ip_addresses, 'version': version},
        timeout=(3.0, 10.0),
    )
    response.raise_for_status()
    parsed = _BATCH_RESPONSE_ADAPTER.validate_json(response.content)
    return {item.ip: item.players for item in parsed}


def send_crawlme_instruction(api_key: str) -> str:
    """POST a crawlme instruction to the Looky System API to request the crawler for the current session.

    Args:
        api_key: Looky System Bearer API key.

    Returns:
        The instruction tracking ID (UUID string) for polling status via `watch_instruction_status`.

    Raises:
        requests.HTTPError: On a non-2xx response.
        requests.RequestException: On connection/timeout errors.
        KeyError: If the response JSON does not contain a `'trackingId'` field.
    """
    response = session.post(LOOKY_CRAWLME_URL, headers=_json_auth_headers(api_key), timeout=(3.0, 10.0))
    response.raise_for_status()
    return str(response.json()['trackingId'])


def send_crawler_instruction(rid: int, api_key: str) -> str:
    """POST a join instruction to the Looky System API to call the crawler bot for `rid`.

    Args:
        rid: The Rockstar player ID to request the crawler for.
        api_key: Looky System Bearer API key.

    Returns:
        The instruction tracking ID (UUID string) for polling status via `watch_instruction_status`.

    Raises:
        requests.HTTPError: On a non-2xx response.
        requests.RequestException: On connection/timeout errors.
        KeyError: If the response JSON does not contain a `'trackingId'` field.
    """
    response = session.post(
        LOOKY_INSTRUCTION_URL,
        headers=_json_auth_headers(api_key),
        json={'type': 'join', 'rid': rid},
        timeout=(3.0, 10.0),
    )
    response.raise_for_status()
    return str(response.json()['trackingId'])


def watch_instruction_status(
    tracking_id: str,
    api_key: str,
    max_reconnects: int = 10,
    *,
    should_cancel: Callable[[], bool] | None = None,
    register_response: Callable[[requests.Response | None], None] | None = None,
) -> Generator[tuple[LookyInstructionStatus, str | None]]:
    """Stream SSE status updates for a Looky System instruction until a terminal status arrives.

    Yields `(status, result)` tuples parsed from `status_update` events.
    Stops after the first terminal status (`completed`, `failed`, or `canceled`).

    Servers commonly close SSE streams after a short idle window and expect clients
    to reconnect. This function transparently reconnects to the same `tracking_id`
    URL up to `max_reconnects` times whenever the stream ends before a terminal status
    is received (including `ChunkedEncodingError`).

    Args:
        tracking_id: The instruction tracking ID returned by `send_crawler_instruction`.
        api_key: Looky System Bearer API key (sent as the `token` query parameter).
        max_reconnects: Maximum reconnection attempts before raising.
        should_cancel: Optional predicate polled before each connect and after each event; when it
            returns True the generator stops immediately without raising.
        register_response: Optional callback invoked with the active streaming `Response` right after
            it opens (and with `None` once it closes). A caller can hold onto it and call `close()` from
            another thread to unblock the blocking read for a prompt cancel.

    Raises:
        requests.HTTPError: On a non-2xx response.
        requests.RequestException: On connection/timeout errors after exhausting reconnects.
        pydantic.ValidationError: If an SSE event JSON does not match the expected shape.
    """
    url = f'{LOOKY_SSE_URL}/{tracking_id}'
    for attempt in range(max_reconnects + 1):
        if should_cancel is not None and should_cancel():
            return
        if attempt > 0:
            time.sleep(2)
        completed = False
        logger.debug('SSE %s attempt %d/%d', tracking_id, attempt + 1, max_reconnects + 1)
        try:
            with session.get(
                url,
                headers={'Accept': 'text/event-stream'},
                params={'token': api_key},
                stream=True,
                timeout=(3.0, 300.0),
            ) as response:
                if register_response is not None:
                    register_response(response)
                response.raise_for_status()
                for raw_line in response.iter_lines():
                    if should_cancel is not None and should_cancel():
                        return
                    if not raw_line:
                        continue
                    line = raw_line.decode('utf-8') if isinstance(raw_line, bytes) else raw_line
                    if not line.startswith('data: '):
                        continue
                    event = LookyInstructionStatusEvent.model_validate_json(line[6:])
                    logger.debug('SSE %s event status=%r result=%r', tracking_id, event.data.status, event.data.result)
                    yield event.data.status, event.data.result
                    if is_terminal_instruction_status(event.data.status):
                        completed = True
                        break
        except requests.HTTPError:
            raise
        except requests.RequestException as e:
            if should_cancel is not None and should_cancel():
                return
            if attempt >= max_reconnects:
                raise
            logger.debug('SSE %s disconnected: %s; reconnecting (attempt %d/%d)', tracking_id, e, attempt + 1, max_reconnects)
            continue
        finally:
            if register_response is not None:
                register_response(None)
        if completed:
            return
        if attempt >= max_reconnects:
            message = f'SSE stream for instruction {tracking_id!r} ended without a terminal status after {max_reconnects} reconnect attempts'
            raise requests.ConnectionError(message)
