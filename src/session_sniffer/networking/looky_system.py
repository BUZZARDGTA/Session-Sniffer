"""Looky System IP-to-player lookup API client."""

import json
import re
import time
from typing import TYPE_CHECKING, Literal

import requests
from pydantic import TypeAdapter

from session_sniffer.constants.standalone import LOOKY_BASE_HOST
from session_sniffer.logging_setup import get_logger
from session_sniffer.models.looky_system import LookyIpBatchResult, LookyPlayer, LookyUserData, LookyVerifyResponse, LookyWhoAmI
from session_sniffer.networking.http_session import session

if TYPE_CHECKING:
    from collections.abc import Generator

logger = get_logger(__name__)

LOOKY_BASE_URL = f'{LOOKY_BASE_HOST}/api/search'
LOOKY_BATCH_URL = f'{LOOKY_BASE_HOST}/api/search/ip-batch'
LOOKY_WHOAMI_URL = f'{LOOKY_BASE_HOST}/api/whoami'
LOOKY_INSTRUCTION_URL = f'{LOOKY_BASE_HOST}/api/instruction'
LOOKY_CRAWLME_URL = f'{LOOKY_BASE_HOST}/api/instruction/crawlme'
LOOKY_SSE_URL = f'{LOOKY_BASE_HOST}/api/sse/instruction-status'

_RESPONSE_ADAPTER: TypeAdapter[list[LookyPlayer]] = TypeAdapter(list[LookyPlayer])
_BATCH_RESPONSE_ADAPTER: TypeAdapter[list[LookyIpBatchResult]] = TypeAdapter(list[LookyIpBatchResult])

LookyInstructionStatus = Literal['queued', 'running', 'completed', 'failed', 'canceled', 'unknown']

_TERMINAL_INSTRUCTION_STATUSES = frozenset({'completed', 'failed', 'canceled'})
_TERMINAL_FAILURE_INSTRUCTION_STATUSES = frozenset({'failed', 'canceled'})


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
        timeout=10,
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
    response = session.get(url, headers=_auth_headers(api_key), params={'version': version}, timeout=10)
    response.raise_for_status()
    return _RESPONSE_ADAPTER.validate_json(response.content)


def lookup_ip_batch(ips: list[str], api_key: str, version: str = 'both') -> dict[str, list[LookyPlayer]]:
    """Query the Looky System batch endpoint for players associated with multiple IPs in one request.

    Args:
        ips: List of IPv4 addresses to look up (max 32 per call).
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
        json={'ips': ips, 'version': version},
        timeout=10,
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
    response = session.post(LOOKY_CRAWLME_URL, headers=_json_auth_headers(api_key), timeout=10)
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
        timeout=10,
    )
    response.raise_for_status()
    return str(response.json()['trackingId'])


def watch_instruction_status(
    tracking_id: str,
    api_key: str,
    max_reconnects: int = 10,
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

    Raises:
        requests.HTTPError: On a non-2xx response.
        requests.RequestException: On connection/timeout errors after exhausting reconnects.
    """
    url = f'{LOOKY_SSE_URL}/{tracking_id}'
    for attempt in range(max_reconnects + 1):
        if attempt > 0:
            time.sleep(2)
        completed = False
        try:
            with session.get(
                url,
                headers={'Accept': 'text/event-stream'},
                params={'token': api_key},
                stream=True,
                timeout=(10, 300),
            ) as response:
                response.raise_for_status()
                for raw_line in response.iter_lines():
                    if not raw_line:
                        continue
                    line = raw_line.decode('utf-8') if isinstance(raw_line, bytes) else raw_line
                    if not line.startswith('data: '):
                        continue
                    try:
                        event = json.loads(line[6:])
                    except json.JSONDecodeError:
                        continue
                    data = event.get('data', {})
                    status: LookyInstructionStatus = data.get('status', 'unknown')
                    result: str | None = data.get('result')
                    yield status, result
                    if is_terminal_instruction_status(status):
                        completed = True
                        break
        except requests.HTTPError:
            raise
        except requests.RequestException:
            if attempt >= max_reconnects:
                raise
            logger.debug('SSE stream disconnected for instruction %r; reconnecting (attempt %d/%d)', tracking_id, attempt + 1, max_reconnects)
            continue
        if completed:
            return
        if attempt >= max_reconnects:
            msg = f'SSE stream for instruction {tracking_id!r} ended without a terminal status after {max_reconnects} reconnect attempts'
            raise requests.ConnectionError(msg)
