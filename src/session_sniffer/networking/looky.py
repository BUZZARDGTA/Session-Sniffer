"""Looky GTA IP-to-player lookup API client."""

import json
import re
import time
from typing import TYPE_CHECKING

import requests
from pydantic import TypeAdapter

from session_sniffer.models.looky import LookyPlayer
from session_sniffer.networking.http_session import session

if TYPE_CHECKING:
    from collections.abc import Generator

LOOKY_BASE_URL = 'https://looky-gta.cc/api/search'
LOOKY_INSTRUCTION_URL = 'https://looky-gta.cc/api/instruction'
LOOKY_CRAWLME_URL = 'https://looky-gta.cc/api/instruction/crawlme'
LOOKY_SSE_URL = 'https://looky-gta.cc/api/sse/instruction-status'
LOOKY_GETRID_URL = 'https://looky-gta.cc/api/scapi/getrid'

_RESPONSE_ADAPTER: TypeAdapter[list[LookyPlayer]] = TypeAdapter(list[LookyPlayer])


def extract_rate_limit_message(exc: requests.HTTPError) -> str:
    """Return the API error message from a 429 `HTTPError` response, falling back to `'Too Many Requests'`."""
    if exc.response is None:
        return 'Too Many Requests'
    try:
        return str(exc.response.json().get('message', 'Too Many Requests'))
    except requests.JSONDecodeError:
        return 'Too Many Requests'


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


# Static device fingerprint sent with instruction requests.
# The Looky web app collects a browser fingerprint; we provide a fixed
# minimal value so the header is present and well-formed.
_DEVICE_FINGERPRINT: str = json.dumps({
    'visitorId': 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4',
    'confidence': 0.6,
    'userAgent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0',
    'language': 'en-US',
    'languages': ['en-US', 'en'],
    'platform': 'Win32',
    'hardwareConcurrency': 4,
    'vendor': '',
    'screen': {'width': 1920, 'height': 1080, 'availWidth': 1920, 'availHeight': 1080, 'colorDepth': 24, 'pixelRatio': 1},
    'storage': {'localStorage': True, 'sessionStorage': True, 'indexedDB': True, 'cookies': True},
    'touch': {'maxTouchPoints': 0, 'touchEvent': False, 'pointerEnabled': False},
    'timezone': 'UTC',
    'timezoneOffset': 0,
    'canvasHash': '0',
    'audioHash': '0',
    'battery': {'charging': False},
})


def lookup_ip(ip: str, api_key: str, version: str = 'both') -> list[LookyPlayer]:
    """Query the Looky API for GTA players associated with `ip`.

    Args:
        ip: The IPv4 address to look up.
        api_key: Looky Bearer API key.
        version: Game version filter sent to the API (`'both'`, `'legacy'`, or `'enhanced'`).

    Returns:
        A (possibly empty) list of `LookyPlayer` entries.

    Raises:
        requests.HTTPError: On a non-2xx response.
        requests.RequestException: On connection/timeout errors.
        pydantic.ValidationError: If the response JSON shape is unexpected.
    """
    url = f'{LOOKY_BASE_URL}/{ip}'
    headers = {'Authorization': f'Bearer {api_key}'}
    response = session.get(url, headers=headers, params={'version': version}, timeout=10)
    response.raise_for_status()
    return _RESPONSE_ADAPTER.validate_json(response.content)


def send_crawlme_instruction(api_key: str) -> str:
    """POST a crawlme instruction to the Looky API to request the crawler for the current session.

    Args:
        api_key: Looky Bearer API key.

    Returns:
        The instruction tracking ID (UUID string) for polling status via `watch_instruction_status`.

    Raises:
        requests.HTTPError: On a non-2xx response.
        requests.RequestException: On connection/timeout errors.
        KeyError: If the response JSON does not contain a `'trackingId'` field.
    """
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json',
        'x-device-fingerprint': _DEVICE_FINGERPRINT,
    }
    response = session.post(LOOKY_CRAWLME_URL, headers=headers, timeout=10)
    response.raise_for_status()
    return str(response.json()['trackingId'])


def send_crawler_instruction(rid: int, api_key: str) -> str:
    """POST a join instruction to the Looky API to call the crawler bot for `rid`.

    Args:
        rid: The Rockstar player ID to request the crawler for.
        api_key: Looky Bearer API key.

    Returns:
        The instruction tracking ID (UUID string) for polling status via `watch_instruction_status`.

    Raises:
        requests.HTTPError: On a non-2xx response.
        requests.RequestException: On connection/timeout errors.
        KeyError: If the response JSON does not contain a `'trackingId'` field.
    """
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json',
        'x-device-fingerprint': _DEVICE_FINGERPRINT,
    }
    response = session.post(
        LOOKY_INSTRUCTION_URL,
        headers=headers,
        json={'type': 'join', 'rid': rid},
        timeout=10,
    )
    response.raise_for_status()
    return str(response.json()['trackingId'])


def watch_instruction_status(
    tracking_id: str,
    api_key: str,
    max_reconnects: int = 10,
) -> Generator[tuple[str, str | None]]:
    """Stream SSE status updates for a Looky instruction until it completes.

    Yields `(status, result)` tuples parsed from `status_update` events.
    Stops after the first `'completed'` status.

    Servers commonly close SSE streams after a short idle window and expect clients
    to reconnect. This function transparently reconnects to the same `tracking_id`
    URL up to `max_reconnects` times whenever the stream ends before `'completed'`
    is received (including `ChunkedEncodingError`).

    Args:
        tracking_id: The instruction tracking ID returned by `send_crawler_instruction`.
        api_key: Looky Bearer API key (sent as the `token` query parameter).
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
                    status: str = data.get('status', '')
                    result: str | None = data.get('result')
                    yield status, result
                    if status == 'completed':
                        completed = True
                        break
        except requests.HTTPError:
            raise
        except requests.RequestException:
            if attempt >= max_reconnects:
                raise
            continue
        if completed:
            return
        if attempt >= max_reconnects:
            msg = f'SSE stream for instruction {tracking_id!r} ended without a completed event after {max_reconnects} reconnect attempts'
            raise requests.ConnectionError(msg)


def get_rid_by_username(username: str, api_key: str) -> int:
    """Fetch the Rockstar ID for `username` via the Looky scapi endpoint.

    Args:
        username: The Rockstar Social Club username to look up.
        api_key: Looky Bearer API key.

    Returns:
        The integer Rockstar ID.

    Raises:
        requests.HTTPError: On a non-2xx response.
        requests.RequestException: On connection/timeout errors.
        KeyError: If the response JSON does not contain a `'rid'` field.
        ValueError: If the `'rid'` field cannot be converted to an integer.
    """
    headers = {
        'Authorization': f'Bearer {api_key}',
        'x-device-fingerprint': _DEVICE_FINGERPRINT,
    }
    response = session.get(f'{LOOKY_GETRID_URL}/{username}', headers=headers, timeout=10)
    response.raise_for_status()
    return int(response.json()['rid'])
