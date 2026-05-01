"""Discord webhook transport for mirroring live player tables to a Discord channel.

The sender posts two messages once (one per table) and then PATCHes those same
messages on a configurable interval so the channel doesn't get spammed. Message
IDs are persisted in `Settings.discord_webhook_message_ids` (JSON-encoded) so
edits survive application restarts.

Wire format: stdlib `urllib.request` only (no extra dependencies). Each request
uses `?wait=true` so Discord returns the message JSON, allowing us to capture
the message id on first POST.
"""

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from queue import Empty, SimpleQueue
from threading import Event, Lock, Thread
from typing import TYPE_CHECKING, Any, Final, cast  # pylint: disable=unused-import  # `Any` is used in quoted cast() forward refs (Ruff TC006)

import sentinel  # pyright: ignore[reportMissingTypeStubs]

from session_sniffer.constants.standalone import TITLE
from session_sniffer.logging_setup import get_logger
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from datetime import datetime

logger = get_logger(__name__)

SHUTDOWN_SIGNAL = sentinel.create('WebhookShutdownSignal')

WEBHOOK_URL_RE: Final = re.compile(
    r'^https://(?:(?:canary|ptb)\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+/?$',
)

_HTTP_OK_CREATED = 200
_HTTP_NO_CONTENT = 204
_HTTP_TOO_MANY_REQUESTS = 429
_HTTP_NOT_FOUND = 404
_HTTP_UNAUTHORIZED = 401
_HTTP_FORBIDDEN = 403

_REQUEST_TIMEOUT_SECONDS = 10.0
# Discord plain-message content limit is 2000 chars. Reserve room for the
# header line, the ```\n ... \n``` fence (8 chars), and the optional
# truncation notice line.
_DISCORD_CONTENT_LIMIT = 2000
_DISCORD_EMBED_DESCRIPTION_LIMIT = 4096
_CODE_BLOCK_OVERHEAD = 8
_HEADER_RESERVE = 200
_TRUNCATION_NOTICE_RESERVE = 80
_MAX_TABLE_BODY_CHARS = _DISCORD_CONTENT_LIMIT - _CODE_BLOCK_OVERHEAD - _HEADER_RESERVE - _TRUNCATION_NOTICE_RESERVE
# Embed descriptions don't include the message header (it's the embed title),
# but still need room for the truncation footer line.
_MAX_EMBED_BODY_CHARS = _DISCORD_EMBED_DESCRIPTION_LIMIT - _TRUNCATION_NOTICE_RESERVE
_EMBED_COLOR_CONNECTED = 0x2ECC71  # green
_EMBED_COLOR_DISCONNECTED = 0xE74C3C  # red
_EMBED_COLOR_STOPPED = 0x95A5A6  # gray


@dataclass(slots=True)
class DiscordWebhookPayload:
    """Snapshot of the latest live tables to mirror to Discord."""

    connected_text: str | None
    disconnected_text: str | None
    connected_count: int
    disconnected_count: int
    generated_at: datetime
    capture_running: bool


def is_valid_webhook_url(url: str | None) -> bool:
    """Return True when *url* matches the Discord incoming-webhook URL shape."""
    if not isinstance(url, str) or not url:
        return False
    return WEBHOOK_URL_RE.match(url.strip()) is not None


def _truncate_table(table_text: str, max_rows: int, body_char_limit: int = _MAX_TABLE_BODY_CHARS) -> tuple[str, int]:
    """Return (possibly-truncated table, removed_row_count).

    PrettyTable produces lines like:
        ┌───── title ─────┐
        │ header │ header │
        ├────────┼────────┤
        │ cell   │ cell   │
        ...
        └─────────────────┘

    We keep the borders/header intact and only drop *body* rows beyond
    *max_rows*, then fall back to a hard char-cap so we never exceed
    Discord's 4096-char embed description limit.
    """
    if not table_text:
        return table_text, 0

    lines = table_text.splitlines()
    # Identify body rows: lines that start with '│' (data row) but not the
    # header. The first '│' line is the header; subsequent '│' lines are body.
    body_indices: list[int] = []
    seen_header = False
    for idx, line in enumerate(lines):
        if line.startswith('│'):
            if not seen_header:
                seen_header = True
            else:
                body_indices.append(idx)

    removed = 0
    if body_indices:
        # PrettyTable mode: drop body rows beyond max_rows.
        if len(body_indices) > max_rows:
            keep = set(body_indices[:max_rows])
            drop = set(body_indices[max_rows:])
            removed = len(drop)
            lines = [line for idx, line in enumerate(lines) if idx not in drop or idx in keep]
        truncated = '\n'.join(lines)

        # Hard char-cap fallback for PrettyTable: ugly but never breaks
        # markdown because the body is wrapped in a code fence.
        if len(truncated) > body_char_limit:
            truncated = truncated[: body_char_limit - 3] + '...'
    else:
        # Plain-text (mobile/markdown) mode: players are multi-line blocks
        # separated by a blank line. Truncate by full blocks so:
        #   * the "N more players" count refers to players, not raw lines, and
        #   * we never cut mid-line through `**bold**` markdown, which would
        #     leak unmatched asterisks and break the rest of the message.
        blocks = table_text.split('\n\n')
        if len(blocks) > max_rows:
            removed = len(blocks) - max_rows
            blocks = blocks[:max_rows]

        # Drop whole blocks from the tail until we fit Discord's char budget.
        # Allow space for a possible "N more not shown" notice that the caller
        # appends; the _TRUNCATION_NOTICE_RESERVE constant already accounts
        # for it within _MAX_TABLE_BODY_CHARS.
        def _joined_len(parts: list[str]) -> int:
            return sum(len(p) for p in parts) + 2 * max(0, len(parts) - 1)

        while blocks and _joined_len(blocks) > body_char_limit:
            blocks.pop()
            removed += 1
        truncated = '\n\n'.join(blocks)

    return truncated, removed


def _build_message_content(
    *,
    title: str,
    table_text: str | None,
    timestamp: datetime,
    max_rows: int,
    empty_label: str,
) -> str:
    """Build the plain message content for one table.

    The body is wrapped in a fenced code block so Discord renders it in
    monospace at the full message width (used by Desktop format).
    """
    unix_ts = int(timestamp.timestamp())
    header = f'**{title}** \u2014 updated <t:{unix_ts}:R>'

    if not table_text:
        return f'{header}\n_{empty_label}_'

    truncated, removed = _truncate_table(table_text, max_rows)
    parts = [header, f'```\n{truncated}\n```']
    if removed:
        parts.append(f'_\u2026 and {removed} more {"player" if removed == 1 else "players"} not shown_')
    return '\n'.join(parts)


def _build_embed_payload(  # noqa: PLR0913  # pylint: disable=too-many-arguments
    *,
    title: str,
    table_text: str | None,
    timestamp: datetime,
    max_rows: int,
    empty_label: str,
    color: int,
) -> dict[str, object]:
    """Build a Discord embed dict for one table using markdown blocks.

    Uses the same per-player markdown layout as the Mobile content format,
    but inside an embed so we get a colored sidebar, a proper title, the
    larger 4096-char description budget, and a native footer timestamp.
    """
    if not table_text:
        description = f'_{empty_label}_'
    else:
        truncated, removed = _truncate_table(table_text, max_rows, _MAX_EMBED_BODY_CHARS)
        parts = [truncated]
        if removed:
            parts.append(f'_… and {removed} more {"player" if removed == 1 else "players"} not shown_')
        description = '\n\n'.join(parts)

    return {
        'title': title,
        'description': description,
        'color': color,
        'timestamp': timestamp.isoformat(),
    }


def _http_request(
    url: str,
    *,
    method: str,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """Perform a JSON HTTP request. Returns (status_code, headers, body_bytes).

    Network errors are raised; HTTP non-2xx responses are returned, not raised.
    """
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': f'SessionSniffer ({TITLE})',
    }
    request = urllib.request.Request(url, data=body, method=method, headers=headers)  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310
            return (
                int(response.status),
                {str(k).lower(): str(v) for k, v in response.headers.items()},
                response.read(),
            )
    except urllib.error.HTTPError as http_err:
        body_bytes = http_err.read() if hasattr(http_err, 'read') else b''
        response_headers: dict[str, str] = (
            {str(k).lower(): str(v) for k, v in http_err.headers.items()} if http_err.headers else {}
        )
        return int(http_err.code), response_headers, body_bytes


def send_test_message(url: str) -> tuple[bool, str]:
    """Send a one-shot test message to *url*. Returns (ok, human_message).

    Used by the Settings dialog "Test Webhook" button.
    """
    if not is_valid_webhook_url(url):
        return False, 'URL does not look like a Discord webhook URL.'

    payload = json.dumps({
        'content': f'\U0001f527 Test from {TITLE} — webhook is working.',
    }).encode('utf-8')
    try:
        status, _headers, response_body = _http_request(url, method='POST', body=payload)
    except (urllib.error.URLError, TimeoutError) as err:
        return False, f'Network error: {err}'
    except OSError as err:
        return False, f'I/O error: {err}'

    if status in (_HTTP_OK_CREATED, _HTTP_NO_CONTENT):
        return True, 'Test message posted successfully.'
    return False, f'Discord returned HTTP {status}: {response_body.decode("utf-8", errors="replace")[:300]}'


def _load_message_ids() -> dict[str, str]:
    """Return persisted {connected, disconnected} message IDs (or empty dict)."""
    raw = Settings.discord_webhook_message_ids
    if not isinstance(raw, str) or not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    parsed_dict = cast('dict[str, Any]', parsed)
    return {str(k): str(v) for k, v in parsed_dict.items() if isinstance(v, (str, int))}


def _save_message_ids(message_ids: dict[str, str]) -> None:
    """Persist *message_ids* to Settings.ini."""
    Settings.discord_webhook_message_ids = json.dumps(message_ids) if message_ids else None
    Settings.rewrite_settings_file()


class DiscordWebhookSender:
    """Background sender that mirrors live tables to a Discord webhook channel."""

    _instance: 'DiscordWebhookSender | None' = None  # noqa: UP037  # forward reference inside its own class
    _instance_lock: Lock = Lock()

    def __init__(self) -> None:
        """Initialize the sender; the worker thread starts on first `submit()`."""
        self._latest_payload: DiscordWebhookPayload | None = None
        self._payload_lock = Lock()
        self._wakeup: SimpleQueue[object] = SimpleQueue()
        self._closed = False
        self._auto_disabled_url: str | None = None  # tracks last URL we permanently failed against
        self._thread = Thread(
            target=self._run,
            name='DiscordWebhookSender',
            daemon=True,
        )
        self.connection_status = Event()
        self._thread.start()

    @classmethod
    def instance(cls) -> 'DiscordWebhookSender':  # noqa: UP037  # forward reference inside its own class
        """Return the lazily-created process-wide singleton."""
        with cls._instance_lock:
            if cls._instance is None or cls._instance._closed:  # noqa: SLF001  # pylint: disable=protected-access
                cls._instance = cls()
            return cls._instance

    def submit(self, payload: DiscordWebhookPayload) -> None:
        """Replace the pending payload with *payload* (latest-wins coalescing)."""
        if self._closed:
            return
        with self._payload_lock:
            self._latest_payload = payload
        self._wakeup.put(None)

    def close(self) -> None:
        """Stop the worker thread."""
        if self._closed:
            return
        self._closed = True
        self._wakeup.put(SHUTDOWN_SIGNAL)
        self._thread.join(timeout=3)

    # ------------------------------------------------------------------
    # Worker loop
    # ------------------------------------------------------------------

    def _run(self) -> None:
        """Worker loop: wait for payloads, post or edit on the configured cadence."""
        while not self._closed:
            interval = max(5, int(getattr(Settings, 'discord_webhook_refresh_interval', 15)))

            # Block until awakened or interval expires
            try:
                item = self._wakeup.get(timeout=interval)
            except Empty:
                item = None

            if item is SHUTDOWN_SIGNAL:
                return

            # Drain any extra wakeup events without losing the latest payload
            while not self._wakeup.empty():
                try:
                    extra = self._wakeup.get_nowait()
                except Empty:
                    break
                if extra is SHUTDOWN_SIGNAL:
                    return

            with self._payload_lock:
                payload = self._latest_payload
                self._latest_payload = None

            if payload is None:
                continue

            if not Settings.discord_webhook_enabled:
                continue

            url = Settings.discord_webhook_url
            if not isinstance(url, str) or not is_valid_webhook_url(url):
                continue

            if self._auto_disabled_url == url:
                # Already failed permanently against this URL; wait for user to change it.
                continue

            try:
                self._dispatch(url, payload)
            except (urllib.error.URLError, TimeoutError, OSError) as err:
                logger.warning('Discord webhook network error: %s', err)
                self.connection_status.clear()

    def _dispatch(self, url: str, payload: DiscordWebhookPayload) -> None:
        """Build messages for *payload* and POST/PATCH to Discord."""
        max_rows = max(1, int(getattr(Settings, 'discord_webhook_max_rows_per_table', 25)))
        message_ids = _load_message_ids()
        ids_changed = False

        kinds: list[tuple[str, str | None, int, str]] = []
        if Settings.discord_webhook_include_connected:
            kinds.append((
                'connected',
                payload.connected_text,
                payload.connected_count,
                'Connected players',
            ))
        if Settings.discord_webhook_include_disconnected:
            kinds.append((
                'disconnected',
                payload.disconnected_text,
                payload.disconnected_count,
                'Disconnected players',
            ))

        for kind, table_text, count, label in kinds:
            title = f'{label} ({count})'
            if not payload.capture_running:
                title += ' \u2014 capture stopped'
            if not payload.capture_running:
                empty_label = 'Capture stopped'
            elif count > 0:
                empty_label = 'All columns disabled \u2014 enable at least one column in webhook settings'
            else:
                empty_label = 'No players'

            webhook_format = Settings.discord_webhook_format
            if webhook_format == 'Mobile':
                if not payload.capture_running:
                    color = _EMBED_COLOR_STOPPED
                elif kind == 'connected':
                    color = _EMBED_COLOR_CONNECTED
                else:
                    color = _EMBED_COLOR_DISCONNECTED
                embed = _build_embed_payload(
                    title=title,
                    table_text=table_text,
                    timestamp=payload.generated_at,
                    max_rows=max_rows,
                    empty_label=empty_label,
                    color=color,
                )
                request_payload: dict[str, object] = {
                    'content': '',
                    'embeds': [embed],
                    'allowed_mentions': {'parse': []},
                }
            else:
                content = _build_message_content(
                    title=title,
                    table_text=table_text,
                    timestamp=payload.generated_at,
                    max_rows=max_rows,
                    empty_label=empty_label,
                )
                request_payload = {
                    'content': content,
                    # Disable @everyone/@here/role/user pings just in case a username contains them.
                    'allowed_mentions': {'parse': []},
                }
            body = json.dumps(request_payload).encode('utf-8')

            existing_id = message_ids.get(kind)
            new_id = self._post_or_patch(url, existing_id, body)
            if new_id is None:
                # Permanent failure already logged in _post_or_patch
                if kind in message_ids:
                    del message_ids[kind]
                    ids_changed = True
                continue
            if new_id != existing_id:
                message_ids[kind] = new_id
                ids_changed = True

        if ids_changed:
            _save_message_ids(message_ids)

    def _post_or_patch(self, url: str, existing_id: str | None, body: bytes) -> str | None:  # pylint: disable=too-many-return-statements  # noqa: PLR0911
        """Post a new message or patch *existing_id*. Return the message id on success."""
        if existing_id:
            patch_url = f'{url.rstrip("/")}/messages/{urllib.parse.quote(existing_id)}'
            status, _headers, response_body = self._send(patch_url, method='PATCH', body=body)
            if status in (_HTTP_OK_CREATED, _HTTP_NO_CONTENT):
                self.connection_status.set()
                return existing_id
            if status == _HTTP_NOT_FOUND:
                # Message was deleted on Discord; fall through to re-create.
                logger.info('Discord webhook message %s no longer exists, recreating.', existing_id)
                existing_id = None
            elif status == _HTTP_TOO_MANY_REQUESTS:
                self._respect_retry_after(_headers, response_body)
                return existing_id
            elif status in (_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN):
                self._auto_disable(url, status, response_body)
                return None

        # POST new message with ?wait=true to receive the message id back
        post_url = f'{url}{"&" if "?" in url else "?"}wait=true'
        status, _headers, response_body = self._send(post_url, method='POST', body=body)
        if status == _HTTP_OK_CREATED:
            try:
                parsed = json.loads(response_body.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None
            if not isinstance(parsed, dict):
                return None
            new_id = cast('dict[str, Any]', parsed).get('id')
            if isinstance(new_id, (str, int)):
                self.connection_status.set()
                return str(new_id)
            return None
        if status == _HTTP_TOO_MANY_REQUESTS:
            self._respect_retry_after(_headers, response_body)
            return existing_id
        if status in (_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN, _HTTP_NOT_FOUND):
            self._auto_disable(url, status, response_body)
            return None
        logger.warning('Discord webhook unexpected POST status %d: %s', status, response_body[:200])
        return None

    @staticmethod
    def _send(url: str, *, method: str, body: bytes) -> tuple[int, dict[str, str], bytes]:
        return _http_request(url, method=method, body=body)

    def _respect_retry_after(self, headers: dict[str, str], body: bytes) -> None:
        """Sleep for the duration Discord requested via Retry-After."""
        retry_after = headers.get('retry-after') or headers.get('x-ratelimit-reset-after')
        delay: float = 2.0
        if retry_after:
            try:
                delay = float(retry_after)
            except ValueError:
                delay = 2.0
        else:
            try:
                payload = json.loads(body.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                payload = None
            if isinstance(payload, dict):
                retry_value = cast('dict[str, Any]', payload).get('retry_after')
                if isinstance(retry_value, (int, float)):
                    delay = float(retry_value)
        delay = max(0.1, min(delay, 30.0))
        logger.warning('Discord webhook rate-limited; sleeping %.2fs', delay)
        time.sleep(delay)

    def _auto_disable(self, url: str, status: int, body: bytes) -> None:
        """Permanently stop targeting *url* until the user changes it."""
        self._auto_disabled_url = url
        self.connection_status.clear()
        logger.error(
            'Discord webhook URL appears invalid (HTTP %d). Disabling further attempts until URL changes. Body: %s',
            status,
            body[:200],
        )
        # Clear stored message IDs so a fresh URL starts cleanly
        _save_message_ids(cast('dict[str, str]', {}))
