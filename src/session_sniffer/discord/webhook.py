"""Discord webhook transport for mirroring live player tables to a Discord channel.

The sender posts two messages once (one per table) and then PATCHes those same
messages on a configurable interval so the channel doesn't get spammed. Message
IDs are persisted in `Settings.discord_webhook_message_ids` (JSON-encoded) so
edits survive application restarts.

Wire format: stdlib `http.client` only (no extra dependencies). Each request
uses `?wait=true` so Discord returns the message JSON, allowing us to capture
the message id on first POST.
"""

import http.client
import json
import re
import time
import urllib.parse
from dataclasses import dataclass
from queue import Empty, SimpleQueue
from threading import Event, Lock, Thread
from typing import TYPE_CHECKING, Final, cast

import sentinel  # pyright: ignore[reportMissingTypeStubs]

from session_sniffer import msgbox
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
# Discord hard limits for multi-embed messages.
_DISCORD_MAX_EMBEDS_PER_MESSAGE = 10
_DISCORD_EMBEDS_TOTAL_CHAR_LIMIT = 6000
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
    for i, line in enumerate(lines):
        if line.startswith('│'):
            if not seen_header:
                seen_header = True
            else:
                body_indices.append(i)

    removed = 0
    if body_indices:
        # PrettyTable mode: drop body rows beyond max_rows.
        if len(body_indices) > max_rows:
            keep = set(body_indices[:max_rows])
            drop = set(body_indices[max_rows:])
            removed = len(drop)
            lines = [line for i, line in enumerate(lines) if i not in drop or i in keep]
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
            return sum(len(part) for part in parts) + 2 * max(0, len(parts) - 1)

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
    header = f'**{title}** — updated <t:{unix_ts}:R>'

    if not table_text:
        return f'{header}\n_{empty_label}_'

    truncated, removed = _truncate_table(table_text, max_rows)
    parts = [header, f'```\n{truncated}\n```']
    if removed:
        parts.append(f'_… and {removed} more {"player" if removed == 1 else "players"} not shown_')
    return '\n'.join(parts)


@dataclass(slots=True)
class _EmbedStyle:
    timestamp: datetime
    color: int


def _build_multi_embed_payload(
    *,
    title: str,
    table_text: str | None,
    style: _EmbedStyle,
    max_rows: int,
    empty_label: str,
) -> list[dict[str, object]]:
    """Build one or more Discord embed dicts for one table using markdown blocks.

    When the per-player markdown blocks for a table exceed a single embed's
    4096-char description limit, they are split across consecutive embeds
    (continuation titles are suffixed with " · 2", " · 3", …) up to
    Discord's 10-embed-per-message and 6000-total-char-per-message limits.
    Any players that still don't fit are reported as "… and N more not shown".
    """

    def _make_embed(embed_title: str, description: str) -> dict[str, object]:
        return {
            'title': embed_title,
            'description': description,
            'color': style.color,
            'timestamp': style.timestamp.isoformat(),
        }

    if not table_text:
        return [_make_embed(title, f'_{empty_label}_')]

    # Split the mobile-format text into per-player blocks.
    blocks = table_text.split('\n\n')

    # Apply the user-configured max_rows cap globally before packing.
    total_removed = 0
    if len(blocks) > max_rows:
        total_removed = len(blocks) - max_rows
        blocks = blocks[:max_rows]

    embeds: list[dict[str, object]] = []
    current_blocks: list[str] = []
    current_chars = 0
    embed_index = 1
    # chars already consumed by embed titles and running description lengths
    total_chars_used = 0

    def _flush(*, is_last: bool, extra_removed: int) -> None:
        nonlocal total_chars_used
        embed_title = title if embed_index == 1 else f'{title} \u00b7 {embed_index}'
        parts = ['\n\n'.join(current_blocks)]
        remaining = total_removed + extra_removed
        if is_last and remaining:
            parts.append(f'_… and {remaining} more {"player" if remaining == 1 else "players"} not shown_')
        description = '\n\n'.join(parts)
        total_chars_used += len(embed_title) + len(description)
        embeds.append(_make_embed(embed_title, description))

    for block_index, block in enumerate(blocks):
        block_len = len(block)
        next_embed_title = title if embed_index == 1 else f'{title} \u00b7 {embed_index}'
        title_len = len(next_embed_title)
        # Extra chars needed: separator ('\n\n' = 2 chars) if not first block in embed,
        # plus the block itself.  We also need to reserve _TRUNCATION_NOTICE_RESERVE
        # so a final "N more" line never pushes us over the per-embed limit.
        sep = 2 if current_blocks else 0
        projected_desc_len = current_chars + sep + block_len

        # Would this block overflow the current embed's description budget?
        desc_over = projected_desc_len > _MAX_EMBED_BODY_CHARS
        # Would the total-per-message char budget be exceeded?
        # Estimate: existing total_chars_used + this embed's title + projected description.
        total_over = (total_chars_used + title_len + projected_desc_len) > _DISCORD_EMBEDS_TOTAL_CHAR_LIMIT

        if (desc_over or total_over) and current_blocks:
            # Flush the current embed and start a new one.
            _flush(is_last=False, extra_removed=0)
            embed_index += 1
            current_blocks = []
            current_chars = 0

            if len(embeds) >= _DISCORD_MAX_EMBEDS_PER_MESSAGE:
                # No more embed slots — count all remaining as removed.
                total_removed += len(blocks) - block_index
                break

        current_blocks.append(block)
        current_chars += sep + block_len

    if current_blocks:
        _flush(is_last=True, extra_removed=0)

    return embeds


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
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query
    connection = http.client.HTTPSConnection(parsed.netloc, timeout=_REQUEST_TIMEOUT_SECONDS)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response_body = response.read()
    finally:
        connection.close()
    return (
        response.status,
        {str(key).lower(): str(value) for key, value in response.getheaders()},
        response_body,
    )


def send_test_message(url: str) -> tuple[bool, str]:
    """Send a one-shot test message to *url*. Returns (ok, human_message).

    Used by the Settings dialog "Test Webhook" button.
    """
    if not is_valid_webhook_url(url):
        return False, 'URL does not look like a Discord webhook URL.'

    payload = json.dumps(
        {
            'content': f'\U0001f527 Test from {TITLE} — webhook is working.',
        },
    ).encode('utf-8')
    try:
        status, _headers, response_body = _http_request(url, method='POST', body=payload)
    except (http.client.HTTPException, OSError) as e:
        return False, f'Network error: {e}'

    if status in (http.HTTPStatus.OK, http.HTTPStatus.NO_CONTENT):
        return True, 'Test message posted successfully.'
    return False, f'Discord returned HTTP {status}: {response_body.decode("utf-8", errors="replace")[:300]}'


def _load_message_ids() -> dict[str, str]:
    """Return persisted {connected, disconnected} message IDs (or empty dict)."""
    raw = Settings.discord_webhook_message_ids
    if not isinstance(raw, str) or not raw:
        return {}
    try:
        parsed: object = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    parsed_dict = cast('dict[object, object]', parsed)
    return {str(key): str(value) for key, value in parsed_dict.items() if isinstance(value, (str, int))}


def _save_message_ids(message_ids: dict[str, str]) -> None:
    """Persist *message_ids* to Settings.ini."""
    Settings.discord_webhook_message_ids = json.dumps(message_ids) if message_ids else None
    Settings.rewrite_settings_file()


def _describe_auto_disable_status(status: int) -> str:
    """Return a short human-friendly description of the failure status."""
    if status == http.HTTPStatus.NOT_FOUND:
        return 'Webhook not found (deleted, or URL is wrong)'
    if status == http.HTTPStatus.UNAUTHORIZED:
        return 'Unauthorized (invalid webhook token)'
    if status == http.HTTPStatus.FORBIDDEN:
        return 'Forbidden (webhook revoked or lacks permission)'
    return 'Webhook rejected the request'


class DiscordWebhookSender:
    """Background sender that mirrors live tables to a Discord webhook channel."""

    _instance: DiscordWebhookSender | None = None
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

    @property
    def is_closed(self) -> bool:
        """Return `True` if this sender has been closed."""
        return self._closed

    @classmethod
    def instance(cls) -> DiscordWebhookSender:
        """Return the lazily-created process-wide singleton."""
        with cls._instance_lock:
            if cls._instance is None or cls._instance.is_closed:
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
            except (http.client.HTTPException, OSError) as e:
                logger.warning('Discord webhook network error: %s', e)
                self.connection_status.clear()

    def _dispatch(self, url: str, payload: DiscordWebhookPayload) -> None:
        """Build messages for *payload* and POST/PATCH to Discord."""
        max_rows = max(1, int(getattr(Settings, 'discord_webhook_max_rows_per_table', 25)))
        message_ids = _load_message_ids()
        ids_changed = False

        kinds: list[tuple[str, str | None, int, str]] = []
        if Settings.discord_webhook_include_connected:
            kinds.append(
                (
                    'connected',
                    payload.connected_text,
                    payload.connected_count,
                    'Connected players',
                ),
            )
        if Settings.discord_webhook_include_disconnected:
            kinds.append(
                (
                    'disconnected',
                    payload.disconnected_text,
                    payload.disconnected_count,
                    'Disconnected players',
                ),
            )

        for kind, table_text, count, label in kinds:
            title = f'{label} ({count})'
            if not payload.capture_running:
                title += ' — capture stopped'
            if not payload.capture_running:
                empty_label = 'Capture stopped'
            elif count > 0:
                empty_label = 'All columns disabled — enable at least one column in webhook settings'
            else:
                empty_label = 'No players'

            if Settings.discord_webhook_format == 'Mobile':
                if not payload.capture_running:
                    color = _EMBED_COLOR_STOPPED
                elif kind == 'connected':
                    color = _EMBED_COLOR_CONNECTED
                else:
                    color = _EMBED_COLOR_DISCONNECTED
                embeds = _build_multi_embed_payload(
                    title=title,
                    table_text=table_text,
                    style=_EmbedStyle(timestamp=payload.generated_at, color=color),
                    max_rows=max_rows,
                    empty_label=empty_label,
                )
                # Always include 'content' (empty string) so that if the
                # message previously had a Desktop text body it is cleared.
                request_payload: dict[str, object] = {
                    'content': '',
                    'embeds': embeds,
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
                # Always include 'embeds': [] so that if the message previously
                # had a Mobile embed it is removed when switching to Desktop.
                request_payload = {
                    'content': content,
                    'embeds': [],
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

    def _post_or_patch(self, url: str, existing_id: str | None, body: bytes) -> str | None:
        """Post a new message or patch *existing_id*. Return the message id on success."""
        if existing_id:
            patch_url = f'{url.rstrip("/")}/messages/{urllib.parse.quote(existing_id)}'
            status, _headers, response_body = self._send(patch_url, method='PATCH', body=body)
            if status in (http.HTTPStatus.OK, http.HTTPStatus.NO_CONTENT):
                self.connection_status.set()
                return existing_id
            if status == http.HTTPStatus.NOT_FOUND:
                # Message was deleted on Discord; fall through to re-create.
                logger.info('Discord webhook message %s no longer exists, recreating.', existing_id)
                existing_id = None
            elif status == http.HTTPStatus.TOO_MANY_REQUESTS:
                self._respect_retry_after(_headers, response_body)
                return existing_id
            elif status in (http.HTTPStatus.UNAUTHORIZED, http.HTTPStatus.FORBIDDEN):
                self._auto_disable(url, status, response_body)
                return None

        # POST new message with ?wait=true to receive the message id back
        post_url = f'{url}{"&" if "?" in url else "?"}wait=true'
        status, _headers, response_body = self._send(post_url, method='POST', body=body)
        if status == http.HTTPStatus.OK:
            new_id = self._parse_posted_id(response_body)
            if new_id is not None:
                self.connection_status.set()
            return new_id
        if status == http.HTTPStatus.TOO_MANY_REQUESTS:
            self._respect_retry_after(_headers, response_body)
            return existing_id
        if status in (http.HTTPStatus.UNAUTHORIZED, http.HTTPStatus.FORBIDDEN, http.HTTPStatus.NOT_FOUND):
            self._auto_disable(url, status, response_body)
        else:
            logger.warning('Discord webhook unexpected POST status %d: %s', status, response_body[:200])
        return None

    @staticmethod
    def _parse_posted_id(response_body: bytes) -> str | None:
        """Extract the message id from a POST ?wait=true response body."""
        try:
            parsed: object = json.loads(response_body.decode('utf-8'))
        except json.JSONDecodeError, UnicodeDecodeError:
            return None
        if not isinstance(parsed, dict):
            return None
        parsed_dict = cast('dict[str, object]', parsed)
        new_id = parsed_dict.get('id')
        return str(new_id) if isinstance(new_id, (str, int)) else None

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
                payload: object = json.loads(body.decode('utf-8'))
            except json.JSONDecodeError, UnicodeDecodeError:
                payload = None
            if isinstance(payload, dict):
                payload_dict = cast('dict[str, object]', payload)
                retry_value: object = payload_dict.get('retry_after')
                if isinstance(retry_value, (int, float)):
                    delay = float(retry_value)
        delay = max(0.1, min(delay, 30.0))
        logger.warning('Discord webhook rate-limited; sleeping %.2fs', delay)
        time.sleep(delay)

    def _auto_disable(self, url: str, status: int, body: bytes) -> None:
        """Permanently stop targeting *url* until the user changes it."""
        already_disabled_for_this_url = self._auto_disabled_url == url
        self._auto_disabled_url = url
        self.connection_status.clear()
        if already_disabled_for_this_url:
            # Already reported & user notified for this URL; suppress duplicate log + popup.
            return
        logger.error(
            'Discord webhook URL appears invalid (HTTP %d). Disabling further attempts until URL changes. Body: %s',
            status,
            body[:200],
        )
        # Clear stored message IDs so a fresh URL starts cleanly
        _save_message_ids({})

        # Notify the user via a non-blocking popup (msgbox is modal; spawn a
        # daemon thread so the webhook worker keeps draining its queue).
        reason = _describe_auto_disable_status(status)
        popup_text = (
            f'The configured Discord webhook URL is no longer valid and has been disabled.\n\n'
            f'Reason: {reason} (HTTP {status})\n\n'
            f'URL: {url}\n\n'
            f'Open Settings -> Discord and paste a new webhook URL to resume posting.'
        )
        Thread(
            target=msgbox.show,
            args=(
                f'{TITLE} - Discord Webhook Disabled',
                popup_text,
                msgbox.Style.MB_OK | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_SETFOREGROUND,
            ),
            name='DiscordWebhookAutoDisableNotice',
            daemon=True,
        ).start()
