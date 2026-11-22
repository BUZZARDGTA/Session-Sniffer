"""Async web server (aiohttp) for real-time session data with WebSocket support."""

import asyncio
import base64
import binascii
import errno
import hmac
import ipaddress
import json
import logging
import sys
import threading
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING, Any, ClassVar, cast

import aiohttp.web
from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QRectF
from PySide6.QtGui import QColor, QImage, QImageWriter, QPainter
from PySide6.QtSvg import QSvgRenderer

from session_sniffer.constants.local import VERSION
from session_sniffer.constants.standalone import LOOKY_BASE_HOST, TITLE
from session_sniffer.constants.tables import GUI_COLUMN_HEADERS_TOOLTIPS, NUMERIC_RIGHT_ALIGNED_COLUMNS
from session_sniffer.core import terminate_on_uncaught_exception
from session_sniffer.guis.theming import ICONS_DIR_PATH, get_active_theme, get_theme_generation
from session_sniffer.i18n import get_active_language, get_web_panel_i18n, is_rtl_language, tr
from session_sniffer.player.registry import SessionTracker
from session_sniffer.rendering_core.country_flags import resolve_country_flag_path
from session_sniffer.rendering_core.types import CellColor, GUIRenderingSnapshot, GUIRenderingState
from session_sniffer.webserver.host_diagnostics import build_host_diagnostics_payload
from session_sniffer.webserver.player_details import (
    build_player_details_payload,
    build_player_seen_stats_payload,
    build_row_context_meta,
    get_known_players_map,
)
from session_sniffer.webserver.theme import build_web_theme_payload, qcolor_to_css, render_web_theme_css

if TYPE_CHECKING:
    from asyncio import AbstractEventLoop
    from collections.abc import Mapping, Sequence
    from pathlib import Path

    from session_sniffer.models.player import Player
    from session_sniffer.rendering_core.types import GUITableData

logger = logging.getLogger(__name__)

_WEB_SERVER_STARTUP_TIMEOUT_SECONDS = 3.0
_NO_STORE_HEADERS: dict[str, str] = {'Cache-Control': 'no-store'}
_FLAG_CACHE_HEADERS: dict[str, str] = {'Cache-Control': 'public, max-age=86400, immutable'}
_APP_ICON_SVG_PATH = ICONS_DIR_PATH / 'app_icon.svg'
_PWA_ICON_BACKGROUND = '#121212'
_WSAEACCES = 10013
_WSAEINVAL = 10022
_WSAENOTSOCK = 10038
_WSAEADDRINUSE = 10048
_WSAEADDRNOTAVAIL = 10049
_WSAENOTCONN = 10057
_BENIGN_ASYNCIO_WINERRORS: frozenset[int] = frozenset({_WSAEINVAL, _WSAENOTSOCK, _WSAENOTCONN})


@lru_cache(maxsize=1)
def _get_app_icon_svg_bytes() -> bytes:
    """Read and cache the application's SVG icon for web/PWA responses."""
    return _APP_ICON_SVG_PATH.read_bytes()


@lru_cache(maxsize=4)
def _render_pwa_png_icon(size: int) -> bytes:
    """Render and cache a square PNG app icon from `app_icon.svg` at *size* x *size* pixels."""
    renderer = QSvgRenderer(_get_app_icon_svg_bytes())
    image = QImage(size, size, QImage.Format.Format_ARGB32)
    image.fill(QColor(_PWA_ICON_BACKGROUND))
    margin = size * 0.14
    target_rect = QRectF(margin, margin, size - (margin * 2), size - (margin * 2))
    painter = QPainter()
    if painter.begin(image):
        try:
            renderer.render(painter, target_rect)
        finally:
            painter.end()
    buffer = QBuffer()
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    writer = QImageWriter(buffer, QByteArray(b'PNG'))
    writer.write(image)
    return bytes(buffer.data().data())


def _parse_optional_session_id(raw_value: str | None) -> tuple[int | None, bool]:
    """Parse an optional positive integer `session_id` query parameter."""
    if raw_value is None or not raw_value.strip():
        return None, True
    try:
        parsed = int(raw_value.strip())
    except ValueError:
        return None, False
    if parsed <= 0:
        return None, False
    return parsed, True


@dataclass(slots=True, frozen=True)
class WebServerStatus:
    """Snapshot of the embedded web server's current runtime state."""

    running: bool
    host: str | None = None
    port: int | None = None
    auth_enabled: bool = False
    error_code: str | None = None
    error_detail: str | None = None


def _classify_startup_error(error: Exception) -> str:
    """Map an OS socket startup exception to a stable user-facing error category."""
    if isinstance(error, PermissionError):
        return 'permission_denied'
    if isinstance(error, OSError):
        winerror = getattr(error, 'winerror', None)
        if error.errno == errno.EADDRINUSE or winerror == _WSAEADDRINUSE:
            return 'port_in_use'
        if error.errno == errno.EACCES or winerror == _WSAEACCES:
            return 'permission_denied'
        if error.errno == errno.EADDRNOTAVAIL or winerror == _WSAEADDRNOTAVAIL:
            return 'invalid_host'
    return 'startup_failed'


def format_webserver_error(status: WebServerStatus) -> str:
    """Return a plain-language localized message explaining why the web server failed to start."""
    port = status.port if status.port is not None else 80
    host = status.host or ''
    if status.error_code == 'port_in_use':
        return tr(
            'Port {port} is already in use by another app. Switch to a different port (for example 8080 or 8081) and click Save.',
            port=port,
        )
    if status.error_code == 'permission_denied':
        return tr(
            'Port {port} is blocked by system permissions or reserved by the OS. Switch to a higher port (such as 8080 or 8081) and click Save.',
            port=port,
        )
    if status.error_code == 'invalid_host':
        return tr(
            'The IP address {host} is not assigned to any network adapter on this PC. Choose Local Network or pick one of your PC IP addresses.',
            host=host,
        )
    if status.error_code == 'timeout':
        return tr('The web server took too long to start. Try again or choose a different port.')
    return tr(
        'Could not start the web server on {host}:{port}: {detail}',
        host=host,
        port=port,
        detail=status.error_detail or tr('Unknown error'),
    )


def _is_benign_asyncio_transport_error(exception: BaseException) -> bool:
    """Return `True` for benign peer-disconnect or socket-teardown errors."""
    if isinstance(exception, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return True
    if isinstance(exception, OSError):
        if getattr(exception, 'winerror', None) in _BENIGN_ASYNCIO_WINERRORS:
            return True
        if exception.errno == errno.ENOTCONN:
            return True
    return False


def _handle_asyncio_exception(_loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
    """Crash the app when an asyncio task raises an unexpected exception."""
    exc = context.get('exception')
    if exc is None:
        logger.error('Asyncio exception handler called without exception: %s', context.get('message', ''))
        return
    if isinstance(exc, asyncio.CancelledError):
        return
    # Benign transport-level disconnects and socket-teardown errors reported by
    # asyncio internals (e.g. WinError 10022/10054/10057 on abrupt peer close).
    # These are raised by socket teardown, not application logic, so don't crash.
    if _is_benign_asyncio_transport_error(exc):
        logger.debug('Ignored benign asyncio transport error: %s: %s', type(exc).__name__, exc)
        return
    terminate_on_uncaught_exception(exc)


@dataclass(slots=True, frozen=True)
class WebServerConfig:
    """Configuration values used to start the embedded web server."""

    host: str
    port: int
    static_dir: Path | None = None
    auth_username: str | None = None
    auth_password: str | None = None


@dataclass(slots=True)
class _ServerStartupState:
    """Tracks whether the server thread has finished binding its port."""

    ready: threading.Event = field(default_factory=threading.Event)
    error: Exception | None = None


class WebServer:
    """Async web server for accessing Session Sniffer data remotely."""

    _instance: ClassVar[WebServer | None] = None
    _thread: ClassVar[threading.Thread | None] = None
    _status: ClassVar[WebServerStatus] = WebServerStatus(running=False)

    def __init__(self, config: WebServerConfig) -> None:
        """Initialize the web server with the given `config`."""
        self.host = config.host
        self.port = config.port
        self.static_dir = config.static_dir
        self.auth_username = config.auth_username
        self.auth_password = config.auth_password
        self._event_loop: AbstractEventLoop | None = None
        self._stop_event: asyncio.Event | None = None
        self._runner: aiohttp.web.AppRunner | None = None
        self._websockets: set[aiohttp.web.WebSocketResponse] = set()
        logger.debug(
            'WebServer initialized host=%s port=%d static_dir=%s auth_enabled=%s',
            self.host,
            self.port,
            self.static_dir,
            self._is_auth_enabled(),
        )

    def _is_auth_enabled(self) -> bool:
        return bool(self.auth_username and self.auth_password)

    def _is_request_authorized(self, request: aiohttp.web.Request) -> bool:
        if not self._is_auth_enabled():
            return True

        authorization_header_value = request.headers.get('Authorization')
        if authorization_header_value is None or not authorization_header_value:
            logger.debug('Authorization rejected for %s: missing Authorization header.', request.path)
            return False

        auth_type, _, auth_value = authorization_header_value.partition(' ')
        if auth_type.casefold() != 'basic' or not auth_value:
            logger.debug('Authorization rejected for %s: invalid Authorization scheme.', request.path)
            return False

        try:
            decoded = base64.b64decode(auth_value, validate=True).decode('utf-8')
        except binascii.Error, UnicodeDecodeError:
            logger.debug('Authorization rejected for %s: malformed Basic token.', request.path)
            return False

        username, separator, password = decoded.partition(':')
        if not separator:
            logger.debug('Authorization rejected for %s: missing username/password separator.', request.path)
            return False

        authorized = hmac.compare_digest(username, self.auth_username or '') and hmac.compare_digest(password, self.auth_password or '')
        if not authorized:
            logger.debug('Authorization rejected for %s: credential mismatch.', request.path)
        return authorized

    @staticmethod
    def _unauthorized_response() -> aiohttp.web.Response:
        return aiohttp.web.Response(
            text='Unauthorized',
            status=401,
            headers={'WWW-Authenticate': 'Basic realm="Session Sniffer Web Panel"'},
        )

    async def _on_shutdown(self, _app: aiohttp.web.Application) -> None:
        for ws in set(self._websockets):
            await ws.close(
                code=aiohttp.WSCloseCode.GOING_AWAY,
                message=b'Server shutting down',
            )
        GUIRenderingState.wake()

    @staticmethod
    async def _drain_websocket_incoming(ws: aiohttp.web.WebSocketResponse) -> None:
        """Consume incoming WebSocket frames so client close handshakes complete promptly."""
        async for _ in ws:
            pass
        GUIRenderingState.wake()

    def _build_app(self) -> aiohttp.web.Application:
        app = aiohttp.web.Application()
        app.on_shutdown.append(self._on_shutdown)
        app.router.add_get('/', self._index)
        app.router.add_get('/theme.css', self._get_theme_css)
        app.router.add_get('/manifest.webmanifest', self._get_web_manifest)
        app.router.add_get('/icon.svg', self._get_app_icon_svg)
        app.router.add_get('/apple-touch-icon.png', self._get_apple_touch_icon)
        app.router.add_get('/icon-192.png', self._get_pwa_icon_192)
        app.router.add_get('/icon-512.png', self._get_pwa_icon_512)
        app.router.add_get('/flags/{code}.png', self._get_country_flag)
        app.router.add_get('/api/snapshot', self._get_snapshot)
        app.router.add_get('/api/player/{ip}/seen-stats', self._get_player_seen_stats)
        app.router.add_get('/api/player/{ip}', self._get_player_details)
        app.router.add_get('/api/host-diagnostics', self._get_host_diagnostics)
        app.router.add_get('/ws/updates', self._websocket_updates)
        app.router.add_get('/{filename:.+}', self._serve_static)
        return app

    @staticmethod
    def _serialize_row_style(cell_colors: tuple[CellColor, ...]) -> dict[str, object]:
        if not cell_colors:
            return {}
        first_cell = cell_colors[0]
        base_fg = qcolor_to_css(first_cell.foreground) if first_cell.foreground.isValid() else None
        base_bg = qcolor_to_css(first_cell.background) if first_cell.background is not None and first_cell.background.isValid() else None

        cell_fg: dict[str, str] = {}
        cell_bg: dict[str, str] = {}
        for index, cell in enumerate(cell_colors):
            if cell.foreground.isValid():
                fg_css = qcolor_to_css(cell.foreground)
                if fg_css != base_fg:
                    cell_fg[str(index)] = fg_css
            bg_css = qcolor_to_css(cell.background) if cell.background is not None and cell.background.isValid() else None
            if bg_css != base_bg and bg_css is not None:
                cell_bg[str(index)] = bg_css

        style: dict[str, object] = {}
        if base_fg is not None:
            style['fg'] = base_fg
        if base_bg is not None:
            style['bg'] = base_bg
        if cell_fg:
            style['cell_fg'] = cell_fg
        if cell_bg:
            style['cell_bg'] = cell_bg
        return style

    @classmethod
    def _serialize_table_payload(
        cls,
        *,
        table_data: GUITableData,
        column_keys: Sequence[str],
        players_map: Mapping[str, Player],
        session_id: int | None = None,
        include_rates: bool = False,
    ) -> dict[str, object]:
        try:
            ip_column_index = column_keys.index('IP Address')
        except ValueError:
            ip_column_index = -1

        row_meta: list[dict[str, object]] = []
        for row, _ in table_data.rows_with_colors:
            ip_address = row[ip_column_index] if 0 <= ip_column_index < len(row) else ''
            row_meta.append(
                build_row_context_meta(ip_address, players_map, session_id=session_id, include_rates=include_rates)
                if ip_address
                else {},
            )

        return {
            'count': table_data.row_count,
            'column_keys': list(column_keys),
            'columns': [tr(col) for col in column_keys],
            'column_tooltips': [tr(GUI_COLUMN_HEADERS_TOOLTIPS[col]) if col in GUI_COLUMN_HEADERS_TOOLTIPS else '' for col in column_keys],
            'numeric_columns': [index for index, col in enumerate(column_keys) if col in NUMERIC_RIGHT_ALIGNED_COLUMNS],
            'rows': [list(row) for row, _ in table_data.rows_with_colors],
            'styles': [cls._serialize_row_style(cell_colors) for _, cell_colors in table_data.rows_with_colors],
            'meta': row_meta,
        }

    @staticmethod
    def _build_meta_payload() -> dict[str, object]:
        active_lang = get_active_language()
        return {
            'type': 'meta',
            'lang': active_lang,
            'dir': 'rtl' if is_rtl_language(active_lang) else 'ltr',
            'i18n': get_web_panel_i18n(),
            'theme': build_web_theme_payload(),
            'app': {
                'title': TITLE,
                'version': VERSION,
                'looky_base_host': LOOKY_BASE_HOST,
            },
        }

    @classmethod
    def _build_past_sessions_payload(
        cls,
        snapshot: GUIRenderingSnapshot,
        disconnected_columns: Sequence[str],
    ) -> list[dict[str, object]]:
        past_sessions_payload: list[dict[str, object]] = []
        for session_id, table_data in sorted(snapshot.past_sessions.items(), reverse=True):
            display_name = SessionTracker.get_session_display_name(session_id)
            custom_name = SessionTracker.get_session_name(session_id)
            base_label = (
                tr('Session #{id} ({name})', id=session_id, name=custom_name)
                if custom_name is not None
                else tr('Session #{id}', id=session_id)
            )
            time_label = SessionTracker.get_session_time_label(session_id) or ''
            full_label = f'{base_label} ({time_label})' if time_label else base_label
            session_players_map = get_known_players_map(session_id=session_id)
            past_sessions_payload.append(
                {
                    'id': session_id,
                    'name': display_name,
                    'label': full_label,
                    'time_label': time_label,
                    'table': cls._serialize_table_payload(
                        table_data=table_data,
                        column_keys=disconnected_columns,
                        players_map=session_players_map,
                        session_id=session_id,
                    ),
                },
            )
        return past_sessions_payload

    @classmethod
    def _build_snapshot_payload(cls, snapshot: GUIRenderingSnapshot, version: int, *, message_type: str | None = None) -> dict[str, object]:
        connected_columns = snapshot.column_config.connected_column_names
        disconnected_columns = snapshot.column_config.disconnected_column_names
        active_lang = get_active_language()
        players_map = get_known_players_map()
        payload: dict[str, object] = {
            'version': version,
            'lang': active_lang,
            'dir': 'rtl' if is_rtl_language(active_lang) else 'ltr',
            'i18n': get_web_panel_i18n(),
            'theme': build_web_theme_payload(),
            'app': {
                'title': TITLE,
                'version': VERSION,
                'looky_base_host': LOOKY_BASE_HOST,
                'capture_running': snapshot.status.capture_running,
                'uptime_seconds': snapshot.status.uptime_seconds,
                'total_packets': snapshot.status.total_packets,
                'is_merged': snapshot.status.is_merged,
            },
            'status': {
                'sections': [
                    {
                        'key': section.key,
                        'title': section.title,
                        'items': [
                            {
                                'label': item.label,
                                'value': item.value,
                                'tone': item.tone,
                                'mono': item.mono,
                                'dot': item.dot,
                            }
                            for item in section.items
                        ],
                    }
                    for section in snapshot.status.status_sections
                ],
            },
            'connected': cls._serialize_table_payload(
                table_data=snapshot.connected,
                column_keys=connected_columns,
                players_map=players_map,
                include_rates=True,
            ),
            'disconnected': cls._serialize_table_payload(
                table_data=snapshot.disconnected,
                column_keys=disconnected_columns,
                players_map=players_map,
            ),
            'past_sessions': cls._build_past_sessions_payload(snapshot, disconnected_columns),
        }
        if message_type is not None:
            payload['type'] = message_type
        return payload

    async def _index(self, request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
        if not self._is_request_authorized(request):
            logger.debug('Request unauthorized: %s %s', request.method, request.path)
            return self._unauthorized_response()
        return await self._serve_static_file('index.html', headers=_NO_STORE_HEADERS)

    async def _get_theme_css(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        if not self._is_request_authorized(request):
            logger.debug('Request unauthorized: %s %s', request.method, request.path)
            return self._unauthorized_response()
        return aiohttp.web.Response(
            text=render_web_theme_css(),
            content_type='text/css',
            charset='utf-8',
            headers=_NO_STORE_HEADERS,
        )

    async def _get_web_manifest(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        if not self._is_request_authorized(request):
            logger.debug('Request unauthorized: %s %s', request.method, request.path)
            return self._unauthorized_response()
        colors = get_active_theme().colors
        manifest = {
            'name': TITLE,
            'short_name': TITLE,
            'start_url': '/',
            'scope': '/',
            'display': 'standalone',
            'background_color': colors.background,
            'theme_color': colors.menubar,
            'icons': [
                {'src': '/icon-192.png', 'sizes': '192x192', 'type': 'image/png', 'purpose': 'any maskable'},
                {'src': '/icon-512.png', 'sizes': '512x512', 'type': 'image/png', 'purpose': 'any maskable'},
                {'src': '/icon.svg', 'sizes': 'any', 'type': 'image/svg+xml'},
            ],
        }
        return aiohttp.web.Response(
            text=json.dumps(manifest),
            content_type='application/manifest+json',
            charset='utf-8',
            headers=_NO_STORE_HEADERS,
        )

    async def _get_app_icon_svg(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        if not self._is_request_authorized(request):
            logger.debug('Request unauthorized: %s %s', request.method, request.path)
            return self._unauthorized_response()
        return aiohttp.web.Response(
            body=_get_app_icon_svg_bytes(),
            content_type='image/svg+xml',
            headers=_FLAG_CACHE_HEADERS,
        )

    async def _serve_pwa_png(self, request: aiohttp.web.Request, size: int) -> aiohttp.web.Response:
        if not self._is_request_authorized(request):
            logger.debug('Request unauthorized: %s %s', request.method, request.path)
            return self._unauthorized_response()
        png_bytes = await asyncio.to_thread(_render_pwa_png_icon, size)
        return aiohttp.web.Response(
            body=png_bytes,
            content_type='image/png',
            headers=_FLAG_CACHE_HEADERS,
        )

    async def _get_apple_touch_icon(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        return await self._serve_pwa_png(request, 180)

    async def _get_pwa_icon_192(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        return await self._serve_pwa_png(request, 192)

    async def _get_pwa_icon_512(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        return await self._serve_pwa_png(request, 512)

    async def _get_country_flag(self, request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
        if not self._is_request_authorized(request):
            logger.debug('Request unauthorized: %s %s', request.method, request.path)
            return self._unauthorized_response()
        country_code = request.match_info.get('code', '')
        flag_path = resolve_country_flag_path(country_code)
        if flag_path is None:
            return aiohttp.web.Response(text='Not found', status=404)
        return aiohttp.web.FileResponse(flag_path, headers=_FLAG_CACHE_HEADERS)

    async def _get_snapshot(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        if not self._is_request_authorized(request):
            logger.debug('Request unauthorized: %s %s', request.method, request.path)
            return self._unauthorized_response()
        snapshot, version = await asyncio.to_thread(
            GUIRenderingState.wait_rendering_snapshot,
            timeout=0.1,
            last_seen_version=0,
        )
        if snapshot is None:
            logger.debug('Snapshot request returned no data (status=503).')
            return aiohttp.web.json_response({'error': 'No data available'}, status=503, headers=_NO_STORE_HEADERS)
        return aiohttp.web.json_response(self._build_snapshot_payload(snapshot, version), headers=_NO_STORE_HEADERS)

    async def _get_player_details(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        if not self._is_request_authorized(request):
            logger.debug('Request unauthorized: %s %s', request.method, request.path)
            return self._unauthorized_response()
        raw_ip = request.match_info.get('ip', '').strip()
        try:
            normalized_ip = str(ipaddress.ip_address(raw_ip))
        except ValueError:
            return aiohttp.web.json_response({'error': 'Invalid IP address'}, status=400, headers=_NO_STORE_HEADERS)
        session_id, valid_session_id = _parse_optional_session_id(request.query.get('session_id'))
        if not valid_session_id:
            return aiohttp.web.json_response({'error': 'Invalid session_id'}, status=400, headers=_NO_STORE_HEADERS)
        payload = await asyncio.to_thread(build_player_details_payload, normalized_ip, session_id=session_id)
        if payload is None:
            return aiohttp.web.json_response({'error': 'Player not found'}, status=404, headers=_NO_STORE_HEADERS)
        return aiohttp.web.json_response(payload, headers=_NO_STORE_HEADERS)

    async def _get_player_seen_stats(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        if not self._is_request_authorized(request):
            logger.debug('Request unauthorized: %s %s', request.method, request.path)
            return self._unauthorized_response()
        raw_ip = request.match_info.get('ip', '').strip()
        try:
            normalized_ip = str(ipaddress.ip_address(raw_ip))
        except ValueError:
            return aiohttp.web.json_response({'error': 'Invalid IP address'}, status=400, headers=_NO_STORE_HEADERS)
        payload = await asyncio.to_thread(build_player_seen_stats_payload, normalized_ip)
        return aiohttp.web.json_response(payload, headers=_NO_STORE_HEADERS)

    async def _get_host_diagnostics(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        if not self._is_request_authorized(request):
            logger.debug('Request unauthorized: %s %s', request.method, request.path)
            return self._unauthorized_response()
        raw_ip = (request.query.get('ip') or '').strip()
        normalized_ip: str | None = None
        if raw_ip:
            try:
                normalized_ip = str(ipaddress.ip_address(raw_ip))
            except ValueError:
                return aiohttp.web.json_response({'error': 'Invalid IP address'}, status=400, headers=_NO_STORE_HEADERS)
        session_id, valid_session_id = _parse_optional_session_id(request.query.get('session_id'))
        if not valid_session_id:
            return aiohttp.web.json_response({'error': 'Invalid session_id'}, status=400, headers=_NO_STORE_HEADERS)
        payload = await asyncio.to_thread(build_host_diagnostics_payload, ip_address=normalized_ip, session_id=session_id)
        return aiohttp.web.json_response(payload, headers=_NO_STORE_HEADERS)

    async def _serve_static(self, request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
        if not self._is_request_authorized(request):
            logger.debug('Request unauthorized: %s %s', request.method, request.path)
            return self._unauthorized_response()
        filename = request.match_info.get('filename', '')
        return await self._serve_static_file(filename)

    async def _serve_static_file(self, filename: str, *, headers: dict[str, str] | None = None) -> aiohttp.web.StreamResponse:
        if not self.static_dir:
            logger.debug('Static file request failed for %s: static_dir is not configured.', filename)
            return aiohttp.web.Response(text='Static files not configured', status=404)

        static_root = self.static_dir.resolve()
        file_path = (static_root / filename).resolve()
        if not file_path.is_relative_to(static_root):
            logger.debug('Static file request rejected for %s: path traversal detected.', filename)
            return aiohttp.web.Response(text='Not found', status=404)
        if not file_path.is_file():
            logger.debug('Static file request failed for %s: not found at %s', filename, file_path)
            return aiohttp.web.Response(text='Not found', status=404)

        try:
            logger.debug('Serving static file %s', file_path)
            return aiohttp.web.FileResponse(file_path, headers=headers)
        except OSError:
            logger.exception('Error serving file %s', filename)
            return aiohttp.web.Response(text='Internal server error', status=500)

    async def _websocket_updates(self, request: aiohttp.web.Request) -> aiohttp.web.WebSocketResponse:
        if not self._is_request_authorized(request):
            logger.debug('WebSocket unauthorized: %s', request.path)
            raise aiohttp.web.HTTPUnauthorized(headers={'WWW-Authenticate': 'Basic realm="Session Sniffer Web Panel"'})

        ws = aiohttp.web.WebSocketResponse()
        await ws.prepare(request)

        self._websockets.add(ws)
        logger.info('WebSocket client connected (total: %d)', len(self._websockets))
        reader_task = asyncio.create_task(self._drain_websocket_incoming(ws))

        try:
            last_version = 0
            last_theme_generation = -1
            last_language = ''
            while not ws.closed:
                snapshot, version = await asyncio.to_thread(
                    GUIRenderingState.wait_rendering_snapshot,
                    timeout=5.0,
                    last_seen_version=last_version,
                )
                if cast('bool', ws.closed):
                    break
                if snapshot is None:
                    current_theme_generation = get_theme_generation()
                    current_language = get_active_language()
                    if last_theme_generation != current_theme_generation or last_language != current_language:
                        last_theme_generation = current_theme_generation
                        last_language = current_language
                        await ws.send_str(json.dumps(self._build_meta_payload()))
                    else:
                        await ws.send_str(json.dumps({'type': 'keep-alive'}))
                    continue
                last_version = version
                last_theme_generation = get_theme_generation()
                last_language = get_active_language()
                await ws.send_str(json.dumps(self._build_snapshot_payload(snapshot, version, message_type='snapshot')))
        except ConnectionResetError:
            logger.warning('WebSocket connection reset unexpectedly.')
        finally:
            reader_task.cancel()
            await asyncio.gather(reader_task, return_exceptions=True)
            self._websockets.discard(ws)
            logger.info('WebSocket client disconnected (total: %d)', len(self._websockets))

        return ws

    async def _run_async(self, stop_event: asyncio.Event, startup_state: _ServerStartupState) -> None:
        app = self._build_app()
        self._runner = aiohttp.web.AppRunner(app, access_log=None)
        try:
            await self._runner.setup()
            site = aiohttp.web.TCPSite(self._runner, self.host, self.port)
            await site.start()
        except OSError as e:
            if _classify_startup_error(e) == 'startup_failed':
                logger.exception('Failed to start web server on %s:%d', self.host, self.port)
            else:
                logger.debug('Web server failed to bind on %s:%d: %s', self.host, self.port, e)
            startup_state.error = e
            startup_state.ready.set()
            await self._runner.cleanup()
            return
        startup_state.ready.set()
        logger.info('Web server started on %s:%d', self.host, self.port)
        await stop_event.wait()
        await self._runner.cleanup()
        logger.info('Web server stopped.')

    def run(self, startup_state: _ServerStartupState) -> None:
        """Start the web server (blocks until stopped)."""
        logger.debug('Starting web server on %s:%d', self.host, self.port)
        # Use `SelectorEventLoop` on Windows to avoid CPython's `ProactorEventLoop`
        # `_call_connection_lost` calling unguarded `socket.shutdown(SHUT_RDWR)`
        # on already-closed/reset client sockets (WinError 10022 / 10054), which
        # raises in callback teardown and skips socket close / server detach.
        loop = asyncio.SelectorEventLoop() if sys.platform == 'win32' else asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.set_exception_handler(_handle_asyncio_exception)
        self._event_loop = loop
        stop_event = asyncio.Event()
        self._stop_event = stop_event
        try:
            loop.run_until_complete(self._run_async(stop_event, startup_state))
        finally:
            loop.close()
            self._event_loop = None
            self._stop_event = None

    def stop(self) -> None:
        """Request web server shutdown."""
        if self._event_loop is not None and self._event_loop.is_running() and self._stop_event is not None:
            logger.debug('Scheduling web server stop on event loop thread.')
            self._event_loop.call_soon_threadsafe(self._stop_event.set)
            GUIRenderingState.wake()
            return
        logger.debug('Web server stop requested but event loop is not running.')

    @classmethod
    def get_status(cls) -> WebServerStatus:
        """Return a snapshot of the managed web server's current state."""
        return cls._status

    @classmethod
    def is_running(cls) -> bool:
        """Return `True` when the managed web server is actively listening."""
        return cls._status.running and cls._instance is not None

    @classmethod
    def _cleanup_instance(cls) -> bool:
        """Stop and clear the running server instance and thread without altering `_status`.

        Returns:
            `True` if no server thread remains active, `False` if shutdown timed out.
        """
        if cls._instance is None:
            return True

        cls._instance.stop()
        if cls._thread is not None:
            cls._thread.join(timeout=2.0)
            if cls._thread.is_alive():
                logger.warning('Web server thread did not stop within timeout; keeping current instance active.')
                return False

        cls._instance = None
        cls._thread = None
        return True

    @classmethod
    def start_server(
        cls,
        *,
        config: WebServerConfig,
    ) -> None:
        """Start a managed web server instance in a daemon thread."""
        logger.debug('Managed web server start requested for %s:%d', config.host, config.port)
        cls.stop_server()
        if cls._instance is not None:
            logger.error('Web server restart skipped because the previous instance is still shutting down.')
            cls._status = WebServerStatus(
                running=False,
                host=config.host,
                port=config.port,
                error_code='timeout',
                error_detail='Previous web server instance is still shutting down.',
            )
            return

        startup_state = _ServerStartupState()
        cls._instance = cls(config)
        cls._thread = threading.Thread(
            target=cls._instance.run,
            args=(startup_state,),
            name='webserver',
            daemon=True,
        )
        cls._thread.start()
        logger.debug('Managed web server thread started (name=%s).', cls._thread.name)

        if not startup_state.ready.wait(timeout=_WEB_SERVER_STARTUP_TIMEOUT_SECONDS):
            logger.error(
                'Web server startup timed out after %.1f s; stopping.',
                _WEB_SERVER_STARTUP_TIMEOUT_SECONDS,
            )
            cls._cleanup_instance()
            cls._status = WebServerStatus(
                running=False,
                host=config.host,
                port=config.port,
                error_code='timeout',
            )
            return

        if startup_state.error is not None:
            error_code = _classify_startup_error(startup_state.error)
            if error_code == 'port_in_use':
                logger.error(
                    'Web server failed to start: port %d on %s is already in use by another process. '
                    'Change the Web Server port in Settings or stop the conflicting application.',
                    config.port,
                    config.host,
                )
            elif error_code == 'permission_denied':
                logger.error(
                    'Web server failed to start: port %d on %s is blocked by system permissions or reserved by the OS. '
                    'Change the Web Server port in Settings or run with sufficient privileges.',
                    config.port,
                    config.host,
                )
            elif error_code == 'invalid_host':
                logger.error(
                    'Web server failed to start: host address %s is not assigned to any local network adapter. '
                    'Choose Local Network or a valid adapter IP address in Settings.',
                    config.host,
                )
            else:
                logger.error('Web server failed to start on %s:%d: %r', config.host, config.port, startup_state.error)
            cls._cleanup_instance()
            cls._status = WebServerStatus(
                running=False,
                host=config.host,
                port=config.port,
                error_code=error_code,
                error_detail=str(startup_state.error),
            )
            return

        cls._status = WebServerStatus(
            running=True,
            host=config.host,
            port=config.port,
            auth_enabled=bool(config.auth_username and config.auth_password),
        )

    @classmethod
    def stop_server(cls) -> None:
        """Stop the managed web server instance if one is running."""
        if cls._instance is None:
            logger.debug('Managed web server stop requested but no instance is active.')
            cls._status = WebServerStatus(running=False)
            return

        logger.debug('Managed web server stop requested.')
        if cls._cleanup_instance():
            cls._status = WebServerStatus(running=False)

    @classmethod
    def update_auth_credentials(
        cls,
        *,
        auth_username: str | None,
        auth_password: str | None,
    ) -> None:
        """Update auth credentials on the running server without restarting it."""
        if cls._instance is None:
            logger.debug('Auth credential update skipped: no active web server instance.')
            return

        cls._instance.auth_username = auth_username
        cls._instance.auth_password = auth_password
        auth_enabled = bool(auth_username and auth_password)
        if cls._status.running:
            cls._status = WebServerStatus(
                running=True,
                host=cls._status.host,
                port=cls._status.port,
                auth_enabled=auth_enabled,
            )
        logger.debug('Auth credentials updated on running web server (auth_enabled=%s).', auth_enabled)
