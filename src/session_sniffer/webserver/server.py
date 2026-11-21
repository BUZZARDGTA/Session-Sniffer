"""Async web server (aiohttp) for real-time session data with WebSocket support."""

import asyncio
import base64
import binascii
import errno
import hmac
import json
import logging
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, cast

import aiohttp.web

from session_sniffer.core import terminate_on_uncaught_exception
from session_sniffer.i18n import get_active_language, get_web_panel_i18n, is_rtl_language, tr
from session_sniffer.rendering_core.types import GUIRenderingSnapshot, GUIRenderingState

if TYPE_CHECKING:
    from asyncio import AbstractEventLoop
    from pathlib import Path

logger = logging.getLogger(__name__)

_WEB_SERVER_STARTUP_TIMEOUT_SECONDS = 3.0
_WSAEACCES = 10013
_WSAEADDRINUSE = 10048
_WSAEADDRNOTAVAIL = 10049


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


def _handle_asyncio_exception(_loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
    """Crash the app when an asyncio task raises an unexpected exception."""
    exc = context.get('exception')
    if exc is None:
        logger.error('Asyncio exception handler called without exception: %s', context.get('message', ''))
        return
    if isinstance(exc, asyncio.CancelledError):
        return
    # Benign transport-level disconnects reported by the Windows proactor during
    # connection teardown (e.g. WinError 10054 from `_call_connection_lost`).
    # These are logged by asyncio itself, not raised by our code, so don't crash.
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
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

    def _build_app(self) -> aiohttp.web.Application:
        app = aiohttp.web.Application()
        app.on_shutdown.append(self._on_shutdown)
        app.router.add_get('/', self._index)
        app.router.add_get('/api/snapshot', self._get_snapshot)
        app.router.add_get('/ws/updates', self._websocket_updates)
        app.router.add_get('/{filename:.+}', self._serve_static)
        return app

    @staticmethod
    def _build_snapshot_payload(snapshot: GUIRenderingSnapshot, version: int, *, message_type: str | None = None) -> dict[str, object]:
        connected_columns = snapshot.column_config.connected_column_names
        disconnected_columns = snapshot.column_config.disconnected_column_names
        active_lang = get_active_language()
        payload: dict[str, object] = {
            'version': version,
            'lang': active_lang,
            'dir': 'rtl' if is_rtl_language(active_lang) else 'ltr',
            'i18n': get_web_panel_i18n(),
            'header': snapshot.status.header_text,
            'status': {
                'capture': snapshot.status.status_capture_text,
                'config': snapshot.status.status_config_text,
                'issues': snapshot.status.status_issues_text,
                'performance': snapshot.status.status_performance_text,
            },
            'connected': {
                'count': snapshot.connected.row_count,
                'column_keys': list(connected_columns),
                'columns': [tr(col) for col in connected_columns],
                'rows': [list(row) for row, _ in snapshot.connected.rows_with_colors],
            },
            'disconnected': {
                'count': snapshot.disconnected.row_count,
                'column_keys': list(disconnected_columns),
                'columns': [tr(col) for col in disconnected_columns],
                'rows': [list(row) for row, _ in snapshot.disconnected.rows_with_colors],
            },
        }
        if message_type is not None:
            payload['type'] = message_type
        return payload

    async def _index(self, request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
        if not self._is_request_authorized(request):
            logger.debug('Request unauthorized: %s %s', request.method, request.path)
            return self._unauthorized_response()
        return await self._serve_static_file('index.html')

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
            return aiohttp.web.json_response({'error': 'No data available'}, status=503)
        return aiohttp.web.json_response(self._build_snapshot_payload(snapshot, version))

    async def _serve_static(self, request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
        if not self._is_request_authorized(request):
            logger.debug('Request unauthorized: %s %s', request.method, request.path)
            return self._unauthorized_response()
        filename = request.match_info.get('filename', '')
        return await self._serve_static_file(filename)

    async def _serve_static_file(self, filename: str) -> aiohttp.web.StreamResponse:
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
            return aiohttp.web.FileResponse(file_path)
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

        try:
            last_version = 0
            while not ws.closed:
                snapshot, version = await asyncio.to_thread(
                    GUIRenderingState.wait_rendering_snapshot,
                    timeout=5.0,
                    last_seen_version=last_version,
                )
                if cast('bool', ws.closed):
                    break
                if snapshot is None:
                    await ws.send_str(json.dumps({'type': 'keep-alive'}))
                    continue
                last_version = version
                await ws.send_str(json.dumps(self._build_snapshot_payload(snapshot, version, message_type='snapshot')))
        except ConnectionResetError:
            logger.warning('WebSocket connection reset unexpectedly.')
        finally:
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
            logger.exception('Failed to start web server on %s:%d', self.host, self.port)
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
        loop = asyncio.new_event_loop()
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
