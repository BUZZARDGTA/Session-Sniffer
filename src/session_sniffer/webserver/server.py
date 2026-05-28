"""Async web server (aiohttp) for real-time session data with WebSocket support."""

import asyncio
import base64
import binascii
import hmac
import json
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar

import aiohttp.web

from session_sniffer.logging_setup import get_logger
from session_sniffer.rendering_core.types import GUIRenderingSnapshot, GUIRenderingState

if TYPE_CHECKING:
    from asyncio import AbstractEventLoop
    from pathlib import Path

logger = get_logger(__name__)


@dataclass(slots=True, frozen=True)
class WebServerConfig:
    """Configuration values used to start the embedded web server."""

    host: str
    port: int
    static_dir: Path | None = None
    auth_username: str | None = None
    auth_password: str | None = None


class WebServer:
    """Async web server for accessing Session Sniffer data remotely."""

    _instance: ClassVar[WebServer | None] = None
    _thread: ClassVar[threading.Thread | None] = None

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
        if not authorization_header_value:
            logger.debug('Authorization rejected for %s: missing Authorization header.', request.path)
            return False

        auth_type, _, auth_value = authorization_header_value.partition(' ')
        if auth_type.casefold() != 'basic' or not auth_value:
            logger.debug('Authorization rejected for %s: invalid Authorization scheme.', request.path)
            return False

        try:
            decoded = base64.b64decode(auth_value, validate=True).decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            logger.debug('Authorization rejected for %s: malformed Basic token.', request.path)
            return False

        username, separator, password = decoded.partition(':')
        if not separator:
            logger.debug('Authorization rejected for %s: missing username/password separator.', request.path)
            return False

        authorized = (
            hmac.compare_digest(username, self.auth_username or '')
            and hmac.compare_digest(password, self.auth_password or '')
        )
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
        payload: dict[str, object] = {
            'version': version,
            'header': snapshot.status.header_text,
            'status': {
                'capture': snapshot.status.status_capture_text,
                'config': snapshot.status.status_config_text,
                'issues': snapshot.status.status_issues_text,
                'performance': snapshot.status.status_performance_text,
            },
            'connected': {
                'count': snapshot.connected.num_rows,
                'columns': snapshot.column_config.connected_column_names,
                'rows': [list(row) for row in snapshot.connected.rows],
            },
            'disconnected': {
                'count': snapshot.disconnected.num_rows,
                'columns': snapshot.column_config.disconnected_column_names,
                'rows': [list(row) for row in snapshot.disconnected.rows],
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
                if ws.closed:
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

    async def _run_async(self, stop_event: asyncio.Event) -> None:
        app = self._build_app()
        self._runner = aiohttp.web.AppRunner(app, access_log=None)
        await self._runner.setup()
        site = aiohttp.web.TCPSite(self._runner, self.host, self.port)
        await site.start()
        logger.info('Web server started on %s:%d', self.host, self.port)
        await stop_event.wait()
        await self._runner.cleanup()
        logger.info('Web server stopped.')

    def run(self) -> None:
        """Start the web server (blocks until stopped)."""
        logger.info('Starting web server on %s:%d', self.host, self.port)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._event_loop = loop
        stop_event = asyncio.Event()
        self._stop_event = stop_event
        try:
            loop.run_until_complete(self._run_async(stop_event))
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
            return

        cls._instance = cls(config)
        cls._thread = threading.Thread(
            target=cls._instance.run,
            name='webserver',
            daemon=True,
        )
        cls._thread.start()
        logger.debug('Managed web server thread started (name=%s).', cls._thread.name)

    @classmethod
    def stop_server(cls) -> None:
        """Stop the managed web server instance if one is running."""
        if cls._instance is None:
            logger.debug('Managed web server stop requested but no instance is active.')
            return

        logger.debug('Managed web server stop requested.')
        cls._instance.stop()
        if cls._thread is not None:
            cls._thread.join(timeout=2.0)
            if cls._thread.is_alive():
                logger.warning('Web server thread did not stop within timeout; keeping current instance active.')
                return

        cls._instance = None
        cls._thread = None

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
        logger.debug('Auth credentials updated on running web server (auth_enabled=%s).', bool(auth_username and auth_password))
