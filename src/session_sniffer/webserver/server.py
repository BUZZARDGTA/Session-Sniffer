"""Async web server (Sanic) for real-time session data with WebSocket support."""

import asyncio
import base64
import binascii
import contextlib
import hmac
import json
import threading
import warnings
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, cast
from unittest.mock import patch

from sanic import HTTPResponse, Request, Sanic, Websocket, text
from sanic import json as sanic_json
from sanic.exceptions import WebsocketClosed
from sanic.response import file as sanic_file
from sanic_ext import Extend
from websockets.exceptions import ConnectionClosed

from session_sniffer.logging_setup import get_logger
from session_sniffer.rendering_core.types import GUIRenderingSnapshot, GUIRenderingState
from session_sniffer.utils import is_pyinstaller_compiled

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
        """Initialize the web server.

        Args:
            config: Web server startup configuration.
        """
        self.host = config.host
        self.port = config.port
        self.static_dir = config.static_dir
        self.auth_username = config.auth_username
        self.auth_password = config.auth_password
        self.app = Sanic('session_sniffer')
        Extend(self.app)
        self._event_loop: AbstractEventLoop | None = None
        self.app.register_listener(self._on_after_server_start, 'after_server_start')
        self.app.register_listener(self._on_after_server_stop, 'after_server_stop')
        self._connected_clients: set[str] = set()
        self._setup_routes()
        logger.debug(
            'WebServer initialized host=%s port=%d static_dir=%s auth_enabled=%s',
            self.host,
            self.port,
            self.static_dir,
            self._is_auth_enabled(),
        )

    async def _on_after_server_start(self, _app: object) -> None:
        self._event_loop = asyncio.get_running_loop()
        logger.debug('Web server event loop attached (thread=%s).', threading.current_thread().name)

    async def _on_after_server_stop(self, _app: object) -> None:
        self._event_loop = None
        logger.debug('Web server event loop detached (thread=%s).', threading.current_thread().name)

    def _is_auth_enabled(self) -> bool:
        return bool(self.auth_username and self.auth_password)

    def _is_request_authorized(self, request: Request) -> bool:
        if not self._is_auth_enabled():
            logger.debug('Auth bypassed for %s because credentials are not configured.', request.path)
            return True

        authorization_header_value = cast('object | None', request.headers.get('authorization'))
        if not isinstance(authorization_header_value, str) or not authorization_header_value:
            logger.debug('Authorization rejected for %s: missing Authorization header.', request.path)
            return False
        authorization_header = authorization_header_value

        auth_type, _, auth_value = authorization_header.partition(' ')
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
    def _unauthorized_response() -> HTTPResponse:
        return text(
            'Unauthorized',
            status=401,
            headers={'WWW-Authenticate': 'Basic realm="Session Sniffer Web Panel"'},
        )

    def _suppress_sanic_signal_registration(self) -> contextlib.AbstractContextManager[object]:
        """Prevent Sanic from calling signal.signal() in non-main threads."""
        if threading.current_thread() is threading.main_thread():
            return contextlib.nullcontext()

        return self._patch_sanic_signal_func()

    @staticmethod
    def _patch_sanic_signal_func() -> contextlib.AbstractContextManager[object]:
        """Temporarily replace Sanic's signal registration function with a no-op."""

        def _noop_signal_func(_signalnum: int, handler: object) -> object:
            return handler

        return patch('sanic.server.runners.signal_func', _noop_signal_func)

    def _setup_routes(self) -> None:
        """Set up all API routes and static file serving."""
        # Serve index.html on root
        self.app.add_route(self._index, '/', methods=['GET'])

        # API: Get current rendering snapshot
        self.app.add_route(self._get_snapshot, '/api/snapshot', methods=['GET'])

        # WebSocket: Real-time updates
        self.app.add_websocket_route(self._websocket_updates, '/ws/updates')

        # Static file serving
        self.app.add_route(self._serve_static, '/<filename:path>', methods=['GET'])

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

    async def _index(self, request: Request) -> HTTPResponse:
        """Serve the web UI entry point."""
        if not self._is_request_authorized(request):
            logger.debug('Request unauthorized: %s %s', request.method, request.path)
            return self._unauthorized_response()
        return await self._serve_static_file('index.html')

    async def _get_snapshot(self, request: Request) -> HTTPResponse:
        """Return the latest rendering snapshot for HTTP clients."""
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
            return sanic_json({'error': 'No data available'}, status=503)

        return sanic_json(self._build_snapshot_payload(snapshot, version))

    async def _serve_static(self, request: Request, filename: str) -> HTTPResponse:
        """Serve a static file route request."""
        if not self._is_request_authorized(request):
            logger.debug('Request unauthorized: %s %s', request.method, request.path)
            return self._unauthorized_response()
        return await self._serve_static_file(filename)

    async def _serve_static_file(self, filename: str) -> HTTPResponse:
        """Serve a static file from the static directory."""
        if not self.static_dir:
            logger.debug('Static file request failed for %s: static_dir is not configured.', filename)
            return text('Static files not configured', status=404)

        file_path = self.static_dir / filename
        if not file_path.exists() or not file_path.is_file():
            logger.debug('Static file request failed for %s: not found at %s', filename, file_path)
            return text('Not found', status=404)

        try:
            logger.debug('Serving static file %s', file_path)
            return await sanic_file(str(file_path))
        except OSError:
            logger.exception('Error serving file %s', filename)
            return text('Internal server error', status=500)

    async def _websocket_updates(self, request: Request, ws: Websocket) -> None:
        """WebSocket endpoint for real-time snapshot updates."""
        if not self._is_request_authorized(request):
            logger.debug('WebSocket unauthorized: %s', request.path)
            await ws.close(code=1008, reason='Unauthorized')
            return

        client_id = str(id(ws))
        self._connected_clients.add(client_id)
        logger.info('WebSocket client connected: %s (total: %d)', client_id, len(self._connected_clients))

        try:
            last_version = 0
            while True:
                # Wait for new snapshot with 5 second timeout
                snapshot, version = await asyncio.to_thread(
                    GUIRenderingState.wait_rendering_snapshot,
                    timeout=5.0,
                    last_seen_version=last_version,
                )

                if snapshot is None:
                    # Timeout - send keep-alive
                    await ws.send(json.dumps({'type': 'keep-alive'}))
                    continue

                last_version = version

                await ws.send(json.dumps(self._build_snapshot_payload(snapshot, version, message_type='snapshot')))
        except (ConnectionClosed, WebsocketClosed):
            logger.warning('WebSocket error for client %s', client_id, exc_info=True)
        finally:
            self._connected_clients.discard(client_id)
            logger.info('WebSocket client disconnected: %s (total: %d)', client_id, len(self._connected_clients))

    def run(self) -> None:
        """Start the web server (blocks until stopped)."""
        run_debug_mode = not is_pyinstaller_compiled()
        logger.info('Starting web server on %s:%d', self.host, self.port)
        logger.debug('Web server run invoked on thread %s (debug_mode=%s).', threading.current_thread().name, run_debug_mode)
        with warnings.catch_warnings():
            # Sanic 25.12 triggers Windows event-loop policy deprecations on Python 3.14+.
            warnings.filterwarnings(
                'ignore',
                message=".*'asyncio.get_event_loop_policy' is deprecated.*",
                category=DeprecationWarning,
                module='sanic.server.loop',
            )
            warnings.filterwarnings(
                'ignore',
                message=".*'asyncio.WindowsSelectorEventLoopPolicy' is deprecated.*",
                category=DeprecationWarning,
                module='sanic.server.loop',
            )
            warnings.filterwarnings(
                'ignore',
                message=".*'asyncio.set_event_loop_policy' is deprecated.*",
                category=DeprecationWarning,
                module='sanic.server.loop',
            )
            with self._suppress_sanic_signal_registration():
                self.app.run(
                    host=self.host,
                    port=self.port,
                    debug=run_debug_mode,
                    single_process=True,
                    auto_reload=False,
                    access_log=False,
                    register_sys_signals=False,
                )

    def stop(self) -> None:
        """Request web server shutdown."""
        if self._event_loop is not None and self._event_loop.is_running():
            logger.debug('Scheduling web server stop on event loop thread.')
            self._event_loop.call_soon_threadsafe(self.app.stop)
            return

        try:
            logger.debug('Stopping web server directly without event-loop scheduling.')
            self.app.stop()
        except RuntimeError:
            logger.warning('Unable to stop web server because Sanic event loop is unavailable.')

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
