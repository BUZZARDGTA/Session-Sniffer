"""Async web server (Sanic) for real-time session data with WebSocket support."""

import contextlib
import json
import threading
from typing import TYPE_CHECKING, Any, ClassVar

import sanic.server.runners as sanic_runners
from sanic import Request, Sanic, text
from sanic import json as sanic_json
from sanic.response import file as sanic_file
from sanic_ext import Extend

from session_sniffer.logging_setup import get_logger
from session_sniffer.rendering_core.types import GUIRenderingState

if TYPE_CHECKING:
    from pathlib import Path

logger = get_logger(__name__)


class WebServer:
    """Async web server for accessing Session Sniffer data remotely."""

    _instance: ClassVar[WebServer | None] = None

    def __init__(self, host: str, port: int, static_dir: Path | None = None) -> None:
        """Initialize the web server.

        Args:
            host: IP address to bind to.
            port: Port number to listen on.
            static_dir: Optional path to static files directory.
        """
        self.host = host
        self.port = port
        self.static_dir = static_dir
        self.app = Sanic('session_sniffer')
        Extend(self.app)
        self._connected_clients: set[str] = set()
        self._setup_routes()

    def _suppress_sanic_signal_registration(self) -> contextlib.AbstractContextManager[None]:
        """Prevent Sanic from calling signal.signal() in non-main threads."""
        if threading.current_thread() is threading.main_thread():
            return contextlib.nullcontext()

        @contextlib.contextmanager
        def _patch_signal_func() -> contextlib.AbstractContextManager[None]:
            original_signal_func = sanic_runners.signal_func

            def _noop_signal_func(*_args: object, **_kwargs: object) -> None:
                return None

            sanic_runners.signal_func = _noop_signal_func
            try:
                yield
            finally:
                sanic_runners.signal_func = original_signal_func

        return _patch_signal_func()

    def _setup_routes(self) -> None:
        """Set up all API routes and static file serving."""
        # Serve index.html on root
        @self.app.route('/', methods=['GET'])
        async def index(request: Request) -> Any:  # noqa: ARG001, ANN401
            return await self._serve_static_file('index.html')

        # API: Get current rendering snapshot
        @self.app.route('/api/snapshot', methods=['GET'])
        async def get_snapshot(request: Request) -> Any:  # noqa: ARG001, ANN401
            snapshot, version = GUIRenderingState.wait_rendering_snapshot(timeout=0.1, last_seen_version=0)
            if snapshot is None:
                return sanic_json({'error': 'No data available'}, status=503)

            payload = {
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
            return sanic_json(payload)

        # WebSocket: Real-time updates
        @self.app.websocket('/ws/updates')
        async def websocket_updates(request: Request, ws: Any) -> None:  # noqa: ARG001, ANN401
            """WebSocket endpoint for real-time snapshot updates."""
            client_id = str(id(ws))
            self._connected_clients.add(client_id)
            logger.info('WebSocket client connected: %s (total: %d)', client_id, len(self._connected_clients))

            try:
                last_version = 0
                while True:
                    # Wait for new snapshot with 5 second timeout
                    snapshot, version = GUIRenderingState.wait_rendering_snapshot(
                        timeout=5.0,
                        last_seen_version=last_version,
                    )

                    if snapshot is None:
                        # Timeout - send keep-alive
                        await ws.send(json.dumps({'type': 'keep-alive'}))
                        continue

                    last_version = version

                    # Send full snapshot
                    payload = {
                        'type': 'snapshot',
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
                    await ws.send(json.dumps(payload))
            except Exception:  # pylint: disable=broad-except  # noqa: BLE001
                logger.warning('WebSocket error for client %s', client_id, exc_info=True)
            finally:
                self._connected_clients.discard(client_id)
                logger.info('WebSocket client disconnected: %s (total: %d)', client_id, len(self._connected_clients))

        # Static file serving
        @self.app.route('/<filename:path>', methods=['GET'])
        async def serve_static(request: Request, filename: str) -> Any:  # noqa: ARG001, ANN401
            return await self._serve_static_file(filename)

    async def _serve_static_file(self, filename: str) -> Any:  # noqa: ANN401
        """Serve a static file from the static directory."""
        if not self.static_dir:
            return text('Static files not configured', status=404)

        file_path = self.static_dir / filename
        if not file_path.exists() or not file_path.is_file():
            return text('Not found', status=404)

        try:
            return await sanic_file(str(file_path))
        except Exception:  # pylint: disable=broad-except
            logger.exception('Error serving file %s', filename)
            return text('Internal server error', status=500)

    def run(self) -> None:
        """Start the web server (blocks until stopped)."""
        logger.info('Starting web server on %s:%d', self.host, self.port)
        try:
            with self._suppress_sanic_signal_registration():
                self.app.run(
                    host=self.host,
                    port=self.port,
                    single_process=True,
                    auto_reload=False,
                    access_log=False,
                    register_sys_signals=False,
                )
        except Exception:  # pylint: disable=broad-except
            logger.exception('Web server error')
