"""Cross-platform single-instance lock and local focus-handoff IPC.

This module intentionally uses only the Python standard library, `constants.standalone`,
and `ctypes_windows` so duplicate launches can detect an existing instance, signal it
to focus its active window, and exit before importing PySide6, logging handlers, or
application subsystems.
"""

import contextlib
import hmac
import json
import logging
import os
import secrets
import socket
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

if sys.platform != 'win32':
    import fcntl
    import pwd

from session_sniffer.constants.standalone import TITLE
from session_sniffer.ctypes_windows import acquire_win32_named_mutex, allow_set_foreground_window, release_win32_handle

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

_WIN32_MUTEX_NAME = r'Local\SessionSniffer_SingleInstance'
_LOCK_FILENAME = 'single_instance.lock'
_IPC_FILENAME = 'single_instance.ipc'
_IPC_HOST = '127.0.0.1'
_IPC_COMMAND_PREFIX = 'ACTIVATE '
_IPC_ACK = b'OK\n'
_IPC_MAX_LINE_BYTES = 256
_IPC_CONNECT_TIMEOUT_SECONDS = 0.5
_IPC_ACCEPT_TIMEOUT_SECONDS = 0.5
_IPC_NOTIFY_DEADLINE_SECONDS = 1.0
_IPC_NOTIFY_RETRY_INTERVAL_SECONDS = 0.05
_IPC_THREAD_JOIN_TIMEOUT_SECONDS = 0.5
_MIN_PORT = 1
_MAX_PORT = 65535


@dataclass(slots=True)
class _SingleInstanceState:
    """Process-wide ownership state for the single-instance lock and IPC listener."""

    acquired: bool = False
    win32_mutex_handle: int | None = None
    posix_lock_fd: int | None = None
    ipc_socket: socket.socket | None = None
    ipc_thread: threading.Thread | None = None
    ipc_token: str | None = None
    ipc_file_path: Path | None = None
    stop_event: threading.Event | None = None
    activation_handler: Callable[[], None] | None = None
    pending_activation: bool = False


_state_lock = threading.RLock()
_state = _SingleInstanceState()


def _get_posix_target_identity() -> tuple[int, int, Path] | None:
    """Return `(uid, gid, home_dir)` of the invoking user when running under `sudo` on POSIX."""
    if sys.platform != 'win32':
        sudo_user = os.environ.get('SUDO_USER', '')
        if bool(os.geteuid()) or not sudo_user:
            return None
        try:
            password_record = pwd.getpwnam(sudo_user)
            return password_record.pw_uid, password_record.pw_gid, Path(password_record.pw_dir)
        except KeyError, OSError:
            return None
    return None


def _repair_posix_ownership(target_path: Path) -> None:
    """Repair *target_path* ownership to the invoking `SUDO_USER` when running elevated on POSIX."""
    if sys.platform != 'win32':
        identity = _get_posix_target_identity()
        if identity is None:
            return
        target_uid, target_gid, _ = identity
        with contextlib.suppress(OSError):
            stat_info = target_path.stat()
            if stat_info.st_uid != target_uid or stat_info.st_gid != target_gid:
                os.chown(target_path, target_uid, target_gid)


def _resolve_local_app_dir() -> Path:
    """Resolve and ensure the per-user local AppData directory without importing GUI modules."""
    if sys.platform == 'win32':
        base_dir = Path(os.getenv('LOCALAPPDATA') or str(Path.home() / 'AppData' / 'Local'))
    else:
        identity = _get_posix_target_identity()
        user_home = identity[2] if identity is not None else Path.home()
        if sys.platform == 'darwin':
            base_dir = user_home / 'Library' / 'Application Support'
        else:
            base_dir = Path(os.getenv('XDG_DATA_HOME') or str(user_home / '.local' / 'share'))

    app_dir = base_dir / TITLE
    app_dir.mkdir(parents=True, exist_ok=True)
    _repair_posix_ownership(app_dir)
    return app_dir


def _write_ipc_endpoint_file(ipc_path: Path, *, process_id: int, port: int, token: str) -> None:
    """Atomically write the loopback IPC endpoint metadata file for secondary launches."""
    payload = json.dumps({'pid': process_id, 'port': port, 'token': token}) + '\n'
    temp_path = ipc_path.with_name(f'{ipc_path.name}.{process_id}.tmp')
    try:
        if sys.platform == 'win32':
            temp_path.write_text(payload, encoding='utf-8')
        else:
            temp_fd = os.open(temp_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
            try:
                os.write(temp_fd, payload.encode('utf-8'))
            finally:
                os.close(temp_fd)
            _repair_posix_ownership(temp_path)
        temp_path.replace(ipc_path)
        _repair_posix_ownership(ipc_path)
    except OSError:
        with contextlib.suppress(OSError):
            temp_path.unlink(missing_ok=True)
        raise


def _read_ipc_endpoint_file(ipc_path: Path) -> tuple[int, int, str] | None:
    """Read and validate `(pid, port, token)` from *ipc_path*, returning `None` if unavailable."""
    try:
        raw_text = ipc_path.read_text(encoding='utf-8')
        parsed: object = json.loads(raw_text)
    except OSError, ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    typed_data = cast('dict[str, object]', parsed)
    process_id = typed_data.get('pid')
    port = typed_data.get('port')
    token = typed_data.get('token')
    if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
        return None
    if isinstance(port, bool) or not isinstance(port, int) or not _MIN_PORT <= port <= _MAX_PORT:
        return None
    if not isinstance(token, str) or not token:
        return None
    return process_id, port, token


def _dispatch_activation() -> None:
    """Invoke the registered activation callback or queue it until the GUI finishes initializing."""
    with _state_lock:
        handler = _state.activation_handler
        if handler is None:
            _state.pending_activation = True
            return
    handler()


def _handle_ipc_client(client_socket: socket.socket, expected_token: str) -> None:
    """Validate a single local IPC activation request and trigger window focus when authorized."""
    with client_socket:
        client_socket.settimeout(_IPC_CONNECT_TIMEOUT_SECONDS)
        received_chunks: list[bytes] = []
        total_bytes = 0
        try:
            while total_bytes < _IPC_MAX_LINE_BYTES:
                chunk = client_socket.recv(_IPC_MAX_LINE_BYTES - total_bytes)
                if not chunk:
                    break
                received_chunks.append(chunk)
                total_bytes += len(chunk)
                if b'\n' in chunk:
                    break
        except OSError:
            return

        line = b''.join(received_chunks).decode('utf-8', errors='replace').strip()
        if not line.startswith(_IPC_COMMAND_PREFIX):
            return
        provided_token = line.removeprefix(_IPC_COMMAND_PREFIX)
        if not hmac.compare_digest(provided_token, expected_token):
            return
        with contextlib.suppress(OSError):
            client_socket.sendall(_IPC_ACK)
        _dispatch_activation()


def _ipc_server_loop(server_socket: socket.socket, expected_token: str, stop_event: threading.Event) -> None:
    """Listen on loopback for activation pings from duplicate Session Sniffer launches."""
    while not stop_event.is_set():
        try:
            client_socket, _ = server_socket.accept()
        except TimeoutError:
            continue
        except OSError:
            break
        _handle_ipc_client(client_socket, expected_token)


def _start_ipc_server_locked() -> None:
    """Bind an ephemeral loopback socket, publish its endpoint file, and start the listener thread."""
    ipc_path = _resolve_local_app_dir() / _IPC_FILENAME
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((_IPC_HOST, 0))
        server_socket.listen(8)
        server_socket.settimeout(_IPC_ACCEPT_TIMEOUT_SECONDS)
        bound_port = int(server_socket.getsockname()[1])
        token = secrets.token_hex(16)
        _write_ipc_endpoint_file(ipc_path, process_id=os.getpid(), port=bound_port, token=token)
    except OSError as e:
        with contextlib.suppress(OSError):
            server_socket.close()
        logger.debug('Failed to start single-instance IPC listener: %s', e)
        return

    stop_event = threading.Event()
    listener_thread = threading.Thread(
        target=_ipc_server_loop,
        name='SingleInstanceIPC',
        args=(server_socket, token, stop_event),
        daemon=True,
    )
    _state.ipc_socket = server_socket
    _state.ipc_thread = listener_thread
    _state.ipc_token = token
    _state.ipc_file_path = ipc_path
    _state.stop_event = stop_event
    listener_thread.start()


def _notify_existing_instance() -> bool:
    """Signal the already-running instance over loopback IPC to raise and focus its active window."""
    try:
        ipc_path = _resolve_local_app_dir() / _IPC_FILENAME
    except OSError:
        return False

    deadline = time.monotonic() + _IPC_NOTIFY_DEADLINE_SECONDS
    while True:
        endpoint = _read_ipc_endpoint_file(ipc_path)
        if endpoint is not None:
            existing_pid, port, token = endpoint
            if sys.platform == 'win32':
                allow_set_foreground_window(existing_pid)
            try:
                with socket.create_connection((_IPC_HOST, port), timeout=_IPC_CONNECT_TIMEOUT_SECONDS) as client_socket:
                    client_socket.settimeout(_IPC_CONNECT_TIMEOUT_SECONDS)
                    client_socket.sendall(f'{_IPC_COMMAND_PREFIX}{token}\n'.encode('ascii'))
                    ack = client_socket.recv(len(_IPC_ACK))
                    if ack.startswith(_IPC_ACK):
                        return True
            except OSError:
                pass
        elif sys.platform == 'win32':
            allow_set_foreground_window()

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(_IPC_NOTIFY_RETRY_INTERVAL_SECONDS, remaining))


def _acquire_posix_lock() -> tuple[int | None, bool]:
    """Acquire a non-blocking exclusive `flock` on POSIX and return `(fd, already_exists)`."""
    if sys.platform != 'win32':
        lock_path = _resolve_local_app_dir() / _LOCK_FILENAME
        lock_fd: int | None = None
        try:
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            _repair_posix_ownership(lock_path)
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            if lock_fd is not None:
                with contextlib.suppress(OSError):
                    os.close(lock_fd)
            return None, True
        except OSError as e:
            if lock_fd is not None:
                with contextlib.suppress(OSError):
                    os.close(lock_fd)
            logger.debug('Failed to acquire POSIX single-instance lock: %s', e)
            return None, False
        return lock_fd, False
    return None, False


def acquire_single_instance() -> bool:
    """Acquire the process-wide single-instance lock, returning `False` if another instance is running.

    Idempotent when already acquired by this process. When another instance holds the lock,
    attempts to wake and focus its active window before returning `False`.
    """
    with _state_lock:
        if _state.acquired:
            return True

        if sys.platform == 'win32':
            mutex_handle, already_exists = acquire_win32_named_mutex(_WIN32_MUTEX_NAME)
            if already_exists:
                _notify_existing_instance()
                return False
            _state.win32_mutex_handle = mutex_handle
        else:
            posix_lock_fd, already_exists = _acquire_posix_lock()
            if already_exists:
                _notify_existing_instance()
                return False
            _state.posix_lock_fd = posix_lock_fd

        _state.acquired = True
        _start_ipc_server_locked()
        return True


def register_activation_handler(handler: Callable[[], None]) -> None:
    """Register *handler* to run whenever a duplicate launch requests focusing this instance."""
    with _state_lock:
        _state.activation_handler = handler
        should_trigger_immediately = _state.pending_activation
        _state.pending_activation = False
    if should_trigger_immediately:
        handler()


def release_single_instance() -> None:
    """Stop the IPC listener and release the single-instance OS kernel lock.

    Must be called right before spawning a self-relaunch child process (such as the
    self-updater or Linux capability relaunch) so the new process can acquire the lock
    immediately without self-blocking.
    """
    with _state_lock:
        if not _state.acquired:
            return
        _state.acquired = False
        _state.activation_handler = None
        _state.pending_activation = False

        stop_event = _state.stop_event
        ipc_socket = _state.ipc_socket
        ipc_thread = _state.ipc_thread
        ipc_token = _state.ipc_token
        ipc_file_path = _state.ipc_file_path
        win32_mutex_handle = _state.win32_mutex_handle
        posix_lock_fd = _state.posix_lock_fd

        _state.stop_event = None
        _state.ipc_socket = None
        _state.ipc_thread = None
        _state.ipc_token = None
        _state.ipc_file_path = None
        _state.win32_mutex_handle = None
        _state.posix_lock_fd = None

    if stop_event is not None:
        stop_event.set()
    if ipc_socket is not None:
        with contextlib.suppress(OSError):
            ipc_socket.close()
    if ipc_thread is not None and ipc_thread.is_alive() and threading.current_thread() is not ipc_thread:
        ipc_thread.join(timeout=_IPC_THREAD_JOIN_TIMEOUT_SECONDS)

    if ipc_file_path is not None and ipc_token is not None:
        current_endpoint = _read_ipc_endpoint_file(ipc_file_path)
        if current_endpoint is not None and hmac.compare_digest(current_endpoint[2], ipc_token):
            with contextlib.suppress(OSError):
                ipc_file_path.unlink(missing_ok=True)

    if sys.platform == 'win32':
        if win32_mutex_handle is not None:
            release_win32_handle(win32_mutex_handle)
    elif posix_lock_fd is not None:
        with contextlib.suppress(OSError):
            fcntl.flock(posix_lock_fd, fcntl.LOCK_UN)
        with contextlib.suppress(OSError):
            os.close(posix_lock_fd)
