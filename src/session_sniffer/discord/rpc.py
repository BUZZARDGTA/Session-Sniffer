"""The module manages the integration with Discord Rich Presence (RPC) to display custom status updates.

It connects to Discord using a provided client ID, updates the presence state with a message, and provides
functionality to update or close the presence. It uses threading to run the update process asynchronously.
"""

import contextlib
import os
import socket
import struct
import sys
import time
import uuid
from enum import Enum, auto
from pathlib import Path
from queue import SimpleQueue
from threading import Event, Thread
from typing import BinaryIO, NamedTuple

from pydantic import BaseModel, ValidationError

from session_sniffer.constants.standalone import GITHUB_REPO_URL
from session_sniffer.error_messages import ensure_instance
from session_sniffer.logging_setup import get_logger
from session_sniffer.models import (
    DiscordActivity,
    DiscordActivityArgs,
    DiscordActivityButton,
    DiscordActivityTimestamps,
    DiscordClosePayload,
    DiscordCommandPayload,
    DiscordHandshakePayload,
    DiscordResponsePayload,
)

_OPCODE_HANDSHAKE = 0
_OPCODE_FRAME = 1
_OPCODE_CLOSE = 2

_HEADER_FORMAT = '<II'
_HEADER_LENGTH = struct.calcsize(_HEADER_FORMAT)
_MAX_PIPE_INDEX = 10


class _PresenceUpdate(NamedTuple):
    """Payload queued for a Discord Rich Presence update."""

    state_message: str
    details: str | None


class _ShutdownSignal(Enum):
    SIGNAL = auto()


type QueueType = SimpleQueue[_PresenceUpdate | _ShutdownSignal]


SHUTDOWN_SIGNAL = _ShutdownSignal.SIGNAL
START_TIME_INT = int(time.time())
_RECONNECT_COOLDOWN_SECONDS = 60.0
DISCORD_RPC_BUTTONS = [
    DiscordActivityButton(label='GitHub Repo', url=GITHUB_REPO_URL),
]

logger = get_logger(__name__)


class _DiscordIPCConnection:
    """Manages raw communication with the local Discord IPC pipe."""

    def __init__(self, pipe_stream: BinaryIO, unix_socket: socket.socket | None = None) -> None:
        self._stream = pipe_stream
        self._unix_socket = unix_socket

    @classmethod
    def connect(cls) -> _DiscordIPCConnection | None:
        """Find and connect to an active Discord IPC pipe (0 through 9)."""
        for pipe_index in range(_MAX_PIPE_INDEX):
            if sys.platform == 'win32':
                pipe_path = Path(rf'\\.\pipe\discord-ipc-{pipe_index}')
                try:
                    stream = pipe_path.open('r+b', buffering=0)
                    return cls(pipe_stream=stream)
                except OSError:
                    continue
            elif hasattr(socket, 'AF_UNIX'):
                candidate_paths: list[Path] = []
                for environment_variable in ('XDG_RUNTIME_DIR', 'TMPDIR', 'TMP', 'TEMP'):
                    directory_path = os.environ.get(environment_variable)
                    if directory_path:
                        candidate_paths.append(Path(directory_path) / f'discord-ipc-{pipe_index}')
                candidate_paths.append(Path('/tmp') / f'discord-ipc-{pipe_index}')  # noqa: S108

                for socket_path in candidate_paths:
                    if not socket_path.exists():
                        continue
                    try:
                        unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        unix_socket.connect(str(socket_path))
                        stream = unix_socket.makefile('r+b', buffering=0)
                        return cls(pipe_stream=stream, unix_socket=unix_socket)
                    except OSError:
                        continue

        return None

    def send(self, opcode: int, payload: BaseModel) -> None:
        """Encode and send a Pydantic payload with the Discord IPC header."""
        encoded_data = payload.model_dump_json().encode('utf-8')
        header_bytes = struct.pack(_HEADER_FORMAT, opcode, len(encoded_data))
        self._stream.write(header_bytes + encoded_data)

    def receive(self) -> tuple[int, DiscordResponsePayload] | None:
        """Read and decode a frame from the Discord IPC pipe."""
        header_bytes = self._stream.read(_HEADER_LENGTH)
        if len(header_bytes) < _HEADER_LENGTH:
            return None

        opcode, payload_length = struct.unpack(_HEADER_FORMAT, header_bytes)
        payload_bytes = self._stream.read(payload_length)
        if len(payload_bytes) < payload_length:
            return None

        try:
            response_payload = DiscordResponsePayload.model_validate_json(payload_bytes)
        except ValidationError:
            return None

        return opcode, response_payload

    def close(self) -> None:
        """Close the pipe stream and any underlying socket."""
        with contextlib.suppress(OSError):
            self._stream.close()

        if self._unix_socket is not None:
            with contextlib.suppress(OSError):
                self._unix_socket.close()


class DiscordRPC:
    """Manage Discord Rich Presence updates and connection."""

    def __init__(self, client_id: int) -> None:
        """Initialize the DiscordRPC instance.

        Args:
            client_id: The client ID for connecting to Discord Rich Presence.
        """
        self._client_id = client_id
        self._closed = False
        self._queue: QueueType = SimpleQueue()

        self.connection_status = Event()

        self._thread = Thread(
            target=_run,
            name='DiscordRPCThread',
            daemon=True,
            args=(self._client_id, self._queue, self.connection_status),
        )
        self._thread.start()

        self.last_update_time: float | None = None
        self._last_queued_update: _PresenceUpdate | None = None

    def update(self, state_message: str = '', details: str | None = None) -> None:
        """Attempt to update the Discord Rich Presence.

        Args:
            state_message: If provided, the state message to display in Discord presence.
            details: If provided, the details line to display in Discord presence.
        """
        if self._closed:
            return

        self.last_update_time = time.monotonic()

        new_update = _PresenceUpdate(state_message, details)
        if new_update == self._last_queued_update:
            return

        self._last_queued_update = new_update
        if self._thread.is_alive():
            self._queue.put(new_update)

    def close(self) -> None:
        """Remove the Discord Rich Presence."""
        if self._closed:
            return

        self._closed = True
        self._queue.put(SHUTDOWN_SIGNAL)
        self._thread.join(timeout=3)


def _connect_ipc(client_id: int) -> _DiscordIPCConnection | None:
    """Establish a connection and perform the handshake with Discord."""
    connection = _DiscordIPCConnection.connect()
    if connection is None:
        return None

    try:
        connection.send(_OPCODE_HANDSHAKE, DiscordHandshakePayload(client_id=str(client_id)))
        response = connection.receive()
        if response is None:
            connection.close()
            return None

        _, payload = response
        if payload.evt == 'ERROR':
            connection.close()
            return None
    except (OSError, ValidationError, struct.error):
        connection.close()
        return None

    return connection


def _build_activity_payload(update_payload: _PresenceUpdate) -> DiscordCommandPayload:
    """Build the payload representing a Discord Rich Presence activity."""
    activity = DiscordActivity(
        state=update_payload.state_message,
        details=update_payload.details,
        timestamps=DiscordActivityTimestamps(start=START_TIME_INT),
        buttons=DISCORD_RPC_BUTTONS,
    )
    return DiscordCommandPayload(
        cmd='SET_ACTIVITY',
        args=DiscordActivityArgs(
            pid=os.getpid(),
            activity=activity,
        ),
        nonce=str(uuid.uuid4()),
    )


def _clear_activity_payload() -> DiscordCommandPayload:
    """Build the payload to clear the current Discord Rich Presence activity."""
    return DiscordCommandPayload(
        cmd='SET_ACTIVITY',
        args=DiscordActivityArgs(
            pid=os.getpid(),
            activity=None,
        ),
        nonce=str(uuid.uuid4()),
    )


def _run(client_id: int, queue: QueueType, connection_status: Event) -> None:
    """Run the Discord RPC update loop in a separate thread."""
    last_connect_attempt: float = 0.0
    active_connection: _DiscordIPCConnection | None = None

    while True:
        queue_item = queue.get()
        if queue_item is SHUTDOWN_SIGNAL:
            if active_connection is not None:
                with contextlib.suppress(OSError):
                    active_connection.send(_OPCODE_FRAME, _clear_activity_payload())
                    active_connection.send(_OPCODE_CLOSE, DiscordClosePayload())
                active_connection.close()
            connection_status.clear()
            return

        update_payload = ensure_instance(queue_item, _PresenceUpdate)

        if active_connection is None:
            now = time.monotonic()
            if now - last_connect_attempt < _RECONNECT_COOLDOWN_SECONDS:
                continue
            last_connect_attempt = now

            active_connection = _connect_ipc(client_id)
            if active_connection is None:
                logger.debug('Discord RPC connection failed')
                continue

            logger.debug('Discord RPC connected')
            connection_status.set()

        try:
            active_connection.send(_OPCODE_FRAME, _build_activity_payload(update_payload))
            active_connection.receive()
        except (OSError, ValidationError, struct.error) as e:
            logger.debug('Discord RPC pipe lost: %s: %s', type(e).__name__, e)
            active_connection.close()
            active_connection = None
            connection_status.clear()
