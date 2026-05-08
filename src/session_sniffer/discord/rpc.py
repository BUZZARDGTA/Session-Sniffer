"""The module manages the integration with Discord Rich Presence (RPC) to display custom status updates.

It connects to Discord using a provided client ID, updates the presence state with a message, and provides
functionality to update or close the presence. It uses threading to run the update process asynchronously.
"""
import time
from queue import SimpleQueue
from threading import Event, Thread
from typing import NamedTuple

import sentinel  # pyright: ignore[reportMissingTypeStubs]
from pypresence import exceptions
from pypresence.presence import Presence

from session_sniffer.error_messages import ensure_instance


class _PresenceUpdate(NamedTuple):
    """Payload queued for a Discord Rich Presence update."""
    state_message: str
    details: str | None


type QueueType = SimpleQueue[_PresenceUpdate | object]

SHUTDOWN_SIGNAL = sentinel.create('ShutdownSignal')
START_TIME_INT = int(time.time())
_RECONNECT_COOLDOWN_SECONDS = 60.0
DISCORD_RPC_BUTTONS = [
    {'label': 'GitHub Repo', 'url': 'https://github.com/BUZZARDGTA/Session-Sniffer'},
]


class DiscordRPC:
    """Manage Discord Rich Presence updates and connection."""

    def __init__(self, client_id: int) -> None:
        """Initialize the DiscordRPC instance.

        Args:
            client_id: The client ID for connecting to Discord Rich Presence.
        """
        self._rpc = Presence(client_id)
        self._closed = False
        self._queue: QueueType = SimpleQueue()

        self.connection_status = Event()

        self._thread = Thread(
            target=_run,
            name='DiscordRPCThread',
            daemon=True,
            args=(self._rpc, self._queue, self.connection_status),
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


def _run(rpc: Presence, queue: QueueType, connection_status: Event) -> None:
    """Run the Discord RPC update loop in a separate thread."""
    last_connect_attempt: float = 0.0
    while True:
        queue_item = queue.get()
        if queue_item is SHUTDOWN_SIGNAL:
            if connection_status.is_set():
                rpc.clear()
                rpc.close()
            return

        update_payload = ensure_instance(queue_item, _PresenceUpdate)
        state_message = update_payload.state_message
        details = update_payload.details

        if not connection_status.is_set():
            now = time.monotonic()
            if now - last_connect_attempt < _RECONNECT_COOLDOWN_SECONDS:
                continue
            last_connect_attempt = now
            try:
                rpc.connect()
            except (
                exceptions.DiscordNotFound,
                exceptions.DiscordError,
                exceptions.ConnectionTimeout,
                exceptions.InvalidPipe,
            ):
                continue
            else:
                connection_status.set()

        try:
            rpc.update(
                state=state_message,
                details=details,
                start=START_TIME_INT,
                buttons=DISCORD_RPC_BUTTONS,
            )
        except (exceptions.PipeClosed, exceptions.ResponseTimeout):
            rpc.close()
            connection_status.clear()
