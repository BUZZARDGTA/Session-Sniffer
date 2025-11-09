"""This module manages the integration with Discord Rich Presence (RPC) to display custom status updates.

It connects to Discord using a provided client ID, updates the presence state with a message, and provides
functionality to update or close the presence. It uses threading to run the update process asynchronously.
"""
import time
from queue import SimpleQueue
from threading import Event, Thread

import sentinel  # pyright: ignore[reportMissingTypeStubs]
from pypresence import exceptions
from pypresence.presence import Presence

from modules.utils import format_type_error

QueueType = SimpleQueue[str | object]

SHUTDOWN_SIGNAL = sentinel.create('ShutdownSignal')  # pyright: ignore[reportUnknownMemberType]
DISCORD_RPC_TITLE = "Sniffin' my babies IPs"
START_TIME_INT = int(time.time())
DISCORD_RPC_BUTTONS = [
    {'label': 'GitHub Repo', 'url': 'https://github.com/BUZZARDGTA/Session-Sniffer'},
]


class DiscordRPC:
    """Manage Discord Rich Presence updates and connection."""

    def __init__(self, client_id: int) -> None:
        """Initialize the DiscordRPC instance.

        Args:
            client_id (int): The client ID for connecting to Discord Rich Presence.
        """
        self._rpc = Presence(client_id)
        self._closed = False
        self._queue: QueueType = SimpleQueue()

        self.connection_status = Event()

        self._thread = Thread(
            target=_run,
            name='DiscordRPCThread',
            args=(self._rpc, self._queue, self.connection_status),
        )
        self._thread.start()

        self.last_update_time: float | None = None

    def update(self, state_message: str = '') -> None:
        """Attempt to update the Discord Rich Presence.

        Args:
            state_message (optional): If provided, the state message to display in Discord presence.
        """
        if self._closed:
            return

        self.last_update_time = time.monotonic()

        if self._thread.is_alive():
            self._queue.put(state_message)

    def close(self) -> None:
        """Remove the Discord Rich Presence."""
        if self._closed:
            return

        self._closed = True
        self._queue.put(SHUTDOWN_SIGNAL)
        self._thread.join(timeout=3)


def _run(rpc: Presence, queue: QueueType, connection_status: Event) -> None:
    """Run the Discord RPC update loop in a separate thread."""
    while True:
        queue_item = queue.get()
        if queue_item is SHUTDOWN_SIGNAL:
            if connection_status.is_set():
                rpc.clear()
                rpc.close()
            return

        if not isinstance(queue_item, str):
            raise TypeError(format_type_error(queue_item, str))

        state_message = queue_item

        if not connection_status.is_set():
            try:
                rpc.connect()
            except (exceptions.DiscordNotFound, exceptions.DiscordError):
                continue
            else:
                connection_status.set()

        try:
            rpc.update(  # pyright: ignore[reportUnknownMemberType]
                state=state_message,
                details=DISCORD_RPC_TITLE,
                start=START_TIME_INT,
                buttons=DISCORD_RPC_BUTTONS,
            )
        except (exceptions.PipeClosed, exceptions.ResponseTimeout):
            connection_status.clear()
