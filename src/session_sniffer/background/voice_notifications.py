"""Background worker and queue for text-to-speech voice notifications."""

import logging
import shutil
import subprocess
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Lock, Thread
from typing import TYPE_CHECKING, Literal

if sys.platform == 'win32':
    import winsound

if TYPE_CHECKING:
    from collections.abc import Callable

from session_sniffer.background.events import gui_closed__event
from session_sniffer.settings import Settings

logger = logging.getLogger(__name__)

_VOICE_QUEUE_MAXSIZE = 10
_INTER_SOUND_PAUSE_SECONDS = 0.5
_VOICE_NOTIFICATION_THREAD_NAME = 'VoiceNotificationWorker'
_voice_notification_lock = Lock()


class _DeduplicatedQueue:
    """Bounded FIFO queue that silently rejects duplicate entries."""

    def __init__(self, maxsize: int) -> None:
        self._deque: deque[str] = deque()
        self._set: set[str] = set()
        self._lock = Lock()
        self._not_empty = Event()
        self._maxsize = maxsize

    def put(self, item: str) -> None:
        """Enqueue *item* unless it is already present or the queue is full."""
        if not Settings.voice_notifications_enabled:
            return
        with self._lock:
            if item in self._set:
                return
            if len(self._deque) >= self._maxsize:
                logger.debug('Voice queue full (%d items); dropping %s', self._maxsize, item)
                return
            self._deque.append(item)
            self._set.add(item)
            self._not_empty.set()
        ensure_voice_notification_worker_running()

    def get(self, timeout: float) -> str | None:
        """Dequeue oldest item, waiting up to *timeout* seconds, returning None on timeout while retaining duplicate rejection."""
        if not self._not_empty.wait(timeout):
            return None
        with self._lock:
            if not self._deque:
                self._not_empty.clear()
                return None
            item = self._deque.popleft()
            if not self._deque:
                self._not_empty.clear()
            return item

    def acknowledge(self, item: str) -> None:
        """Remove *item* from the duplicate-rejection set after it has been fully processed."""
        with self._lock:
            self._set.discard(item)

    def empty(self) -> bool:
        """Return True if the queue has no pending items."""
        with self._lock:
            return not self._deque

    def clear(self) -> None:
        """Remove all pending items."""
        with self._lock:
            self._deque.clear()
            self._set.clear()
            self._not_empty.clear()

    def remove_matching(self, predicate: Callable[[str], bool]) -> None:
        """Remove all items for which *predicate(item)* is truthy."""
        with self._lock:
            kept: deque[str] = deque()
            kept_set: set[str] = set()
            for item in self._deque:
                if not predicate(item):
                    kept.append(item)
                    kept_set.add(item)
            self._deque = kept
            self._set = kept_set
            if not self._deque:
                self._not_empty.clear()


_voice_notification_queue = _DeduplicatedQueue(maxsize=_VOICE_QUEUE_MAXSIZE)


def _play_wav_linux(wav_path: str) -> None:
    """Play a WAV audio file on Linux using available audio player (pw-play, aplay, or paplay)."""
    player = shutil.which('pw-play') or shutil.which('aplay') or shutil.which('paplay')
    if player is not None:
        try:
            subprocess.run([player, wav_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10.0, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            logger.warning('Failed to play audio with %s: %s', player, e)


@dataclass(slots=True)
class _VoiceNotificationWorkerState:
    is_running: bool = False


_voice_notification_worker_state = _VoiceNotificationWorkerState()


def ensure_voice_notification_worker_running() -> None:
    """Start the `VoiceNotificationWorker` thread if it is not already running."""
    if not Settings.voice_notifications_enabled:
        return
    with _voice_notification_lock:
        if _voice_notification_worker_state.is_running:
            return
        _voice_notification_worker_state.is_running = True
        Thread(target=_voice_notification_worker, name=_VOICE_NOTIFICATION_THREAD_NAME, daemon=True).start()


def _voice_notification_worker() -> None:
    """Worker that sequentially plays queued voice notification WAV files until drained."""
    try:
        while not gui_closed__event.is_set():
            if not Settings.voice_notifications_enabled:
                _voice_notification_queue.clear()
                return

            wav_path = _voice_notification_queue.get(timeout=1.0)
            if wav_path is None:
                with _voice_notification_lock:
                    if _voice_notification_queue.empty():
                        _voice_notification_worker_state.is_running = False
                        return
                    continue

            try:
                if sys.platform == 'win32':
                    try:
                        if not Path(wav_path).is_file():
                            logger.warning('Voice notification file not found: %s', wav_path)
                        else:
                            winsound.PlaySound(wav_path, winsound.SND_FILENAME | winsound.SND_NODEFAULT)
                    except (RuntimeError, OSError, ValueError) as e:
                        logger.warning('Failed to play voice notification %s: %s', wav_path, e)
                else:
                    _play_wav_linux(wav_path)
                gui_closed__event.wait(_INTER_SOUND_PAUSE_SECONDS)
            finally:
                _voice_notification_queue.acknowledge(wav_path)
    finally:
        with _voice_notification_lock:
            _voice_notification_worker_state.is_running = False


def queue_voice_notification(wav_path: Path | str) -> None:
    """Enqueue a WAV file path for sequential voice notification playback."""
    _voice_notification_queue.put(str(wav_path))


def clear_voice_notification_queue() -> None:
    """Drain all pending voice notifications from the queue."""
    _voice_notification_queue.clear()


def clear_detection_voice_notifications() -> None:
    """Remove only detection voice notifications from the queue, keeping userip ones."""
    _voice_notification_queue.remove_matching(lambda path: 'detection' in Path(path).parts)


def tts_voice_name(*, voice_setting: Literal['Male', 'Female'] | bool) -> Literal['Liam', 'Jane']:
    """Map a voice-notification setting to its TTS folder name (`Liam` for Male, `Jane` otherwise)."""
    return 'Liam' if voice_setting == 'Male' else 'Jane'
