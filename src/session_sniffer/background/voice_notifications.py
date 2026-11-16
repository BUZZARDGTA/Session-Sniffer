"""Background worker and queue for text-to-speech voice notifications."""

import array
import io
import logging
import math
import shutil
import subprocess
import sys
import time
import wave
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Final, Literal

if sys.platform == 'win32':
    import winsound

from session_sniffer.background.events import gui_closed__event
from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.ctypes_windows import play_wav_memory_async
from session_sniffer.notifications_state import notifications_state

logger = logging.getLogger(__name__)

_VOICE_QUEUE_MAXSIZE = 10
_INTER_SOUND_PAUSE_SECONDS = 0.5
_VOICE_NOTIFICATION_THREAD_NAME = 'VoiceNotificationWorker'
_voice_notification_lock = Lock()

_SPIKE_SOUNDS_DIR: Final[Path] = RESOURCES_DIR_PATH / 'sounds'
_SPIKE_SOUND_FILES: Final[dict[str, str]] = {
    'Ding': 'spike_ding.wav',
    'Radar Ping': 'spike_ping.wav',
    'Double Beep': 'spike_beep.wav',
    'Geiger Click': 'spike_click.wav',
    'Siren Pulse': 'spike_alert.wav',
    'End': 'spike_end.wav',
    'Geiger1': 'spike_geiger_1.wav',
    'Geiger2': 'spike_geiger_2.wav',
    'Geiger3': 'spike_geiger_3.wav',
    'Geiger4': 'spike_geiger_4.wav',
    'Critical': 'spike_critical.wav',
}
_DEFAULT_SPIKE_SOUND_COOLDOWN_SECONDS: Final[float] = 0.25
_MAX_SPIKE_VOLUME_PERCENT: Final[int] = 100
_SPIKE_VOLUME_CURVE_EXPONENT: Final[float] = 1.6
_MAX_SCALED_WAV_CACHE_ENTRIES: Final[int] = 32
_PCM16_MIN: Final[int] = -32768
_PCM16_MAX: Final[int] = 32767
_PCM16_SAMPLE_WIDTH: Final[int] = 2
_PULSE_AUDIO_MAX_VOLUME: Final[int] = 65536
_SPIKE_SOUND_THREAD_NAME: Final[str] = 'SpikeSoundAudioWorker'
_spike_sound_lock = Lock()
_raw_spike_wav_cache: dict[Path, tuple[int, int, int, array.array[int]]] = {}
_scaled_spike_wav_cache: dict[tuple[Path, int], bytes] = {}


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
        if not notifications_state.voice_enabled:
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


_voice_notification_queue = _DeduplicatedQueue(maxsize=_VOICE_QUEUE_MAXSIZE)


def _play_wav_posix(wav_path: str) -> None:
    """Play a WAV audio file on macOS (afplay) or Linux (pw-play, aplay, or paplay)."""
    if sys.platform == 'darwin':
        player = shutil.which('afplay')
    else:
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
    if not notifications_state.voice_enabled:
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
            if not notifications_state.voice_enabled:
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
                if not Path(wav_path).is_file():
                    logger.warning('Voice notification file not found: %s', wav_path)
                elif sys.platform == 'win32':
                    try:
                        winsound.PlaySound(wav_path, winsound.SND_FILENAME | winsound.SND_NODEFAULT)
                    except (RuntimeError, OSError, ValueError) as e:
                        logger.warning('Failed to play voice notification %s: %s', wav_path, e)
                else:
                    _play_wav_posix(wav_path)
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


def tts_voice_name(*, voice_setting: Literal['Male', 'Female'] | bool) -> Literal['Liam', 'Jane']:
    """Map a voice-notification setting to its TTS folder name (`Liam` for Male, `Jane` otherwise)."""
    return 'Liam' if voice_setting == 'Male' else 'Jane'


@dataclass(slots=True)
class _SpikeSoundState:
    last_played_monotonic: float = 0.0
    posix_playing: bool = False


_spike_sound_state = _SpikeSoundState()


def _volume_to_amplitude_gain(volume_percent: int) -> float:
    """Convert a 0-100 UI volume percentage into a perceptual PCM amplitude gain factor."""
    clamped = min(_MAX_SPIKE_VOLUME_PERCENT, max(0, volume_percent))
    if not clamped:
        return 0.0
    if clamped == _MAX_SPIKE_VOLUME_PERCENT:
        return 1.0
    return math.pow(clamped / _MAX_SPIKE_VOLUME_PERCENT, _SPIKE_VOLUME_CURVE_EXPONENT)


def _get_scaled_spike_wav_bytes(wav_file_path: Path, volume_percent: int) -> bytes:
    """Return a cached in-memory WAV image scaled to *volume_percent* (`1..100`)."""
    cache_key = (wav_file_path, volume_percent)
    with _spike_sound_lock:
        if (cached := _scaled_spike_wav_cache.get(cache_key)) is not None:
            return cached

    if volume_percent >= _MAX_SPIKE_VOLUME_PERCENT:
        scaled_bytes = wav_file_path.read_bytes()
    else:
        with _spike_sound_lock:
            raw_entry = _raw_spike_wav_cache.get(wav_file_path)
        if raw_entry is None:
            with wave.open(str(wav_file_path), 'rb') as wav_reader:
                n_channels = wav_reader.getnchannels()
                sample_width = wav_reader.getsampwidth()
                frame_rate = wav_reader.getframerate()
                raw_frames = wav_reader.readframes(wav_reader.getnframes())
            if sample_width != _PCM16_SAMPLE_WIDTH:
                return wav_file_path.read_bytes()
            base_samples = array.array('h')
            base_samples.frombytes(raw_frames)
            if sys.byteorder == 'big':
                base_samples.byteswap()
            raw_entry = (n_channels, sample_width, frame_rate, base_samples)
            with _spike_sound_lock:
                _raw_spike_wav_cache[wav_file_path] = raw_entry

        n_channels, sample_width, frame_rate, base_samples = raw_entry
        gain = _volume_to_amplitude_gain(volume_percent)
        scaled_samples = array.array(
            'h',
            (max(_PCM16_MIN, min(_PCM16_MAX, round(sample * gain))) for sample in base_samples),
        )
        if sys.byteorder == 'big':
            scaled_samples.byteswap()
        buffer = io.BytesIO()
        with wave.Wave_write(buffer) as wav_writer:
            wav_writer.setnchannels(n_channels)
            wav_writer.setsampwidth(sample_width)
            wav_writer.setframerate(frame_rate)
            wav_writer.writeframes(scaled_samples.tobytes())
        scaled_bytes = buffer.getvalue()

    with _spike_sound_lock:
        if len(_scaled_spike_wav_cache) >= _MAX_SCALED_WAV_CACHE_ENTRIES:
            _scaled_spike_wav_cache.pop(next(iter(_scaled_spike_wav_cache)))
        _scaled_spike_wav_cache[cache_key] = scaled_bytes
    return scaled_bytes


def _play_spike_sound_posix_worker(wav_file_path: Path, volume_percent: int) -> None:
    """Play a spike alert WAV file on POSIX systems at *volume_percent* without blocking the GUI thread."""
    try:
        if volume_percent >= _MAX_SPIKE_VOLUME_PERCENT:
            _play_wav_posix(str(wav_file_path))
            return

        gain = _volume_to_amplitude_gain(volume_percent)
        if sys.platform == 'darwin':
            if (afplay := shutil.which('afplay')) is not None:
                subprocess.run([afplay, '-v', f'{gain:.4f}', str(wav_file_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10.0, check=False)
        elif (pw_play := shutil.which('pw-play')) is not None:
            subprocess.run([pw_play, f'--volume={gain:.4f}', str(wav_file_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10.0, check=False)
        elif (paplay := shutil.which('paplay')) is not None:
            pa_vol = round(gain * _PULSE_AUDIO_MAX_VOLUME)
            subprocess.run([paplay, f'--volume={pa_vol}', str(wav_file_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10.0, check=False)
        elif (aplay := shutil.which('aplay')) is not None:
            wav_bytes = _get_scaled_spike_wav_bytes(wav_file_path, volume_percent)
            subprocess.run([aplay, '-q'], input=wav_bytes, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10.0, check=False)
    except (OSError, subprocess.TimeoutExpired, wave.Error) as e:
        logger.warning('Failed to play spike sound %s: %s', wav_file_path, e)
    finally:
        with _spike_sound_lock:
            _spike_sound_state.posix_playing = False


def play_spike_sound(
    sound_kind: str = 'Ding',
    *,
    volume: int = _MAX_SPIKE_VOLUME_PERCENT,
    min_cooldown: float = _DEFAULT_SPIKE_SOUND_COOLDOWN_SECONDS,
    bypass_cooldown: bool = False,
) -> None:
    """Play a built-in spike alert WAV file immediately at *volume* (`0..100`), guarded by a configurable minimum cooldown."""
    clamped_volume = min(_MAX_SPIKE_VOLUME_PERCENT, max(0, volume))
    if gui_closed__event.is_set() or clamped_volume <= 0:
        return

    now = time.monotonic()
    with _spike_sound_lock:
        if (
            not bypass_cooldown
            and _spike_sound_state.last_played_monotonic
            and (now - _spike_sound_state.last_played_monotonic) < min_cooldown
        ):
            return
        if sys.platform != 'win32' and _spike_sound_state.posix_playing:
            return
        _spike_sound_state.last_played_monotonic = now
        if sys.platform != 'win32':
            _spike_sound_state.posix_playing = True

    sound_filename = _SPIKE_SOUND_FILES.get(sound_kind, 'spike_ding.wav')
    wav_file_path = _SPIKE_SOUNDS_DIR / sound_filename
    if not wav_file_path.is_file():
        if sys.platform != 'win32':
            with _spike_sound_lock:
                _spike_sound_state.posix_playing = False
        logger.warning('Spike sound file not found: %s', wav_file_path)
        return

    if sys.platform == 'win32':
        try:
            if clamped_volume >= _MAX_SPIKE_VOLUME_PERCENT:
                winsound.PlaySound(str(wav_file_path), winsound.SND_FILENAME | winsound.SND_NODEFAULT | winsound.SND_ASYNC)
            else:
                scaled_wav_bytes = _get_scaled_spike_wav_bytes(wav_file_path, clamped_volume)
                with _spike_sound_lock:
                    play_wav_memory_async(scaled_wav_bytes)
        except (RuntimeError, OSError, ValueError, wave.Error) as e:
            logger.warning('Failed to play spike sound %s: %s', wav_file_path, e)
    else:
        Thread(
            target=_play_spike_sound_posix_worker,
            args=(wav_file_path, clamped_volume),
            name=_SPIKE_SOUND_THREAD_NAME,
            daemon=True,
        ).start()
