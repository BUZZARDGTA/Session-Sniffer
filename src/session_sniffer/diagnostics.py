"""Lightweight performance diagnostics utilities."""

import time
from typing import ClassVar

from session_sniffer.logging_setup import get_logger

logger = get_logger(__name__)

_SLOWDOWN_RATIO_THRESHOLD = 5.0
_BASELINE_FLOOR_SECONDS = 0.01


class SlowdownDetector:
    """Detects when an operation regresses beyond a threshold ratio.

    Records the first observed duration of a named operation, then warns
    when any subsequent invocation exceeds *_SLOWDOWN_RATIO_THRESHOLD* times
    the baseline.

    Usage::

        detector = SlowdownDetector.get('rendering_loop')
        start = time.monotonic()
        # ... work ...
        detector.check(time.monotonic() - start, 'rendering_loop')

    For network-bound operations, pass a higher *baseline_floor* to avoid
    false positives from normal latency variance::

        detector = SlowdownDetector.get('api_call', baseline_floor=0.15)
    """

    _instances: ClassVar[dict[str, SlowdownDetector]] = {}

    def __init__(self, *, baseline_floor: float = _BASELINE_FLOOR_SECONDS) -> None:
        """Initialize with no baseline."""
        self._baseline: float | None = None
        self._baseline_floor = baseline_floor

    @classmethod
    def get(cls, key: str, *, baseline_floor: float = _BASELINE_FLOOR_SECONDS) -> SlowdownDetector:
        """Return the singleton detector for *key*, creating one if needed."""
        if key not in cls._instances:
            cls._instances[key] = cls(baseline_floor=baseline_floor)
        return cls._instances[key]

    def check(self, duration: float, label: str = '') -> None:
        """Record *duration* and warn if it exceeds the slowdown threshold."""
        if self._baseline is None:
            self._baseline = max(duration, self._baseline_floor)
            return

        ratio = duration / self._baseline
        if ratio >= _SLOWDOWN_RATIO_THRESHOLD:
            logger.warning('[%s] Slower by x%.1f (took %.4fs, baseline %.4fs)', label, ratio, duration, self._baseline)


class TimerStateError(Exception):
    """Raised when ``Timer.stop()`` is called before ``Timer.start()``."""

    def __init__(self, label: str) -> None:
        """Initialize with a message identifying the misbehaving timer *label*."""
        super().__init__(f'{label} timer was started improperly: start time is missing.')


class Timer:
    """High-resolution wall-clock timer with baseline regression detection.

    Records the first measured duration as the baseline.  Subsequent calls
    to :meth:`stop` log the elapsed time together with the delta from the
    baseline and emit a warning when the duration exceeds twice the
    baseline.

    Usage::

        timer = Timer('settings_load')
        timer.start()
        # ... work ...
        timer.stop()
    """

    def __init__(self, label: str) -> None:
        """Initialize a timer identified by *label*."""
        self.label: str = label
        self._start: float | None = None
        self._first_elapsed_time: float | None = None

    def start(self) -> None:
        """Begin timing."""
        self._start = time.perf_counter()

    def stop(self) -> None:
        """Stop timing and log the result.

        Raises:
            TimerStateError: If :meth:`start` was not called first.
        """
        if self._start is None:
            raise TimerStateError(self.label)

        elapsed = time.perf_counter() - self._start
        self._start = None

        if self._first_elapsed_time is None:
            self._first_elapsed_time = elapsed
        elif elapsed > self._first_elapsed_time * 2:
            logger.warning(
                '%s took %.4f seconds, which is more than double the first elapsed time of %.4f seconds.',
                self.label, elapsed, self._first_elapsed_time,
            )
            return

        delta = elapsed - self._first_elapsed_time
        sign = '+' if delta >= 0 else '-'
        logger.info(
            '%s took %.4f seconds. (%s%.4f seconds vs. first scan)',
            self.label, elapsed, sign, abs(delta),
        )

    @property
    def elapsed(self) -> float | None:
        """Return elapsed time in seconds if running, otherwise ``None``."""
        if self._start is None:
            return None
        return time.perf_counter() - self._start

    def __repr__(self) -> str:
        """Return a developer-friendly representation of the timer."""
        state = 'running' if self._start else 'stopped'
        return f'<Timer(label={self.label!r}, state={state})>'
