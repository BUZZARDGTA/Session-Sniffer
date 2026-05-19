"""Lightweight performance diagnostics utilities."""
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
