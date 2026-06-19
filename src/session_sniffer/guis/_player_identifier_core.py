"""Core data models and statistical helpers for the Player Identifier."""

from collections import deque
from dataclasses import dataclass
from enum import Enum, auto
from itertools import islice
from math import sqrt

UPDATE_INTERVAL_MS = 1_000
CONVERGENCE_RECENT_WINDOW = 10
CONVERGENCE_GREEN = 0.10
CONVERGENCE_YELLOW = 0.25
SPIKE_SUSTAINED_SECS = 5
SPIKE_MIN_ZSCORE = 6.0
BUTTON_WIDTH = 250
MIN_CONNECTED_PLAYERS = 2
BASELINE_CONTAMINATION_ZSCORE = 10.0
BASELINE_CONTAMINATION_SECS = 5
BASELINE_CONTAMINATION_MIN_SAMPLES = 15
BASELINE_MIN_SAMPLES = 20
BASELINE_MAX_SECONDS = 30
SESSION_DRIFT_ZSCORE_THRESHOLD = 6.0

_MIN_VARIANCE_SAMPLES = 2
ZSCORE_ELEVATED = 3.0


class Phase(Enum):
    """Phases of the player identifier workflow."""

    IDLE = auto()
    BASELINE = auto()
    READY = auto()
    RESOLVING = auto()
    RESOLVED = auto()


@dataclass(slots=True)
class ResolvedIP:
    """A resolved IP with its confidence score and reason."""

    ip: str
    confidence: float
    reason: str
    username: str


class IPBaseline:
    """Stores PPS/BPS samples for a single IP during the baseline phase."""

    __slots__ = ('_bps_sum', '_pps_sum', 'bps_mean', 'bps_samples', 'bps_std', 'bps_std_floor', 'pps_mean', 'pps_samples', 'pps_std', 'pps_std_floor')

    def __init__(self) -> None:
        self.pps_samples: deque[int] = deque(maxlen=120)
        self.bps_samples: deque[int] = deque(maxlen=120)
        self._pps_sum: int = 0
        self._bps_sum: int = 0
        self.pps_mean: float = 0.0
        self.pps_std: float = 0.0
        self.bps_mean: float = 0.0
        self.bps_std: float = 0.0
        self.pps_std_floor: float = 1.0
        self.bps_std_floor: float = 1.0

    def add_sample(self, pps: int, bps: int) -> None:
        """Append a PPS/BPS sample pair, maintaining running sums in O(1)."""
        # Subtract evicted values before append (deque at maxlen drops leftmost)
        if len(self.pps_samples) == self.pps_samples.maxlen:
            self._pps_sum -= self.pps_samples[0]
            self._bps_sum -= self.bps_samples[0]
        self.pps_samples.append(pps)
        self.bps_samples.append(bps)
        self._pps_sum += pps
        self._bps_sum += bps

    def finalize(self) -> None:
        """Compute mean and standard deviation from collected samples."""
        self.pps_mean, self.pps_std = _mean_std(self.pps_samples)
        self.bps_mean, self.bps_std = _mean_std(self.bps_samples)
        self.pps_std_floor = max(self.pps_std, self.pps_mean * 0.05, 1.0)
        self.bps_std_floor = max(self.bps_std, self.bps_mean * 0.05, 1.0)

    def mean_shift(self, recent_window: int) -> float:
        """Return how much the recent mean diverges from the overall mean (0 = perfectly converged).

        Compares the last *recent_window* samples to the full history.
        Returns the average relative shift across PPS and BPS.
        Uses cached running sums (O(1) overall mean) and reversed iteration
        (O(recent_window) tail access) instead of O(n) full-deque scans.
        """
        count = 0
        total = 0.0
        if self.pps_samples:
            total += self._sample_mean_shift(self.pps_samples, self._pps_sum, recent_window)
            count += 1
        if self.bps_samples:
            total += self._sample_mean_shift(self.bps_samples, self._bps_sum, recent_window)
            count += 1
        return (total / count) if count else 0.0

    @staticmethod
    def _sample_mean_shift(samples: deque[int], overall_sum: int, recent_window: int) -> float:
        """Compute relative mean shift using cached sum and O(recent_window) tail access."""
        n = len(samples)
        if n < recent_window:
            return 1.0
        overall_mean = overall_sum / n
        # reversed() on deque yields from the right in O(1) per step;
        # islice takes only `recent_window` elements -> O(recent_window) total.
        recent_mean = sum(islice(reversed(samples), recent_window)) / recent_window
        return abs(recent_mean - overall_mean) / max(abs(overall_mean), 1.0)

    def spike_score(self, current_pps: int, current_bps: int) -> float:
        """Return a combined z-score measuring how far current rates deviate from baseline."""
        pps_z = (current_pps - self.pps_mean) / self.pps_std_floor
        bps_z = (current_bps - self.bps_mean) / self.bps_std_floor
        return pps_z + bps_z

    def live_zscore(self, current_pps: int, current_bps: int) -> float:
        """Return a combined z-score using live running stats (no finalize needed).

        Used during baseline to detect contamination spikes.
        """
        n_pps = len(self.pps_samples)
        n_bps = len(self.bps_samples)
        if n_pps < _MIN_VARIANCE_SAMPLES or n_bps < _MIN_VARIANCE_SAMPLES:
            return 0.0
        pps_mean = self._pps_sum / n_pps
        bps_mean = self._bps_sum / n_bps
        pps_var = sum((x - pps_mean) ** 2 for x in self.pps_samples) / (n_pps - 1)
        bps_var = sum((x - bps_mean) ** 2 for x in self.bps_samples) / (n_bps - 1)
        pps_std = max(sqrt(pps_var), pps_mean * 0.05, 1.0)
        bps_std = max(sqrt(bps_var), bps_mean * 0.05, 1.0)
        return (current_pps - pps_mean) / pps_std + (current_bps - bps_mean) / bps_std


def _mean_std(samples: deque[int]) -> tuple[float, float]:
    """Return (mean, std) of integer samples."""
    n = len(samples)
    if not n:
        return 0.0, 0.0
    mean = sum(samples) / n
    if n < _MIN_VARIANCE_SAMPLES:
        return mean, 0.0
    variance = sum((x - mean) ** 2 for x in samples) / (n - 1)
    return mean, sqrt(variance)


def zscore_to_confidence(zscore: float) -> float:
    """Map a z-score to a 0-100 confidence percentage using a sigmoid-like curve."""
    # z=6 -> ~50%, z=10 -> ~70%, z=20 -> ~87%
    return min(100.0 * (1.0 - 1.0 / (1.0 + zscore / 6.0)), 99.0)
