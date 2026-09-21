"""Core data models and statistical helpers for the Player Identifier."""

from collections import deque
from enum import Enum, auto
from itertools import islice
from math import sqrt
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from session_sniffer.models.player import Player

UPDATE_INTERVAL_MS = 1_000
CONVERGENCE_RECENT_WINDOW = 10
CONVERGENCE_GREEN = 0.10
CONVERGENCE_YELLOW = 0.25
BUTTON_WIDTH = 140
PROGRESS_BAR_WIDTH = 280
MIN_CONNECTED_PLAYERS = 2

_MIN_VARIANCE_SAMPLES = 2


class Phase(Enum):
    """Phases of the player identifier workflow."""

    IDLE = auto()
    BASELINE = auto()
    READY = auto()
    RESOLVING = auto()


class IPBaseline:
    """Stores PPS/BPS samples for a single IP during the baseline phase."""

    __slots__ = ('_bps_running_sum', '_pps_running_sum', 'bps_mean', 'bps_samples', 'bps_std', 'bps_std_floor', 'pps_mean', 'pps_samples', 'pps_std', 'pps_std_floor')

    def __init__(self) -> None:
        self.pps_samples: deque[int] = deque(maxlen=120)
        self.bps_samples: deque[int] = deque(maxlen=120)
        self._pps_running_sum: int = 0
        self._bps_running_sum: int = 0
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
            self._pps_running_sum -= self.pps_samples[0]
            self._bps_running_sum -= self.bps_samples[0]
        self.pps_samples.append(pps)
        self.bps_samples.append(bps)
        self._pps_running_sum += pps
        self._bps_running_sum += bps

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
            total += self._sample_mean_shift(self.pps_samples, self._pps_running_sum, recent_window)
            count += 1
        if self.bps_samples:
            total += self._sample_mean_shift(self.bps_samples, self._bps_running_sum, recent_window)
            count += 1
        return (total / count) if count else 0.0

    @staticmethod
    def _sample_mean_shift(samples: deque[int], overall_sum: int, recent_window: int) -> float:
        """Compute relative mean shift using cached sum and O(recent_window) tail access."""
        num_samples = len(samples)
        if num_samples < recent_window:
            return 1.0
        overall_mean = overall_sum / num_samples
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
        num_pps = len(self.pps_samples)
        num_bps = len(self.bps_samples)
        if num_pps < _MIN_VARIANCE_SAMPLES or num_bps < _MIN_VARIANCE_SAMPLES:
            return 0.0
        pps_mean = self._pps_running_sum / num_pps
        bps_mean = self._bps_running_sum / num_bps
        pps_var = sum((sample - pps_mean) ** 2 for sample in self.pps_samples) / (num_pps - 1)
        bps_var = sum((sample - bps_mean) ** 2 for sample in self.bps_samples) / (num_bps - 1)
        pps_std = max(sqrt(pps_var), pps_mean * 0.05, 1.0)
        bps_std = max(sqrt(bps_var), bps_mean * 0.05, 1.0)
        return (current_pps - pps_mean) / pps_std + (current_bps - bps_mean) / bps_std


def _mean_std(samples: deque[int]) -> tuple[float, float]:
    """Return (mean, std) of integer samples."""
    num_samples = len(samples)
    if not num_samples:
        return 0.0, 0.0
    mean = sum(samples) / num_samples
    if num_samples < _MIN_VARIANCE_SAMPLES:
        return mean, 0.0
    variance = sum((sample - mean) ** 2 for sample in samples) / (num_samples - 1)
    return mean, sqrt(variance)


def compute_aggregate_zscore(baselines: dict[str, IPBaseline], players: list[Player]) -> float | None:
    """Return the median spike z-score across all baselined IPs, or None if fewer than 2 IPs are available.

    Uses median instead of mean so that a single high-z outlier (the target player being watched)
    does not falsely trigger the aggregate-drift abort. Only session-wide events where the majority
    of IPs shift together (e.g. mass disconnect, session ended) will push the median above the threshold.

    Uses the finalized baseline (must only be called after BASELINE phase ends).
    A positive value means overall traffic is higher than baseline; negative means lower.
    """
    scores: list[float] = []
    for player in players:
        baseline = baselines.get(player.ip)
        if baseline is None:
            continue
        scores.append(baseline.spike_score(player.packets.pps.calculated_rate, player.bandwidth.bps.calculated_rate))
    if len(scores) < MIN_CONNECTED_PLAYERS:
        return None
    scores.sort()
    mid = len(scores) // 2
    if not len(scores) % 2:
        return (scores[mid - 1] + scores[mid]) / 2.0
    return scores[mid]
