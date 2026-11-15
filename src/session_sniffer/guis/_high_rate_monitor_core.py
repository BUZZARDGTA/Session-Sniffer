"""Core data structures, proximity radar math, and tracker state for `HighRateMonitorWidget`."""

import math
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

from session_sniffer.guis.player_rate_graph import DEFAULT_MAX_HISTORY

if TYPE_CHECKING:
    from datetime import datetime

GEIGER_MIN_INTERVAL_SECONDS = 0.095
GEIGER_OPEN_GRAPH_MIN_PROXIMITY = 0.22
GEIGER_GLOBAL_APPROACH_PROXIMITY = 0.65

_MIN_CALM_FLOOR_SAMPLES = 6
_MIN_VELOCITY_SAMPLES = 4
_MIN_BOOST_BASE_PROX = 0.12
_STAGE_2_THRESHOLD = 0.50
_STAGE_3_THRESHOLD = 0.85
_STAGE_4_THRESHOLD = 1.25
_STAGE_CRITICAL_THRESHOLD = 1.75


def _make_rate_history() -> deque[int]:
    return deque(maxlen=DEFAULT_MAX_HISTORY)


def compute_series_proximity(
    *,
    history: deque[int],
    current: int,
    threshold: int,
    min_idle_floor: float,
    min_approach_delta: float,
) -> tuple[float, bool]:
    """Compute `(proximity_level, is_approaching)` from rate *history*, *current* rate, and *threshold*."""
    if threshold <= 0:
        return 0.0, False

    tail = list(history)[-24:]
    if len(tail) >= _MIN_CALM_FLOOR_SAMPLES:
        older_sorted = sorted(tail[:-3])
        calm_floor = max(min_idle_floor, min(threshold * 0.45, float(older_sorted[len(older_sorted) // 4])))
    else:
        calm_floor = min_idle_floor

    approaching = False
    velocity_boost = 0.0
    if len(tail) >= _MIN_VELOCITY_SAMPLES:
        recent = 0.65 * current + 0.35 * tail[-2]
        prior_slice = tail[-8:-2]
        prior_avg = sum(prior_slice) / len(prior_slice)
        delta = recent - prior_avg
        if delta >= min_approach_delta and current > calm_floor:
            approaching = True
            velocity_boost = min(0.55, delta / max(min_approach_delta * 4.0, threshold * 0.50))

    if current <= calm_floor:
        return 0.0, False
    base_prox = (
        (current - calm_floor) / max(1.0, threshold - calm_floor)
        if current < threshold
        else 1.0 + (current - threshold) / max(8.0, threshold * 0.60)
    )
    return base_prox + (velocity_boost if base_prox >= _MIN_BOOST_BASE_PROX else 0.0), approaching


def geiger_stage_sound_kind(proximity_score: float) -> str:
    """Select the rising-pitch proximity sound asset matching *proximity_score*."""
    if proximity_score < _STAGE_2_THRESHOLD:
        return 'Geiger1'
    if proximity_score < _STAGE_3_THRESHOLD:
        return 'Geiger2'
    if proximity_score < _STAGE_4_THRESHOLD:
        return 'Geiger3'
    if proximity_score < _STAGE_CRITICAL_THRESHOLD:
        return 'Geiger4'
    return 'Critical'


def compute_geiger_interval(*, repeat_interval: int, proximity_score: float) -> float:
    """Compute the target tick interval in seconds for `Adaptive Geiger` mode."""
    scale = repeat_interval / 2.0
    raw_interval = (1.65 * scale) / math.pow(0.55 + proximity_score * 1.25, 2.1)
    return max(GEIGER_MIN_INTERVAL_SECONDS, min(repeat_interval * 1.25, raw_interval))


@dataclass(kw_only=True, slots=True)
class PlayerRateData:
    """Per-IP rolling rate history and sustained high-rate streak state."""

    ip: str
    pps: int
    bps: int = 0
    usernames: list[str] = field(default_factory=list[str])

    # Rate history (rolling window matching graph length)
    pps_history: deque[int] = field(default_factory=_make_rate_history)
    bps_history: deque[int] = field(default_factory=_make_rate_history)

    # PPS tracking
    newer_high_pps_time: datetime | None = None
    is_high_pps: bool = False
    current_pps_duration: int = 0
    accumulated_pps_duration: int = 0
    total_pps_duration: int = 0

    # BPS tracking
    newer_high_bps_time: datetime | None = None
    is_high_bps: bool = False
    current_bps_duration: int = 0

    def update_pps_stats(self, *, now: datetime, pps: int, threshold: int, required_duration: int) -> None:
        """Update high-PPS status for this player."""
        self.pps = pps
        self.pps_history.append(pps)
        if pps < threshold:
            self.accumulated_pps_duration += self.current_pps_duration
            self.is_high_pps = False
            self.newer_high_pps_time = None
            self.current_pps_duration = 0
            self.total_pps_duration = self.accumulated_pps_duration
            return

        if self.newer_high_pps_time is None:
            self.newer_high_pps_time = now

        self.current_pps_duration = int((now - self.newer_high_pps_time).total_seconds())
        self.total_pps_duration = self.accumulated_pps_duration + self.current_pps_duration

        if self.current_pps_duration >= required_duration:
            self.is_high_pps = True

    def update_bps_stats(self, *, now: datetime, bps: int, threshold: int, required_duration: int) -> None:
        """Update high-BPS status for this player."""
        self.bps = bps
        self.bps_history.append(bps)
        if bps < threshold:
            self.is_high_bps = False
            self.newer_high_bps_time = None
            self.current_bps_duration = 0
            return

        if self.newer_high_bps_time is None:
            self.newer_high_bps_time = now

        self.current_bps_duration = int((now - self.newer_high_bps_time).total_seconds())

        if self.current_bps_duration >= required_duration:
            self.is_high_bps = True


class HighRateTracker:
    """Global tracker for IPs currently flagged as high-rate."""

    flagged_ips: ClassVar[set[str]] = set()

    @classmethod
    def is_high_rate(cls, ip: str) -> bool:
        """Return whether the given IP is currently flagged as high-rate."""
        return ip in cls.flagged_ips

    @classmethod
    def set_flagged_ips(cls, ips: set[str]) -> None:
        """Update the set of flagged high-rate IPs."""
        cls.flagged_ips = ips
