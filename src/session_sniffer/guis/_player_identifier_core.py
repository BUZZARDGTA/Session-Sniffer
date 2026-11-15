"""Core data models and statistical helpers for the Player Identifier."""

from collections import deque
from enum import Enum, auto
from itertools import islice
from math import sqrt
from typing import TYPE_CHECKING, ClassVar, override

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPainterPath, QPaintEvent, QPen
from PySide6.QtWidgets import QProgressBar, QWidget

from session_sniffer.guis.stylesheets import (
    PROGRESS_BAR_CHUNK_BLUE_STYLESHEET,
    PROGRESS_BAR_CHUNK_GREEN_STYLESHEET,
    PROGRESS_BAR_CHUNK_ORANGE_STYLESHEET,
    PROGRESS_BAR_CHUNK_RED_STYLESHEET,
)
from session_sniffer.guis.theming import register_theme_change_callback, themed_color, themed_qcolor, themed_text_qcolor

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
_CHUNK_TEXT_MIDPOINT = 50
_PROGRESS_BAR_BLUE_GRADIENT: list[tuple[float, QColor]] = []
_PROGRESS_BAR_GREEN_GRADIENT: list[tuple[float, QColor]] = []
_PROGRESS_BAR_ORANGE_GRADIENT: list[tuple[float, QColor]] = []
_PROGRESS_BAR_RED_GRADIENT: list[tuple[float, QColor]] = []


def _refresh_progress_bar_gradients() -> None:
    """Recompute capsule progress bar gradient stops for the active theme."""
    _PROGRESS_BAR_BLUE_GRADIENT[:] = [(0.0, themed_qcolor('#1d4ed8')), (0.5, themed_qcolor('#3b82f6')), (1.0, themed_qcolor('#60a5fa'))]
    _PROGRESS_BAR_GREEN_GRADIENT[:] = [(0.0, themed_qcolor('#059669')), (0.5, themed_qcolor('#10b981')), (1.0, themed_qcolor('#34d399'))]
    _PROGRESS_BAR_ORANGE_GRADIENT[:] = [(0.0, themed_qcolor('#d97706')), (0.5, themed_qcolor('#f59e0b')), (1.0, themed_qcolor('#fbbf24'))]
    _PROGRESS_BAR_RED_GRADIENT[:] = [(0.0, themed_qcolor('#b91c1c')), (0.5, themed_qcolor('#ef4444')), (1.0, themed_qcolor('#f87171'))]


_refresh_progress_bar_gradients()
register_theme_change_callback(_refresh_progress_bar_gradients)


class PlayerIdentifierProgressBar(QProgressBar):
    """Capsule progress bar with anti-aliased clipping to prevent chunk overflow."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the custom capsule progress bar."""
        super().__init__(parent)
        self.setRange(0, 100)
        self.setFixedHeight(24)
        self.setFixedWidth(PROGRESS_BAR_WIDTH)
        self.setTextVisible(True)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._chunk_gradient: list[tuple[float, QColor]] | None = None

    @override
    def setStyleSheet(self, styleSheet: str) -> None:
        super().setStyleSheet(styleSheet)
        if styleSheet == PROGRESS_BAR_CHUNK_BLUE_STYLESHEET or themed_color('#1d4ed8') in styleSheet:
            self._chunk_gradient = _PROGRESS_BAR_BLUE_GRADIENT
        elif styleSheet == PROGRESS_BAR_CHUNK_GREEN_STYLESHEET or themed_color('#059669') in styleSheet:
            self._chunk_gradient = _PROGRESS_BAR_GREEN_GRADIENT
        elif styleSheet == PROGRESS_BAR_CHUNK_ORANGE_STYLESHEET or themed_color('#d97706') in styleSheet:
            self._chunk_gradient = _PROGRESS_BAR_ORANGE_GRADIENT
        elif styleSheet == PROGRESS_BAR_CHUNK_RED_STYLESHEET or themed_color('#b91c1c') in styleSheet:
            self._chunk_gradient = _PROGRESS_BAR_RED_GRADIENT
        else:
            self._chunk_gradient = None
        self.update()

    @override
    def paintEvent(self, a0: QPaintEvent | None) -> None:
        if a0 is None:
            return
        painter = QPainter(self)
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)

            bounding_rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
            capsule_radius = bounding_rect.height() / 2.0

            outer_path = QPainterPath()
            outer_path.addRoundedRect(bounding_rect, capsule_radius, capsule_radius)
            painter.fillPath(outer_path, themed_qcolor('#0d131a'))
            painter.setPen(QPen(themed_qcolor('#253040'), 1.0))
            painter.drawPath(outer_path)

            current_value = self.value()
            if current_value > 0 and self._chunk_gradient is not None:
                inner_rect = bounding_rect.adjusted(2.0, 2.0, -2.0, -2.0)
                inner_radius = max(0.0, inner_rect.height() / 2.0)
                clip_path = QPainterPath()
                clip_path.addRoundedRect(inner_rect, inner_radius, inner_radius)

                value_range = self.maximum() - self.minimum()
                progress_ratio = (current_value - self.minimum()) / value_range if value_range > 0 else 0.0
                chunk_width = inner_rect.width() * progress_ratio
                chunk_rect = QRectF(inner_rect.x(), inner_rect.y(), chunk_width, inner_rect.height())

                painter.save()
                painter.setClipPath(clip_path)
                linear_gradient = QLinearGradient(inner_rect.left(), 0.0, inner_rect.right(), 0.0)
                for stop_point, stop_color in self._chunk_gradient:
                    linear_gradient.setColorAt(stop_point, stop_color)
                painter.fillRect(chunk_rect, linear_gradient)
                painter.restore()

            displayed_text = self.text()
            if displayed_text and self.isTextVisible():
                on_chunk = current_value >= _CHUNK_TEXT_MIDPOINT and self._chunk_gradient is not None
                painter.setPen(themed_text_qcolor('#ffffff', '#10b981') if on_chunk else themed_text_qcolor('#ffffff', '#0d131a'))
                text_font = self.font()
                text_font.setPointSize(9)
                text_font.setBold(True)
                painter.setFont(text_font)
                painter.drawText(bounding_rect, Qt.AlignmentFlag.AlignCenter, displayed_text)
        finally:
            painter.end()


class PlayerIdentifierTracker:
    """Global tracker for IPs currently identified by the Player Identifier tool."""

    identified_ips: ClassVar[set[str]] = set()

    @classmethod
    def is_identified(cls, ip: str) -> bool:
        """Return whether the given IP is currently identified."""
        return ip in cls.identified_ips

    @classmethod
    def set_identified_ips(cls, ips: set[str]) -> None:
        """Update the set of identified IPs."""
        cls.identified_ips = ips


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
