"""Player Identifier — baseline PPS/BPS profiles then detect spikes to correlate IPs to players."""

from math import sqrt
from typing import TYPE_CHECKING, ClassVar, override

from PySide6.QtCore import QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPainterPath, QPaintEvent, QPen
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.guis._player_identifier_core import (
    BUTTON_WIDTH,
    CONVERGENCE_GREEN,
    CONVERGENCE_RECENT_WINDOW,
    CONVERGENCE_YELLOW,
    MIN_CONNECTED_PLAYERS,
    PROGRESS_BAR_WIDTH,
    UPDATE_INTERVAL_MS,
    IPBaseline,
    Phase,
    compute_aggregate_zscore,
)
from session_sniffer.guis._player_identifier_params import PlayerIdentifierParamsWidget
from session_sniffer.guis.stylesheets import (
    PROGRESS_BAR_CHUNK_BLUE_STYLESHEET,
    PROGRESS_BAR_CHUNK_GREEN_STYLESHEET,
    PROGRESS_BAR_CHUNK_ORANGE_STYLESHEET,
    PROGRESS_BAR_CHUNK_RED_STYLESHEET,
    PROGRESS_BAR_IDLE_STYLESHEET,
)
from session_sniffer.models.player import PlayerBandwidth
from session_sniffer.networking.third_party_servers import is_third_party_server_ip
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.models.player import Player


_PROGRESS_BAR_BLUE_GRADIENT: list[tuple[float, QColor]] = [
    (0.0, QColor('#1d4ed8')),
    (0.5, QColor('#3b82f6')),
    (1.0, QColor('#60a5fa')),
]
_PROGRESS_BAR_GREEN_GRADIENT: list[tuple[float, QColor]] = [
    (0.0, QColor('#059669')),
    (0.5, QColor('#10b981')),
    (1.0, QColor('#34d399')),
]
_PROGRESS_BAR_ORANGE_GRADIENT: list[tuple[float, QColor]] = [
    (0.0, QColor('#d97706')),
    (0.5, QColor('#f59e0b')),
    (1.0, QColor('#fbbf24')),
]
_PROGRESS_BAR_RED_GRADIENT: list[tuple[float, QColor]] = [
    (0.0, QColor('#b91c1c')),
    (0.5, QColor('#ef4444')),
    (1.0, QColor('#f87171')),
]


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
        self._background_color = QColor('#0d131a')
        self._border_color = QColor('#253040')

    @override
    def setStyleSheet(self, styleSheet: str) -> None:
        super().setStyleSheet(styleSheet)
        if '#1d4ed8' in styleSheet:
            self._chunk_gradient = _PROGRESS_BAR_BLUE_GRADIENT
        elif '#059669' in styleSheet:
            self._chunk_gradient = _PROGRESS_BAR_GREEN_GRADIENT
        elif '#d97706' in styleSheet:
            self._chunk_gradient = _PROGRESS_BAR_ORANGE_GRADIENT
        elif '#b91c1c' in styleSheet:
            self._chunk_gradient = _PROGRESS_BAR_RED_GRADIENT
        else:
            self._chunk_gradient = None
        self.update()

    @override
    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        bounding_rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        capsule_radius = bounding_rect.height() / 2.0

        outer_path = QPainterPath()
        outer_path.addRoundedRect(bounding_rect, capsule_radius, capsule_radius)
        painter.fillPath(outer_path, self._background_color)
        painter.setPen(QPen(self._border_color, 1.0))
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
            painter.setPen(QColor('#ffffff'))
            text_font = self.font()
            text_font.setPointSize(9)
            text_font.setBold(True)
            painter.setFont(text_font)
            painter.drawText(bounding_rect, Qt.AlignmentFlag.AlignCenter, displayed_text)


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


class PlayerIdentifierWidget(QWidget):
    """Baseline PPS/BPS then detect spikes to identify which IP belongs to a target player."""

    def __init__(
        self,
        select_ips_callback: Callable[[list[str]], None],
        deselect_ips_callback: Callable[[list[str] | None], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the Player Identifier widget."""
        super().__init__(parent)

        self._select_ips = select_ips_callback
        self._deselect_ips = deselect_ips_callback
        self._phase = Phase.IDLE
        self._baseline_ips: set[str] = set()
        self._baselines: dict[str, IPBaseline] = {}
        self._sample_count = 0
        self._spike_streak: dict[str, int] = {}
        self._total_spike_duration: dict[str, int] = {}
        self._contamination_streak: dict[str, int] = {}
        self._identified_ips: set[str] = set()
        self._currently_selected_ips: set[str] = set()
        self._auto_select: bool = True
        PlayerIdentifierTracker.set_identified_ips(set())

        self._params_box = PlayerIdentifierParamsWidget(self)

        # Widget update caches — skip redundant repaints when values haven't changed
        self._prev_stability_pct: int | None = None
        self._prev_stability_format: str | None = None
        self._prev_stability_style: str | None = None
        self._prev_stability_text: str | None = None
        self._prev_sample_text: str | None = None
        self._prev_result_text: str | None = None

        layout = QVBoxLayout(self)

        # Instructions
        self._instructions = QLabel()
        self._instructions.setWordWrap(True)
        self._instructions.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._set_idle_instructions()
        layout.addWidget(self._instructions)

        # Stability indicator
        self._stability_label = QLabel('Stability: —')
        self._stability_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._stability_label.setToolTip(
            'Shows whether the traffic measurements have settled down.\n\n'
            'GREEN = Traffic is steady. You can stop the baseline.\n'
            'YELLOW = Traffic is still changing. Keep waiting.\n'
            'ORANGE = Collecting initial data. Not enough samples yet.\n'
            'RED = Traffic is very erratic. Stay still and wait.',
        )
        self._stability_label.setVisible(False)
        layout.addWidget(self._stability_label)

        self._stability_bar = PlayerIdentifierProgressBar()
        self._stability_bar.setRange(0, 100)
        self._stability_bar.setValue(0)
        self._stability_bar.setTextVisible(True)
        self._stability_bar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._stability_bar.setFormat('Waiting...')
        self._stability_bar.setFixedWidth(PROGRESS_BAR_WIDTH)
        self._stability_bar.setStyleSheet(PROGRESS_BAR_IDLE_STYLESHEET)
        self._stability_bar.setToolTip(
            'Progress toward a stable baseline.\n\n'
            'During baseline: fills up as traffic patterns stabilize. '
            'When it reaches 100% and turns green, the data is reliable.\n\n'
            'During resolve: fills up as a candidate IP sustains a traffic spike. '
            'Reaches 100% when a match is confirmed.',
        )
        self._stability_bar.setVisible(False)
        layout.addWidget(self._stability_bar, alignment=Qt.AlignmentFlag.AlignHCenter)

        # Sample count label
        self._sample_label = QLabel('')
        self._sample_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._sample_label.setToolTip(
            'Number of IPs being tracked and how many 1-second snapshots have been recorded.\nMore samples = more accurate baseline.',
        )
        self._sample_label.setVisible(False)
        layout.addWidget(self._sample_label)

        # Result label
        self._result_label = QLabel('')
        self._result_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._result_label.setWordWrap(True)
        layout.addWidget(self._result_label)

        # Buttons row
        button_layout = QHBoxLayout()
        button_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._baseline_button = QPushButton('Start Baseline')
        self._baseline_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._baseline_button.setFixedWidth(BUTTON_WIDTH)
        self._baseline_button.clicked.connect(self._on_baseline_button_clicked)
        button_layout.addWidget(self._baseline_button)

        self._resolve_button = QPushButton('Resolve')
        self._resolve_button.setToolTip(
            'Step 2: Starts watching for traffic spikes.\n\n'
            'After clicking this, spectate the player you want to identify using '
            'the Orbital Cannon, a CCTV camera, or by physically approaching them.\n'
            'When your game loads that player, it sends more data to/from their IP, '
            'causing a spike compared to the baseline.\n\n'
            f'An IP must spike for {self._spike_sustained_seconds} consecutive seconds to be confirmed.\n\n'
            'Tip: Detection works best when the target player is moving — '
            'a moving player generates significantly more traffic than a stationary one.',
        )
        self._resolve_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._resolve_button.setFixedWidth(BUTTON_WIDTH)
        self._resolve_button.clicked.connect(self._on_resolve)
        self._resolve_button.setEnabled(False)
        button_layout.addWidget(self._resolve_button)

        self._reset_button = QPushButton('Reset Scan')
        self._reset_button.setToolTip(
            'Clears all candidate streaks and identified players from the current scan, preserving the baseline so you can immediately resolve another player.',
        )
        self._reset_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._reset_button.setFixedWidth(BUTTON_WIDTH)
        self._reset_button.clicked.connect(self._on_reset_scan)
        self._reset_button.setEnabled(False)
        button_layout.addWidget(self._reset_button)

        self._update_baseline_button_state()

        layout.addLayout(button_layout)

        # Table selection controls
        table_selection_layout = QHBoxLayout()
        table_selection_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._select_button = QPushButton('Select in Table')
        self._select_button.setToolTip('Select and scroll to all identified players in the connected players table.')
        self._select_button.setFixedWidth(BUTTON_WIDTH)
        self._select_button.setEnabled(False)
        self._select_button.clicked.connect(self._select_resolved)
        table_selection_layout.addWidget(self._select_button)

        self._deselect_button = QPushButton('Deselect in Table')
        self._deselect_button.setToolTip('Deselect all identified players in the connected players table.')
        self._deselect_button.setFixedWidth(BUTTON_WIDTH)
        self._deselect_button.setEnabled(False)
        self._deselect_button.clicked.connect(self._deselect_resolved)
        table_selection_layout.addWidget(self._deselect_button)

        self._auto_select_checkbox = QCheckBox('Auto-select in Table')
        self._auto_select_checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._auto_select_checkbox.toggled.connect(self._on_auto_select_toggled)
        self._auto_select_checkbox.setToolTip(
            'Keep identified players selected in the connected players table automatically.\n\nLive updates occur with every scan. Turn off for manual selection control.',
        )
        self._auto_select_checkbox.setChecked(True)
        table_selection_layout.addWidget(self._auto_select_checkbox)

        layout.addLayout(table_selection_layout)
        layout.addStretch()
        layout.addWidget(self._params_box)

        # Timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

    # -- Phase transitions ----------------------------------------------------

    def _update_baseline_button_state(self) -> None:
        if self._phase == Phase.IDLE:
            self._baseline_button.setText('Start Baseline')
            self._baseline_button.setToolTip(
                'Step 1: Records the normal traffic (PPS/BPS) for every IP currently in the session.\n\n'
                'IMPORTANT: Make sure you are ALONE and standing still (e.g. inside a bunker, '
                'facility, or away from all other players) before clicking this.\n\n'
                'Only IPs connected RIGHT NOW will be tracked. Anyone who joins later is ignored.\n\n'
                f'The baseline runs until traffic is stable or {self._baseline_max_seconds}s have elapsed, then automatically locks in.',
            )
            self._baseline_button.setEnabled(True)
        elif self._phase == Phase.BASELINE:
            self._baseline_button.setText('Cancel Baseline')
            self._baseline_button.setToolTip('Cancel recording the baseline and return to the idle state.')
            self._baseline_button.setEnabled(True)
        else:
            self._baseline_button.setText('Reset Baseline')
            self._baseline_button.setToolTip('Discard the recorded baseline data and start over from scratch.')
            self._baseline_button.setEnabled(True)

    def _on_baseline_button_clicked(self) -> None:
        if self._phase == Phase.IDLE:
            self._on_start_baseline()
        else:
            self.reset()

    def _set_idle_instructions(self) -> None:
        self._instructions.setText(
            '<b>How to use the Player Identifier:</b><br><br>'
            '<b>1.</b> Go somewhere alone in-game where no other player is near you '
            '(e.g. a bunker, facility, or empty area).<br>'
            '<b>2.</b> Click <b>Start Baseline</b> to record the normal traffic for every IP in the session. '
            "Stand still and don't interact with anyone.<br>"
            '<b>3.</b> The baseline auto-locks once traffic is stable '
            f'(or after {self._baseline_max_seconds}s).<br>'
            '<b>4.</b> Click <b>Resolve</b>, then spectate the player you want to identify '
            '(e.g. Orbital Cannon, CCTV camera, or physically approaching them).<br>'
            "The tool detects which IP's traffic increases when your game loads that player.<br><br>"
            '<small>Only IPs present when you start the baseline are tracked. '
            'Anyone who joins later is completely ignored.<br>'
            'Tip: Detection works best when the target player is <b>moving</b> — '
            'a moving player generates significantly more traffic than a stationary one.</small>',
        )

    def _on_start_baseline(self) -> None:
        players = [player for player in PlayersRegistry.get_connected_players() if not is_third_party_server_ip(player.ip)]
        if len(players) < MIN_CONNECTED_PLAYERS:
            QMessageBox.warning(
                self,
                'Not Enough Players',
                f'There must be at least {MIN_CONNECTED_PLAYERS} connected players to use the Player Identifier.\n\nWith only 0 or 1 players, there is nothing to resolve.',
            )
            return

        self._phase = Phase.BASELINE
        self._baselines.clear()
        self._sample_count = 0
        self._spike_streak.clear()
        self._total_spike_duration.clear()
        self._contamination_streak.clear()
        self._identified_ips.clear()
        PlayerIdentifierTracker.set_identified_ips(set())
        self._prev_stability_pct = None
        self._prev_stability_format = None
        self._prev_stability_style = None
        self._prev_stability_text = None
        self._prev_sample_text = None
        self._prev_result_text = None
        self._result_label.setText('')
        self._update_baseline_button_state()
        self._resolve_button.setEnabled(False)
        self._reset_button.setEnabled(False)

        self._baseline_ips = {player.ip for player in players}
        for ip in self._baseline_ips:
            self._baselines[ip] = IPBaseline()

        num_ips = len(self._baseline_ips)
        self._instructions.setText(
            f'Recording baseline for <b>{num_ips}</b> IP{pluralize(num_ips)}…<br><br>'
            'Stay still while the baseline records. It will auto-lock once traffic is stable '
            f'(or after {self._baseline_max_seconds}s).<br>'
            'Do <b>NOT</b> move or interact with anyone while recording.',
        )
        self._stability_bar.setFormat('Collecting…')
        self._stability_bar.setValue(0)
        self._stability_bar.setStyleSheet(PROGRESS_BAR_IDLE_STYLESHEET)
        self._prev_stability_pct = 0
        self._prev_stability_format = 'Collecting…'
        self._prev_stability_style = PROGRESS_BAR_IDLE_STYLESHEET
        self._prev_stability_text = None
        self._stability_label.setVisible(True)
        self._stability_bar.setVisible(True)
        self._sample_label.setVisible(True)
        self._sample_label.setText('')
        self._params_box.setVisible(False)
        self._timer.start(UPDATE_INTERVAL_MS)

    def _auto_stop_baseline(self, reason: str) -> None:
        """Finalize baselines and transition to READY (timer keeps running for contamination monitoring)."""
        for bl in self._baselines.values():
            bl.finalize()
        self._phase = Phase.READY
        self._update_baseline_button_state()
        self._resolve_button.setEnabled(True)
        self._reset_button.setEnabled(False)
        num_ips = len(self._baselines)
        self._instructions.setText(
            f'Baseline locked ({reason}) with <b>{num_ips}</b> IP{pluralize(num_ips)} '
            f'over <b>{self._sample_count}</b> sample{pluralize(self._sample_count)}.<br><br>'
            'Click <b>Resolve</b>, then spectate the target player (Orbital Cannon, CCTV, or walk up to them).<br>'
            "The tool will detect which IP's traffic spikes when your game loads that player.<br>"
            '<small>Tip: Detection works best when the target player is <b>moving</b>.</small>',
        )
        self._stability_bar.setFormat('Locked')
        self._stability_bar.setValue(100)
        self._stability_bar.setStyleSheet(PROGRESS_BAR_CHUNK_GREEN_STYLESHEET)
        self._stability_label.setText('Stability: <span style="color:green;">Locked</span>')
        self._contamination_streak.clear()

    def _on_resolve(self) -> None:
        self._phase = Phase.RESOLVING
        self._spike_streak.clear()
        self._total_spike_duration.clear()
        self._identified_ips.clear()
        PlayerIdentifierTracker.set_identified_ips(set())
        self._resolve_button.setEnabled(False)
        self._reset_button.setEnabled(True)
        self._select_button.setEnabled(not self._auto_select)
        self._deselect_button.setEnabled(not self._auto_select)
        self._instructions.setText(
            'Spectate the player you want to identify (Orbital Cannon, CCTV, or walk up to them).<br><br>'
            'The tool is comparing live traffic against the baseline.<br>'
            f"If any IP's traffic spikes for <b>{self._spike_sustained_seconds}</b> consecutive seconds, "
            'it will be flagged as a match.<br>'
            '<small>Tip: Detection works best when the target player is <b>moving</b>.</small>',
        )
        self._result_label.setText('')
        self._stability_bar.setFormat('Resolving…')
        self._stability_bar.setValue(0)
        self._stability_bar.setStyleSheet(PROGRESS_BAR_CHUNK_BLUE_STYLESHEET)

    def _on_reset_scan(self) -> None:
        """Reset the resolution scan results while keeping the baseline intact."""
        if self._currently_selected_ips and self._deselect_ips is not None:
            self._deselect_ips(list(self._currently_selected_ips))
        self._currently_selected_ips.clear()
        self._spike_streak.clear()
        self._total_spike_duration.clear()
        self._identified_ips.clear()
        PlayerIdentifierTracker.set_identified_ips(set())

        self._phase = Phase.READY
        self._update_baseline_button_state()
        self._resolve_button.setEnabled(True)
        self._reset_button.setEnabled(False)
        self._select_button.setEnabled(False)
        self._deselect_button.setEnabled(False)

        num_ips = len(self._baselines)
        self._instructions.setText(
            f'Baseline locked with <b>{num_ips}</b> IP{pluralize(num_ips)} '
            f'over <b>{self._sample_count}</b> sample{pluralize(self._sample_count)}.<br><br>'
            'Click <b>Resolve</b>, then spectate the target player (Orbital Cannon, CCTV, or walk up to them).<br>'
            "The tool will detect which IP's traffic spikes when your game loads that player.<br>"
            '<small>Tip: Detection works best when the target player is <b>moving</b>.</small>',
        )
        self._update_stability(100, PROGRESS_BAR_CHUNK_GREEN_STYLESHEET, 'Stability: <span style="color:green;">Locked</span>', bar_format='Locked')
        self._update_sample_label(f'{num_ips} IP{pluralize(num_ips)} · {self._sample_count} sample{pluralize(self._sample_count)}')
        self._update_result_label('')
        self._contamination_streak.clear()

    def _on_auto_select_toggled(self, checked: bool) -> None:  # noqa: FBT001
        self._auto_select = checked
        is_active = self._phase == Phase.RESOLVING
        self._select_button.setEnabled(not checked and is_active)
        self._deselect_button.setEnabled(not checked and is_active)
        if checked:
            if self._identified_ips and self._select_ips is not None:
                self._select_ips(list(self._identified_ips))
                self._currently_selected_ips = set(self._identified_ips)
        elif self._currently_selected_ips and self._deselect_ips is not None:
            self._deselect_ips(list(self._currently_selected_ips))
            self._currently_selected_ips.clear()

    def _select_resolved(self) -> None:
        if self._select_ips is not None:
            target_ips = list(self._identified_ips or self._spike_streak.keys())
            if target_ips:
                self._select_ips(target_ips)
                self._currently_selected_ips = set(target_ips)

    def _deselect_resolved(self) -> None:
        if self._deselect_ips is not None:
            target_ips = set(self._identified_ips) | set(self._spike_streak.keys())
            ips_to_deselect = list(self._currently_selected_ips | target_ips)
            self._deselect_ips(ips_to_deselect or None)
            self._currently_selected_ips.clear()

    def reset(self) -> None:
        """Discard all data and return the widget to its initial idle state."""
        self._timer.stop()
        self._phase = Phase.IDLE
        if self._currently_selected_ips and self._deselect_ips is not None:
            self._deselect_ips(list(self._currently_selected_ips))
        self._currently_selected_ips.clear()
        self._baseline_ips.clear()
        self._baselines.clear()
        self._sample_count = 0
        self._spike_streak.clear()
        self._total_spike_duration.clear()
        self._contamination_streak.clear()
        self._identified_ips.clear()
        PlayerIdentifierTracker.set_identified_ips(set())
        self._prev_stability_pct = None
        self._prev_stability_format = None
        self._prev_stability_style = None
        self._prev_stability_text = None
        self._prev_sample_text = None
        self._prev_result_text = None
        self._update_baseline_button_state()
        self._resolve_button.setEnabled(False)
        self._reset_button.setEnabled(False)
        self._select_button.setEnabled(False)
        self._deselect_button.setEnabled(False)
        self._set_idle_instructions()
        self._stability_label.setText('Stability: —')
        self._stability_label.setVisible(False)
        self._stability_bar.setValue(0)
        self._stability_bar.setFormat('Waiting...')
        self._stability_bar.setStyleSheet(PROGRESS_BAR_IDLE_STYLESHEET)
        self._stability_bar.setVisible(False)
        self._sample_label.setText('')
        self._sample_label.setVisible(False)
        self._result_label.setText('')
        self._params_box.setVisible(True)

    def _abort_insufficient_players(self) -> None:
        """Stop the current phase because too many players disconnected."""
        self._timer.stop()
        self._phase = Phase.IDLE
        PlayerIdentifierTracker.set_identified_ips(set())
        self._update_baseline_button_state()
        self._resolve_button.setEnabled(False)
        self._reset_button.setEnabled(False)
        self._select_button.setEnabled(False)
        self._deselect_button.setEnabled(False)
        self._params_box.setVisible(True)
        self._stability_bar.setValue(0)
        self._stability_bar.setFormat('Aborted')
        self._stability_bar.setStyleSheet(PROGRESS_BAR_CHUNK_RED_STYLESHEET)
        self._stability_label.setText(
            'Stability: <span style="color:red;">Aborted — not enough players remaining</span>',
        )
        self._instructions.setText(
            f'<b style="color:#e74c3c;">Aborted:</b> fewer than {MIN_CONNECTED_PLAYERS} tracked players remain in the session.<br><br>'
            'Players disconnected while the scan was running. Click <b>Start Baseline</b> to try again…',
        )

    def _abort_contaminated(self, ip: str, zscore: float) -> None:
        """Stop the baseline because a dramatic traffic spike was detected (contamination)."""
        self._timer.stop()
        self._phase = Phase.IDLE
        PlayerIdentifierTracker.set_identified_ips(set())
        self._update_baseline_button_state()
        self._resolve_button.setEnabled(False)
        self._reset_button.setEnabled(False)
        self._select_button.setEnabled(False)
        self._deselect_button.setEnabled(False)
        self._params_box.setVisible(True)
        self._stability_bar.setValue(0)
        self._stability_bar.setFormat('Contaminated')
        self._stability_bar.setStyleSheet(PROGRESS_BAR_CHUNK_RED_STYLESHEET)
        self._stability_label.setText(
            'Stability: <span style="color:red;">Aborted — baseline contaminated</span>',
        )
        self._instructions.setText(
            f'<b style="color:#e74c3c;">Baseline contaminated!</b> IP <b>{ip}</b> showed a dramatic traffic spike '
            f'(z-score: {zscore:.1f}) while recording.<br><br>'
            'This usually means you moved, spectated someone, or a player approached you. '
            'The baseline data is no longer reliable.<br><br>'
            'Click <b>Start Baseline</b> to start over. Make sure you stay completely still and isolated.',
        )

    def _abort_session_changed(self) -> None:
        """Stop the current phase because overall session traffic drifted too far from the baseline."""
        self._timer.stop()
        self._phase = Phase.IDLE
        PlayerIdentifierTracker.set_identified_ips(set())
        self._update_baseline_button_state()
        self._resolve_button.setEnabled(False)
        self._reset_button.setEnabled(False)
        self._select_button.setEnabled(False)
        self._deselect_button.setEnabled(False)
        self._params_box.setVisible(True)
        self._stability_bar.setValue(0)
        self._stability_bar.setFormat('Aborted')
        self._stability_bar.setStyleSheet(PROGRESS_BAR_CHUNK_RED_STYLESHEET)
        self._stability_label.setText(
            'Stability: <span style="color:red;">Aborted — session conditions changed</span>',
        )
        self._instructions.setText(
            '<b style="color:#e74c3c;">Baseline invalidated:</b> overall session traffic shifted too dramatically '
            'from the recorded baseline.<br><br>'
            'The session may have ended, or a mass game event caused all traffic to spike or drop simultaneously. '
            'The baseline data is no longer reliable.<br><br>'
            'Click <b>Start Baseline</b> to start over.',
        )

    # -- Periodic tick --------------------------------------------------------

    def _tick(self) -> None:
        players = [player for player in PlayersRegistry.get_connected_players() if not is_third_party_server_ip(player.ip)]
        if self._phase == Phase.BASELINE:
            self._tick_baseline(players)
        elif self._phase == Phase.READY:
            self._tick_ready(players)
        elif self._phase == Phase.RESOLVING:
            self._tick_resolving(players)

    def _tick_baseline(self, players: list[Player]) -> None:
        self._sample_count += 1
        sampled_ips: set[str] = set()
        player_by_ip: dict[str, Player] = {}
        for player in players:
            if player.ip in self._baseline_ips:
                sampled_ips.add(player.ip)
                player_by_ip[player.ip] = player
                self._baselines[player.ip].add_sample(
                    player.packets.pps.calculated_rate,
                    player.bandwidth.bps.calculated_rate,
                )
        disconnected = self._baseline_ips - sampled_ips
        if disconnected:
            self._baseline_ips -= disconnected
            for ip in disconnected:
                self._baselines.pop(ip, None)

        if len(self._baselines) < MIN_CONNECTED_PLAYERS:
            self._abort_insufficient_players()
            return

        if self._sample_count >= self._contamination_min_samples:
            for ip, bl in self._baselines.items():
                matched_player = player_by_ip.get(ip)
                if matched_player is None:
                    continue
                zscore = bl.live_zscore(matched_player.packets.pps.calculated_rate, matched_player.bandwidth.bps.calculated_rate)
                if zscore >= self._contamination_zscore:
                    streak = self._contamination_streak[ip] = self._contamination_streak.get(ip, 0) + 1
                    if streak >= self._contamination_seconds:
                        self._abort_contaminated(ip, zscore)
                        return
                else:
                    self._contamination_streak.pop(ip, None)

        if self._sample_count >= CONVERGENCE_RECENT_WINDOW:
            shifts: list[float] = [bl.mean_shift(CONVERGENCE_RECENT_WINDOW) for bl in self._baselines.values()]
            avg_shift = sum(shifts) / len(shifts)
            confidence_factor = sqrt(min(self._sample_count / CONVERGENCE_RECENT_WINDOW, 4.0))
            effective_green = CONVERGENCE_GREEN * confidence_factor
            effective_yellow = CONVERGENCE_YELLOW * confidence_factor
            converged = avg_shift <= effective_green and self._sample_count >= self._baseline_min_samples
        else:
            avg_shift = None
            effective_green = CONVERGENCE_GREEN
            effective_yellow = CONVERGENCE_YELLOW
            converged = False

        if avg_shift is None:
            remaining = CONVERGENCE_RECENT_WINDOW - self._sample_count
            pct = int(self._sample_count / CONVERGENCE_RECENT_WINDOW * 50)
            style = PROGRESS_BAR_CHUNK_ORANGE_STYLESHEET
            label = f'Stability: <span style="color:orange;">Collecting data ({remaining}s left)</span>'
        elif self._sample_count < self._baseline_min_samples:
            remaining = self._baseline_min_samples - self._sample_count
            shift_ok = avg_shift <= effective_green
            pct = int(self._sample_count / self._baseline_min_samples * 60)
            if shift_ok:
                style = PROGRESS_BAR_CHUNK_ORANGE_STYLESHEET
                label = f'Stability: <span style="color:orange;">Looks stable, need {remaining}s more data</span>'
            else:
                style = PROGRESS_BAR_CHUNK_RED_STYLESHEET
                label = 'Stability: <span style="color:red;">Unstable — stay still</span>'
        elif converged:
            pct = 100
            style = PROGRESS_BAR_CHUNK_GREEN_STYLESHEET
            label = 'Stability: <span style="color:green;">Stable — Ready to stop</span>'
        elif avg_shift <= effective_yellow:
            ratio = (effective_yellow - avg_shift) / (effective_yellow - effective_green)
            pct = int(60 + ratio * 39)
            style = PROGRESS_BAR_CHUNK_ORANGE_STYLESHEET
            label = 'Stability: <span style="color:yellow;">Almost stable… keep waiting</span>'
        else:
            pct = max(int((1.0 - min(avg_shift, 1.0)) * 60), 5)
            style = PROGRESS_BAR_CHUNK_RED_STYLESHEET
            label = 'Stability: <span style="color:red;">Unstable — stay still</span>'

        self._update_stability(pct, style, label)
        num_ips = len(self._baselines)
        self._update_sample_label(f'{num_ips} IP{pluralize(num_ips)} · {self._sample_count} sample{pluralize(self._sample_count)}')

        if converged:
            self._auto_stop_baseline('converged')
        elif self._sample_count >= self._baseline_max_seconds:
            self._auto_stop_baseline(f'{self._baseline_max_seconds}s timeout')

    def _tick_ready(self, players: list[Player]) -> None:
        """Monitor while the baseline is locked and the user hasn't clicked Resolve yet."""
        aggregate_z = compute_aggregate_zscore(self._baselines, players)
        if aggregate_z is not None and abs(aggregate_z) >= self._session_drift_threshold:
            self._abort_session_changed()
            return

        connected_baselined = sum(1 for player in players if player.ip in self._baselines)
        if connected_baselined < MIN_CONNECTED_PLAYERS:
            self._abort_insufficient_players()
            return

    def _tick_resolving(self, players: list[Player]) -> None:
        connected_baselined = sum(1 for player in players if player.ip in self._baselines)
        if connected_baselined < MIN_CONNECTED_PLAYERS:
            self._abort_insufficient_players()
            return

        aggregate_z = compute_aggregate_zscore(self._baselines, players)
        if aggregate_z is not None and aggregate_z <= -self._session_drift_threshold:
            self._abort_session_changed()
            return

        max_streak = 0

        for player in players:
            baseline = self._baselines.get(player.ip)
            if baseline is None:
                continue
            score = baseline.spike_score(
                player.packets.pps.calculated_rate,
                player.bandwidth.bps.calculated_rate,
            )
            if score > self._spike_min_zscore:
                streak = self._spike_streak[player.ip] = self._spike_streak.get(player.ip, 0) + 1
                self._total_spike_duration[player.ip] = self._total_spike_duration.get(player.ip, 0) + 1
                if streak >= self._spike_sustained_seconds:
                    self._identified_ips.add(player.ip)
                max_streak = max(max_streak, streak)
            else:
                self._spike_streak.pop(player.ip, None)

        PlayerIdentifierTracker.set_identified_ips(self._identified_ips)

        if self._auto_select and self._identified_ips != self._currently_selected_ips:
            if self._identified_ips:
                if self._select_ips is not None:
                    self._select_ips(list(self._identified_ips))
            elif self._currently_selected_ips and self._deselect_ips is not None:
                self._deselect_ips(list(self._currently_selected_ips))
            self._currently_selected_ips = set(self._identified_ips)

        self._update_resolving_display(players, max_streak)

    def _update_resolving_display(self, players: list[Player], max_streak: int) -> None:
        player_by_ip = {player.ip: player for player in players}
        identified_players = [player_by_ip[ip] for ip in self._identified_ips if ip in player_by_ip]
        candidate_players = [player_by_ip[ip] for ip in self._spike_streak if ip in player_by_ip and ip not in self._identified_ips]

        if not identified_players and not candidate_players:
            num_ips = len(self._baselines)
            self._update_result_label(
                f'<b>No spiking players detected.</b><br><small>Watching {num_ips} baselined IP{pluralize(num_ips)} for traffic spikes.</small>',
            )
            self._update_stability(0, PROGRESS_BAR_IDLE_STYLESHEET, 'Stability: <span style="color:green;">Locked</span>', bar_format='Resolving…')
            return

        lines: list[str] = []
        if identified_players:
            num_identified = len(identified_players)
            lines.append(f'<b style="color:#27ae60;">{num_identified} player{pluralize(num_identified)} identified:</b>')
            for player in identified_players:
                name_part = f' ({", ".join(player.usernames)})' if player.usernames else ''
                formatted_bps = PlayerBandwidth.format_bytes(player.bandwidth.bps.calculated_rate)
                streak = self._spike_streak.get(player.ip, 0)
                total_duration = self._total_spike_duration.get(player.ip, 0)
                streak_text = f'streak: {streak}s (total: {total_duration}s)' if streak > 0 else f'total spike: {total_duration}s'
                lines.append(f'• <b>{player.ip}</b>{name_part} — {player.packets.pps.calculated_rate} PPS · {formatted_bps} · {streak_text}')

        if candidate_players:
            num_candidates = len(candidate_players)
            lines.append(f'<b style="color:#f39c12;">{num_candidates} candidate{pluralize(num_candidates)} spiking:</b>')
            for player in candidate_players:
                name_part = f' ({", ".join(player.usernames)})' if player.usernames else ''
                formatted_bps = PlayerBandwidth.format_bytes(player.bandwidth.bps.calculated_rate)
                streak = self._spike_streak.get(player.ip, 0)
                total_duration = self._total_spike_duration.get(player.ip, 0)
                streak_text = f'streak: {streak}/{self._spike_sustained_seconds}s (total: {total_duration}s)'
                lines.append(f'• <b>{player.ip}</b>{name_part} — {player.packets.pps.calculated_rate} PPS · {formatted_bps} · {streak_text}')

        if identified_players:
            lines.append('<small>Identified players are marked with a target icon in the connected players table.</small>')
        else:
            lines.append(f'<small>Needs {self._spike_sustained_seconds} consecutive seconds of elevated traffic to confirm.</small>')

        self._update_result_label('<br>'.join(lines))

        if identified_players:
            self._update_stability(100, PROGRESS_BAR_CHUNK_GREEN_STYLESHEET, 'Stability: <span style="color:green;">Resolved</span>', bar_format='Resolved')
        elif candidate_players:
            pct = min(int(max_streak / self._spike_sustained_seconds * 100), 99)
            self._update_stability(
                pct,
                PROGRESS_BAR_CHUNK_ORANGE_STYLESHEET,
                'Stability: <span style="color:orange;">Spike detected</span>',
                bar_format=f'{pct}%',
            )

    # -- Widget update helpers (skip redundant repaints) ----------------------

    def _update_stability(self, pct: int, style: str, label_text: str, bar_format: str | None = None) -> None:
        """Update stability bar and label only when values actually change."""
        resolved_format = bar_format if bar_format is not None else f'{pct}%'
        if pct != self._prev_stability_pct or resolved_format != self._prev_stability_format:
            self._stability_bar.setValue(pct)
            self._stability_bar.setFormat(resolved_format)
            self._prev_stability_pct = pct
            self._prev_stability_format = resolved_format
        if style != self._prev_stability_style:
            self._stability_bar.setStyleSheet(style)
            self._prev_stability_style = style
        if label_text != self._prev_stability_text:
            self._stability_label.setText(label_text)
            self._prev_stability_text = label_text

    def _update_sample_label(self, text: str) -> None:
        """Update sample label only when text actually changes."""
        if text != self._prev_sample_text:
            self._sample_label.setText(text)
            self._prev_sample_text = text

    def _update_result_label(self, text: str) -> None:
        """Update result label only when text actually changes."""
        if text != self._prev_result_text:
            self._result_label.setText(text)
            self._prev_result_text = text

    @property
    def _spike_min_zscore(self) -> float:
        return self._params_box.spike_min_zscore

    @property
    def _spike_sustained_seconds(self) -> int:
        return self._params_box.spike_sustained_seconds

    @property
    def _contamination_zscore(self) -> float:
        return self._params_box.contamination_zscore

    @property
    def _contamination_seconds(self) -> int:
        return self._params_box.contamination_seconds

    @property
    def _contamination_min_samples(self) -> int:
        return self._params_box.contamination_min_samples

    @property
    def _baseline_min_samples(self) -> int:
        return self._params_box.baseline_min_samples

    @property
    def _baseline_max_seconds(self) -> int:
        return self._params_box.baseline_max_seconds

    @property
    def _session_drift_threshold(self) -> float:
        return self._params_box.session_drift_threshold
