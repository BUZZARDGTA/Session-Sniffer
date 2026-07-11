"""Player Identifier — baseline PPS/BPS profiles then detect spikes to correlate IPs to players."""

from math import sqrt
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.guis._player_identifier_core import (
    BASELINE_CONTAMINATION_MIN_SAMPLES,
    BASELINE_CONTAMINATION_SECONDS,
    BASELINE_CONTAMINATION_ZSCORE,
    BASELINE_MAX_SECONDS,
    BASELINE_MIN_SAMPLES,
    BUTTON_WIDTH,
    CONVERGENCE_GREEN,
    CONVERGENCE_RECENT_WINDOW,
    CONVERGENCE_YELLOW,
    MIN_CONNECTED_PLAYERS,
    SESSION_DRIFT_ZSCORE_THRESHOLD,
    SPIKE_MIN_ZSCORE,
    SPIKE_SUSTAINED_SECONDS,
    UPDATE_INTERVAL_MS,
    ZSCORE_ELEVATED,
    IPBaseline,
    Phase,
    ResolvedIP,
    zscore_to_confidence,
)
from session_sniffer.guis.stylesheets import (
    PROGRESS_BAR_CHUNK_GREEN_STYLESHEET,
    PROGRESS_BAR_CHUNK_RED_STYLESHEET,
    PROGRESS_BAR_IDLE_STYLESHEET,
)
from session_sniffer.guis.utils import ElidedTextTooltipDelegate
from session_sniffer.models.player import PlayerBandwidth
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.models.player import Player


class PlayerIdentifierWidget(QWidget):
    """Baseline PPS/BPS then detect spikes to identify which IP belongs to a target player."""

    def __init__(self, highlight_ips_callback: Callable[[list[str]], None], parent: QWidget | None = None) -> None:
        """Initialize the Player Identifier widget."""
        super().__init__(parent)

        self._highlight_ips = highlight_ips_callback
        self._phase = Phase.IDLE
        self._baseline_ips: set[str] = set()
        self._baselines: dict[str, IPBaseline] = {}
        self._sample_count = 0
        self._spike_streak: dict[str, int] = {}
        self._contamination_streak: dict[str, int] = {}
        self._resolved_ips: list[ResolvedIP] = []

        # Tweakable detection parameters (adjusted via the control panel)
        self._spike_min_zscore: float = SPIKE_MIN_ZSCORE
        self._spike_sustained_seconds: int = SPIKE_SUSTAINED_SECONDS
        self._contamination_zscore: float = BASELINE_CONTAMINATION_ZSCORE
        self._contamination_seconds: int = BASELINE_CONTAMINATION_SECONDS
        self._contamination_min_samples: int = BASELINE_CONTAMINATION_MIN_SAMPLES
        self._baseline_min_samples: int = BASELINE_MIN_SAMPLES
        self._baseline_max_seconds: int = BASELINE_MAX_SECONDS
        self._session_drift_threshold: float = SESSION_DRIFT_ZSCORE_THRESHOLD

        # Widget update caches — skip redundant repaints when values haven't changed
        self._prev_stability_pct: int | None = None
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

        self._stability_bar = QProgressBar()
        self._stability_bar.setRange(0, 100)
        self._stability_bar.setValue(0)
        self._stability_bar.setTextVisible(True)
        self._stability_bar.setFormat('Waiting...')
        self._stability_bar.setFixedWidth(BUTTON_WIDTH)
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

        # Live z-score table
        self._zscore_table = QTableWidget(0, 6)
        _username_header = QTableWidgetItem('Username')
        _username_header.setToolTip('The in-game username associated with this IP (if known).')
        self._zscore_table.setHorizontalHeaderItem(0, _username_header)
        _ip_header = QTableWidgetItem('IP')
        _ip_header.setToolTip('The IP address of the tracked player.')
        self._zscore_table.setHorizontalHeaderItem(1, _ip_header)
        _pps_header = QTableWidgetItem('PPS')
        _pps_header.setToolTip('Current packets per second for this IP.')
        self._zscore_table.setHorizontalHeaderItem(2, _pps_header)
        _bps_header = QTableWidgetItem('BPS')
        _bps_header.setToolTip('Current bytes per second for this IP.')
        self._zscore_table.setHorizontalHeaderItem(3, _bps_header)
        _zscore_header = QTableWidgetItem('Z-Score')
        _zscore_header.setToolTip(
            "How far this IP's current traffic deviates from its baseline.\n\n"
            'Green  (< 3.0)                — normal\n'
            'Yellow (≥ 3.0)                — slightly elevated\n'
            'Orange (≥ spike threshold)    — in spike zone (resolve confirmation)\n'
            'Red    (≥ contam. threshold)  — baseline abort zone',
        )
        self._zscore_table.setHorizontalHeaderItem(4, _zscore_header)
        _streak_header = QTableWidgetItem('Streak')
        _streak_header.setToolTip(
            'Consecutive seconds above the relevant threshold.\n\n'
            'Baseline/Ready phase: contamination streak — aborts when it reaches\n'
            'the contamination duration (see ⚙ Parameters).\n\n'
            'Resolving phase: spike streak — confirms the IP as a match when\n'
            'it reaches the spike duration (see ⚙ Parameters).',
        )
        self._zscore_table.setHorizontalHeaderItem(5, _streak_header)
        _zscore_header_view = self._zscore_table.horizontalHeader()
        if not _zscore_header_view:
            message = 'Failed to get horizontal header view'
            raise RuntimeError(message)
        _zscore_header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        _zscore_header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        _zscore_header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        _zscore_header_view.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        _zscore_header_view.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        _zscore_header_view.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self._zscore_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._zscore_table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self._zscore_table.setItemDelegate(ElidedTextTooltipDelegate(self._zscore_table))
        self._zscore_table.setWordWrap(False)
        self._zscore_table.setMaximumHeight(150)
        self._zscore_table.setVisible(False)
        layout.addWidget(self._zscore_table)

        # Result label
        self._result_label = QLabel('')
        self._result_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._result_label.setWordWrap(True)
        layout.addWidget(self._result_label)

        # Buttons row
        button_layout = QHBoxLayout()
        button_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._start_button = QPushButton('Start Baseline')
        self._start_button.setToolTip(
            'Step 1: Records the normal traffic (PPS/BPS) for every IP currently in the session.\n\n'
            'IMPORTANT: Make sure you are ALONE and standing still (e.g. inside a bunker, '
            'facility, or away from all other players) before clicking this.\n\n'
            'Only IPs connected RIGHT NOW will be tracked. Anyone who joins later is ignored.\n\n'
            f'The baseline runs until traffic is stable or {self._baseline_max_seconds}s have elapsed, then automatically locks in.',
        )
        self._start_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._start_button.setFixedWidth(BUTTON_WIDTH)
        self._start_button.clicked.connect(self._on_start_baseline)
        button_layout.addWidget(self._start_button)

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

        self._reset_button = QPushButton('Reset')
        self._reset_button.setToolTip('Discard all data and start over from scratch.')
        self._reset_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._reset_button.setFixedWidth(BUTTON_WIDTH)
        self._reset_button.clicked.connect(self.reset)
        self._reset_button.setEnabled(False)
        button_layout.addWidget(self._reset_button)

        layout.addLayout(button_layout)
        layout.addStretch()

        # Parameters control panel
        self._params_box = QGroupBox('⚙ Parameters')
        params_layout = QFormLayout(self._params_box)
        params_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self._spike_zscore_input = QDoubleSpinBox()
        self._spike_zscore_input.setRange(1.0, 20.0)
        self._spike_zscore_input.setSingleStep(0.5)
        self._spike_zscore_input.setDecimals(1)
        self._spike_zscore_input.setValue(self._spike_min_zscore)
        self._spike_zscore_input.setToolTip(
            'Minimum z-score for an IP to be considered spiking during the Resolve phase.\n\n'
            'Higher = only very dramatic traffic increases trigger detection.\n'
            'Lower = more sensitive but may produce false positives.',
        )
        self._spike_zscore_input.valueChanged.connect(self._set_spike_min_zscore)
        params_layout.addRow('Spike Z-Score:', self._spike_zscore_input)

        self._spike_seconds_input = QSpinBox()
        self._spike_seconds_input.setRange(1, 30)
        self._spike_seconds_input.setValue(self._spike_sustained_seconds)
        self._spike_seconds_input.setSuffix('s')
        self._spike_seconds_input.setToolTip(
            'Consecutive seconds an IP must stay above the spike z-score to be confirmed as the target.\n\n'
            'Higher = fewer false positives but takes longer to confirm.\n'
            'Lower = faster confirmation but may match brief coincidental traffic bursts.',
        )
        self._spike_seconds_input.valueChanged.connect(self._set_spike_sustained_seconds)
        params_layout.addRow('Spike Duration:', self._spike_seconds_input)

        self._contam_zscore_input = QDoubleSpinBox()
        self._contam_zscore_input.setRange(3.0, 50.0)
        self._contam_zscore_input.setSingleStep(0.5)
        self._contam_zscore_input.setDecimals(1)
        self._contam_zscore_input.setValue(self._contamination_zscore)
        self._contam_zscore_input.setToolTip(
            'Z-score threshold for detecting baseline contamination (active during baseline and ready phases).\n\n'
            'If an IP sustains this z-score for the contamination duration, the baseline is aborted.\n'
            'Higher = less likely to abort on normal traffic variation.\n'
            'Lower = more aggressively detects movement or spectating.',
        )
        self._contam_zscore_input.valueChanged.connect(self._set_contamination_zscore)
        params_layout.addRow('Contamination Z-Score:', self._contam_zscore_input)

        self._contamination_seconds_input = QSpinBox()
        self._contamination_seconds_input.setRange(1, 30)
        self._contamination_seconds_input.setValue(self._contamination_seconds)
        self._contamination_seconds_input.setSuffix('s')
        self._contamination_seconds_input.setToolTip(
            'Consecutive seconds an IP must stay above the contamination z-score to trigger a baseline abort.\n\n'
            'Higher = more tolerant of brief traffic bursts (fewer false aborts).\n'
            'Lower = aborts sooner if any IP stays elevated.',
        )
        self._contamination_seconds_input.valueChanged.connect(self._set_contamination_seconds)
        params_layout.addRow('Contamination Duration:', self._contamination_seconds_input)

        self._contam_min_samples_input = QSpinBox()
        self._contam_min_samples_input.setRange(5, 60)
        self._contam_min_samples_input.setValue(self._contamination_min_samples)
        self._contam_min_samples_input.setSuffix('s')
        self._contam_min_samples_input.setToolTip(
            'Minimum samples collected before contamination checking activates.\n\n'
            'Prevents false aborts right at the start when the baseline has very little data.\n'
            'Lower = contamination detection activates sooner.',
        )
        self._contam_min_samples_input.valueChanged.connect(self._set_contamination_min_samples)
        params_layout.addRow('Contam. Grace Period:', self._contam_min_samples_input)

        self._min_samples_input = QSpinBox()
        self._min_samples_input.setRange(5, 120)
        self._min_samples_input.setValue(self._baseline_min_samples)
        self._min_samples_input.setSuffix('s')
        self._min_samples_input.setToolTip(
            'Minimum number of 1-second samples required before the baseline can auto-lock on convergence.\n\n'
            'More samples = more statistically accurate baseline.\n'
            'Fewer = faster lock but potentially less reliable detection.',
        )
        self._min_samples_input.valueChanged.connect(self._set_baseline_min_samples)
        params_layout.addRow('Min Baseline Samples:', self._min_samples_input)

        self._max_seconds_input = QSpinBox()
        self._max_seconds_input.setRange(10, 300)
        self._max_seconds_input.setValue(self._baseline_max_seconds)
        self._max_seconds_input.setSuffix('s')
        self._max_seconds_input.setToolTip(
            'Hard time limit for the baseline phase.\n\n'
            'If traffic has not converged within this many seconds, the baseline locks anyway.\n'
            'Increase for very variable or noisy network conditions.',
        )
        self._max_seconds_input.valueChanged.connect(self._set_baseline_max_seconds)
        params_layout.addRow('Baseline Timeout:', self._max_seconds_input)

        self._drift_threshold_input = QDoubleSpinBox()
        self._drift_threshold_input.setRange(1.0, 30.0)
        self._drift_threshold_input.setSingleStep(0.5)
        self._drift_threshold_input.setDecimals(1)
        self._drift_threshold_input.setValue(self._session_drift_threshold)
        self._drift_threshold_input.setToolTip(
            'Aggregate z-score threshold for detecting session-wide traffic drift.\n\n'
            'If the median z-score across all tracked IPs exceeds this magnitude, '
            'the tool assumes the session has changed and aborts.\n'
            'Higher = more tolerant of session-wide traffic shifts.',
        )
        self._drift_threshold_input.valueChanged.connect(self._set_session_drift_threshold)
        params_layout.addRow('Session Drift Z-Score:', self._drift_threshold_input)

        layout.addWidget(self._params_box)

        # Timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

    # -- Phase transitions ----------------------------------------------------

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
        # Snapshot the IPs present right now — only these will be baselined
        players = PlayersRegistry.get_connected_players()
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
        self._contamination_streak.clear()
        self._resolved_ips = []
        self._prev_stability_pct = None
        self._prev_stability_style = None
        self._prev_stability_text = None
        self._prev_sample_text = None
        self._prev_result_text = None
        self._result_label.setText('')
        self._start_button.setEnabled(False)
        self._resolve_button.setEnabled(False)

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
        self._stability_label.setVisible(True)
        self._stability_bar.setVisible(True)
        self._sample_label.setVisible(True)
        self._sample_label.setText('')
        self._reset_button.setEnabled(True)
        self._zscore_table.setRowCount(0)
        self._zscore_table.setVisible(True)
        self._params_box.setVisible(False)
        self._timer.start(UPDATE_INTERVAL_MS)

    def _auto_stop_baseline(self, reason: str) -> None:
        """Finalize baselines and transition to READY (timer keeps running for contamination monitoring)."""
        for bl in self._baselines.values():
            bl.finalize()
        self._phase = Phase.READY
        self._resolve_button.setEnabled(True)
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
        self._stability_label.setText('Stability: <span style="color:green;">Locked ✔</span>')
        self._contamination_streak.clear()

    def _on_resolve(self) -> None:
        self._phase = Phase.RESOLVING
        self._spike_streak.clear()
        self._resolved_ips = []
        self._resolve_button.setEnabled(False)
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
        self._stability_bar.setStyleSheet(PROGRESS_BAR_IDLE_STYLESHEET)
        # Timer is already running from baseline/READY phase; no restart needed

    def reset(self) -> None:
        """Discard all data and return the widget to its initial idle state."""
        self._timer.stop()
        self._phase = Phase.IDLE
        self._baseline_ips.clear()
        self._baselines.clear()
        self._sample_count = 0
        self._spike_streak.clear()
        self._contamination_streak.clear()
        self._resolved_ips = []
        self._start_button.setEnabled(True)
        self._resolve_button.setEnabled(False)
        self._reset_button.setEnabled(False)
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
        self._zscore_table.setRowCount(0)
        self._zscore_table.setVisible(False)
        self._params_box.setVisible(True)

    def _abort_insufficient_players(self) -> None:
        """Stop the current phase because too many players disconnected."""
        self._timer.stop()
        self._phase = Phase.IDLE
        self._start_button.setEnabled(True)
        self._resolve_button.setEnabled(False)
        self._params_box.setVisible(True)
        self._stability_bar.setValue(0)
        self._stability_bar.setFormat('Aborted')
        self._stability_bar.setStyleSheet(PROGRESS_BAR_CHUNK_RED_STYLESHEET)
        self._stability_label.setText(
            'Stability: <span style="color:red;">Aborted — not enough players remaining</span>',
        )
        self._instructions.setText(
            f'<b style="color:#e74c3c;">Aborted:</b> fewer than {MIN_CONNECTED_PLAYERS} tracked players remain in the session.<br><br>'
            'Players disconnected while the scan was running. Click <b>Reset</b> and try again…',
        )

    def _abort_contaminated(self, ip: str, zscore: float) -> None:
        """Stop the baseline because a dramatic traffic spike was detected (contamination)."""
        self._timer.stop()
        self._phase = Phase.IDLE
        self._start_button.setEnabled(True)
        self._resolve_button.setEnabled(False)
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
            'Click <b>Reset</b> to start over. Make sure you stay completely still and isolated.',
        )

    def _abort_session_changed(self) -> None:
        """Stop the current phase because overall session traffic drifted too far from the baseline."""
        self._timer.stop()
        self._phase = Phase.IDLE
        self._start_button.setEnabled(True)
        self._resolve_button.setEnabled(False)
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
            'Click <b>Reset</b> to start over.',
        )

    # -- Periodic tick --------------------------------------------------------

    def _compute_aggregate_zscore(self, players: list[Player]) -> float | None:
        """Return the median spike z-score across all baselined IPs, or None if fewer than 2 IPs are available.

        Uses median instead of mean so that a single high-z outlier (the target player being watched)
        does not falsely trigger the aggregate-drift abort. Only session-wide events where the majority
        of IPs shift together (e.g. mass disconnect, session ended) will push the median above the threshold.

        Uses the finalized baseline (must only be called after BASELINE phase ends).
        A positive value means overall traffic is higher than baseline; negative means lower.
        """
        scores: list[float] = []
        for player in players:
            bl = self._baselines.get(player.ip)
            if bl is None:
                continue
            scores.append(bl.spike_score(player.packets.pps.calculated_rate, player.bandwidth.bps.calculated_rate))
        if len(scores) < MIN_CONNECTED_PLAYERS:
            return None
        scores.sort()
        mid = len(scores) // 2
        if not len(scores) % 2:
            return (scores[mid - 1] + scores[mid]) / 2.0
        return scores[mid]

    def _tick(self) -> None:
        players = PlayersRegistry.get_connected_players()
        if self._phase == Phase.BASELINE:
            self._tick_baseline(players)
        elif self._phase == Phase.READY:
            self._tick_ready(players)
        elif self._phase == Phase.RESOLVING:
            self._tick_resolving(players)

    def _tick_baseline(self, players: list[Player]) -> None:
        self._sample_count += 1
        # Build a lookup of only the players we're tracking (avoids full dict rebuild)
        baseline_ips = self._baseline_ips
        sampled_ips: set[str] = set()
        player_by_ip: dict[str, Player] = {}
        for player in players:
            ip = player.ip
            if ip in baseline_ips:
                sampled_ips.add(ip)
                player_by_ip[ip] = player
                self._baselines[ip].add_sample(
                    player.packets.pps.calculated_rate,
                    player.bandwidth.bps.calculated_rate,
                )
        # Remove any IPs that disconnected
        disconnected = baseline_ips - sampled_ips
        if disconnected:
            baseline_ips -= disconnected
            for ip in disconnected:
                self._baselines.pop(ip, None)

        # Compute convergence: are the running means still shifting?
        if len(self._baselines) < MIN_CONNECTED_PLAYERS:
            self._abort_insufficient_players()
            return

        # Contamination check: if any IP shows a dramatic spike after enough
        # samples have been collected, the baseline is compromised (e.g. the
        # user spectated someone or moved closer to a player).
        # Requires BASELINE_CONTAMINATION_SECONDS consecutive ticks above the threshold
        # to avoid false positives from single-tick network bursts.
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
            # Scale convergence thresholds with sample count.
            # More samples = baseline is more established, so natural noise
            # (PPS/BPS jitter) should not block convergence.
            # Uses sqrt to model the expected decrease in noise floor.
            confidence_factor = sqrt(min(self._sample_count / CONVERGENCE_RECENT_WINDOW, 4.0))
            effective_green = CONVERGENCE_GREEN * confidence_factor
            effective_yellow = CONVERGENCE_YELLOW * confidence_factor
            # Require minimum samples before allowing convergence to lock
            converged = avg_shift <= effective_green and self._sample_count >= self._baseline_min_samples
        else:
            avg_shift = None
            effective_green = CONVERGENCE_GREEN
            effective_yellow = CONVERGENCE_YELLOW
            converged = False

        # Map convergence to progress (lower shift = higher progress)
        if avg_shift is None:
            # Still collecting initial samples — ramp progress smoothly toward 50%
            remaining = CONVERGENCE_RECENT_WINDOW - self._sample_count
            pct = int(self._sample_count / CONVERGENCE_RECENT_WINDOW * 50)
            style = 'QProgressBar::chunk { background-color: #f39c12; }'
            label = f'Stability: <span style="color:orange;">Collecting data ({remaining}s left)</span>'
        elif self._sample_count < self._baseline_min_samples:
            # Have enough for shift calculation but not enough to lock
            remaining = self._baseline_min_samples - self._sample_count
            shift_ok = avg_shift <= effective_green
            pct = int(self._sample_count / self._baseline_min_samples * 60)
            if shift_ok:
                style = 'QProgressBar::chunk { background-color: #f39c12; }'
                label = f'Stability: <span style="color:orange;">Looks stable, need {remaining}s more data</span>'
            else:
                style = 'QProgressBar::chunk { background-color: #e74c3c; }'
                label = 'Stability: <span style="color:red;">Unstable — stay still</span>'
        elif converged:
            pct = 100
            style = 'QProgressBar::chunk { background-color: #27ae60; }'
            label = 'Stability: <span style="color:green;">Stable ✔ Ready to stop</span>'
        elif avg_shift <= effective_yellow:
            ratio = (effective_yellow - avg_shift) / (effective_yellow - effective_green)
            pct = int(60 + ratio * 39)
            style = 'QProgressBar::chunk { background-color: #f39c12; }'
            label = 'Stability: <span style="color:yellow;">Almost stable… keep waiting</span>'
        else:
            pct = max(int((1.0 - min(avg_shift, 1.0)) * 60), 5)
            style = 'QProgressBar::chunk { background-color: #e74c3c; }'
            label = 'Stability: <span style="color:red;">Unstable — stay still</span>'

        self._update_stability(pct, style, label)
        num_ips = len(self._baselines)
        self._update_sample_label(f'{num_ips} IP{pluralize(num_ips)} · {self._sample_count} sample{pluralize(self._sample_count)}')

        # Update live z-score table (sorted by z-score descending)
        table_rows = sorted(
            [
                (
                    player_by_ip[ip].usernames[0] if player_by_ip[ip].usernames else '—',
                    ip,
                    player_by_ip[ip].packets.pps.calculated_rate,
                    player_by_ip[ip].bandwidth.bps.calculated_rate,
                    bl.live_zscore(
                        player_by_ip[ip].packets.pps.calculated_rate,
                        player_by_ip[ip].bandwidth.bps.calculated_rate,
                    ),
                    self._contamination_streak.get(ip, 0),
                )
                for ip, bl in self._baselines.items()
                if ip in player_by_ip
            ],
            key=lambda row: row[4],
            reverse=True,
        )
        self._update_zscore_table(table_rows)

        # Auto-stop: convergence reached or hard timeout
        if converged:
            self._auto_stop_baseline('converged')
        elif self._sample_count >= self._baseline_max_seconds:
            self._auto_stop_baseline(f'{self._baseline_max_seconds}s timeout')

    def _tick_ready(self, players: list[Player]) -> None:
        """Monitor while the baseline is locked and the user hasn't clicked Resolve yet."""
        aggregate_z = self._compute_aggregate_zscore(players)
        if aggregate_z is not None and abs(aggregate_z) >= self._session_drift_threshold:
            self._abort_session_changed()
            return

        connected_baselined = sum(1 for player in players if player.ip in self._baselines)
        if connected_baselined < MIN_CONNECTED_PLAYERS:
            self._abort_insufficient_players()
            return

        # Update live z-score table (sorted by z-score descending)
        player_by_ip = {player.ip: player for player in players}
        table_rows = sorted(
            [
                (
                    player_by_ip[ip].usernames[0] if player_by_ip[ip].usernames else '—',
                    ip,
                    player_by_ip[ip].packets.pps.calculated_rate,
                    player_by_ip[ip].bandwidth.bps.calculated_rate,
                    bl.spike_score(
                        player_by_ip[ip].packets.pps.calculated_rate,
                        player_by_ip[ip].bandwidth.bps.calculated_rate,
                    ),
                    self._contamination_streak.get(ip, 0),
                )
                for ip, bl in self._baselines.items()
                if ip in player_by_ip
            ],
            key=lambda row: row[4],
            reverse=True,
        )
        self._update_zscore_table(table_rows)

    def _tick_resolving(self, players: list[Player]) -> None:
        confirmed_baselined: list[ResolvedIP] = []
        max_streak = 0

        # --- 1. Check baselined IPs for spikes FIRST ---
        # Must run before any abort so a building spike can confirm even if
        # conditions change in the same tick (e.g. everyone leaves at once).
        for player in players:
            ip = player.ip
            bl = self._baselines.get(ip)
            if bl is None:
                continue
            score = bl.spike_score(
                player.packets.pps.calculated_rate,
                player.bandwidth.bps.calculated_rate,
            )
            if score > self._spike_min_zscore:
                streak = self._spike_streak[ip] = self._spike_streak.get(ip, 0) + 1
                if streak >= self._spike_sustained_seconds:
                    confirmed_baselined.append(ResolvedIP(ip, zscore_to_confidence(score), f'PPS/BPS spike (z={score:.1f})', player.usernames[0] if player.usernames else ''))
                max_streak = max(max_streak, streak)
            else:
                self._spike_streak.pop(ip, None)

        # --- Resolve if any IPs confirmed ---
        all_resolved = sorted(confirmed_baselined, key=lambda resolved_ip: resolved_ip.confidence, reverse=True)
        if all_resolved:
            self._resolve_matches(all_resolved)
            return

        # --- 2. Aggregate baseline-drift check (drop only) ---
        # Only abort when traffic drops significantly below baseline (session ended / disconnected).
        # A positive spike is expected — the user is near players and that raises all traffic.
        aggregate_z = self._compute_aggregate_zscore(players)
        if aggregate_z is not None and aggregate_z <= -self._session_drift_threshold:
            self._abort_session_changed()
            return

        # --- 3. Abort if too many baselined IPs disconnected ---
        connected_baselined = sum(1 for player in players if player.ip in self._baselines)
        if connected_baselined < MIN_CONNECTED_PLAYERS:
            self._abort_insufficient_players()
            return

        # --- Show live candidate status (only update label when text changes) ---
        if self._spike_streak:
            parts = ', '.join(f'<b>{ip}</b> (spiking {streak}/{self._spike_sustained_seconds}s)' for ip, streak in self._spike_streak.items())
            num_candidates = len(self._spike_streak)
            result_text = (
                f'Possible candidate{pluralize(num_candidates)}: {parts}<br>'
                f'<small>Needs {self._spike_sustained_seconds} consecutive seconds of elevated traffic to confirm.</small>'
            )
        else:
            num_ips = len(self._baselines)
            result_text = (
                f'Watching {num_ips} baselined IP{pluralize(num_ips)} for traffic spikes…<br><small>Walk toward the target player. No unusual traffic detected yet.</small>'
            )
        self._update_result_label(result_text)

        # Update progress bar as a visual heartbeat (max_streak tracked incrementally)
        self._stability_bar.setValue(min(int(max_streak / self._spike_sustained_seconds * 100), 99))

        # Update live z-score table (sorted by z-score descending)
        table_rows: list[tuple[str, str, int, int, float, int]] = []
        for player in players:
            bl = self._baselines.get(player.ip)
            if bl is None:
                continue
            score = bl.spike_score(
                player.packets.pps.calculated_rate,
                player.bandwidth.bps.calculated_rate,
            )
            table_rows.append(
                (
                    player.usernames[0] if player.usernames else '—',
                    player.ip,
                    player.packets.pps.calculated_rate,
                    player.bandwidth.bps.calculated_rate,
                    score,
                    self._spike_streak.get(player.ip, 0),
                ),
            )
        table_rows.sort(key=lambda row: row[4], reverse=True)
        self._update_zscore_table(table_rows)

    def _resolve_matches(self, resolved: list[ResolvedIP]) -> None:
        self._timer.stop()
        self._phase = Phase.RESOLVED
        self._resolved_ips = resolved

        # Build ranked result text
        num_resolved = len(resolved)
        lines: list[str] = [f'🎯 {num_resolved} match{pluralize(num_resolved, plural="es")} found (ranked by confidence):']
        for rank, entry in enumerate(resolved, 1):
            name_part = f' — <b>{entry.username}</b>' if entry.username else ''
            lines.append(f'#{rank} — <b>{entry.ip}</b>{name_part} — {entry.confidence:.0f}% — {entry.reason}')
        lines.append('')
        lines.append(f'The IP{pluralize(num_resolved)} ha{pluralize(num_resolved, singular="s", plural="ve")} been highlighted in the connected players table.')

        self._result_label.setText('<br>'.join(lines))
        self._instructions.setText(
            f'{num_resolved} player{pluralize(num_resolved)} identified!<br>Click <b>Reset</b> to start over, or check the highlighted rows in the connected players table.',
        )
        self._stability_bar.setValue(100)
        self._stability_bar.setFormat('Resolved ✔')
        self._stability_bar.setStyleSheet(PROGRESS_BAR_CHUNK_GREEN_STYLESHEET)
        self._start_button.setEnabled(False)
        self._resolve_button.setEnabled(False)
        self._zscore_table.setRowCount(0)
        self._zscore_table.setVisible(False)
        self._highlight_ips([entry.ip for entry in resolved])

    # -- Widget update helpers (skip redundant repaints) ----------------------

    def _update_stability(self, pct: int, style: str, label_text: str) -> None:
        """Update stability bar and label only when values actually change."""
        if pct != self._prev_stability_pct:
            self._stability_bar.setValue(pct)
            self._stability_bar.setFormat(f'{pct}%')
            self._prev_stability_pct = pct
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

    def _update_zscore_table(self, rows: list[tuple[str, str, int, int, float, int]]) -> None:
        """Rebuild the live z-score table. rows = [(username, ip, pps, bps, zscore, streak), ...] sorted by zscore desc."""
        self._zscore_table.setRowCount(len(rows))
        for row_index, (username, ip, pps, bps, zscore, streak) in enumerate(rows):
            username_item = QTableWidgetItem(username)
            username_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            ip_item = QTableWidgetItem(ip)
            ip_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            pps_item = QTableWidgetItem(str(pps))
            pps_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            bps_item = QTableWidgetItem(PlayerBandwidth.format_bytes(bps))
            bps_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            zscore_item = QTableWidgetItem(f'{zscore:.1f}')
            zscore_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            streak_text = f'{streak}/{self._spike_sustained_seconds}' if streak > 0 else '—'
            streak_item = QTableWidgetItem(streak_text)
            streak_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            if zscore >= self._contamination_zscore:
                zscore_item.setForeground(QColor('#e74c3c'))  # red — at/above contamination threshold
            elif zscore >= self._spike_min_zscore:
                zscore_item.setForeground(QColor('#f39c12'))  # orange — in spike zone
            elif zscore >= ZSCORE_ELEVATED:
                zscore_item.setForeground(QColor('#f1c40f'))  # yellow — slightly elevated
            else:
                zscore_item.setForeground(QColor('#27ae60'))  # green — normal

            if streak > 0:
                streak_item.setForeground(QColor('#f39c12'))

            self._zscore_table.setItem(row_index, 0, username_item)
            self._zscore_table.setItem(row_index, 1, ip_item)
            self._zscore_table.setItem(row_index, 2, pps_item)
            self._zscore_table.setItem(row_index, 3, bps_item)
            self._zscore_table.setItem(row_index, 4, zscore_item)
            self._zscore_table.setItem(row_index, 5, streak_item)

    # -- Parameter setters ----------------------------------------------------

    def _set_spike_min_zscore(self, value: float) -> None:
        self._spike_min_zscore = value

    def _set_spike_sustained_seconds(self, value: int) -> None:
        self._spike_sustained_seconds = value

    def _set_contamination_zscore(self, value: float) -> None:
        self._contamination_zscore = value

    def _set_contamination_seconds(self, value: int) -> None:
        self._contamination_seconds = value

    def _set_contamination_min_samples(self, value: int) -> None:
        self._contamination_min_samples = value

    def _set_baseline_min_samples(self, value: int) -> None:
        self._baseline_min_samples = value

    def _set_baseline_max_seconds(self, value: int) -> None:
        self._baseline_max_seconds = value

    def _set_session_drift_threshold(self, value: float) -> None:
        self._session_drift_threshold = value
