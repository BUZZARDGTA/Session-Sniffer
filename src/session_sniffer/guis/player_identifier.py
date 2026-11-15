"""Player Identifier — baseline PPS/BPS profiles then detect spikes to correlate IPs to players."""

import html
from math import sqrt
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
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
    PlayerIdentifierProgressBar,
    PlayerIdentifierTracker,
    compute_aggregate_zscore,
)
from session_sniffer.guis.live_language import register_language_refresh
from session_sniffer.guis.stylesheets import (
    PROGRESS_BAR_CHUNK_BLUE_STYLESHEET,
    PROGRESS_BAR_CHUNK_GREEN_STYLESHEET,
    PROGRESS_BAR_CHUNK_ORANGE_STYLESHEET,
    PROGRESS_BAR_CHUNK_RED_STYLESHEET,
    PROGRESS_BAR_IDLE_STYLESHEET,
)
from session_sniffer.guis.theming import themed_qss
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.models.player_traffic import PlayerBandwidth
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.models.player import Player


class PlayerIdentifierWidget(QWidget):
    """Baseline PPS/BPS then detect spikes to identify which IP belongs to a target player."""

    def __init__(
        self,
        select_ips_callback: Callable[[list[str]], None] | None = None,
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

        # Widget update caches — skip redundant repaints when values haven't changed
        self._prev_stability_pct: int | None = None
        self._prev_stability_format: str | None = None
        self._prev_stability_style: str | None = None
        self._prev_stability_text: str | None = None
        self._prev_sample_text: str | None = None
        self._prev_result_text: str | None = None

        self._ready_reason_kind: tuple[str, int] | None = None
        self._abort_state: tuple[str, tuple[str, float] | None] | None = None
        self._baseline_stability_snapshot: tuple[int, str, str, tuple[str, str, int | None]] | None = None
        self._last_max_streak: int = 0

        layout = QVBoxLayout(self)

        # Instructions
        self._instructions = QLabel()
        self._instructions.setWordWrap(True)
        self._instructions.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._instructions)

        # Stability indicator
        self._stability_label = QLabel()
        self._stability_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._stability_label.setVisible(False)
        layout.addWidget(self._stability_label)

        self._stability_bar = PlayerIdentifierProgressBar()
        self._stability_bar.setRange(0, 100)
        self._stability_bar.setValue(0)
        self._stability_bar.setTextVisible(True)
        self._stability_bar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._stability_bar.setFixedWidth(PROGRESS_BAR_WIDTH)
        self._stability_bar.setStyleSheet(PROGRESS_BAR_IDLE_STYLESHEET)
        self._stability_bar.setVisible(False)
        layout.addWidget(self._stability_bar, alignment=Qt.AlignmentFlag.AlignHCenter)

        # Sample count label
        self._sample_label = QLabel('')
        self._sample_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
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

        self._baseline_button = QPushButton()
        self._baseline_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._baseline_button.setFixedWidth(BUTTON_WIDTH)
        self._baseline_button.clicked.connect(self._on_baseline_button_clicked)
        button_layout.addWidget(self._baseline_button)

        self._resolve_button = QPushButton()
        self._resolve_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._resolve_button.setFixedWidth(BUTTON_WIDTH)
        self._resolve_button.clicked.connect(self._on_resolve)
        self._resolve_button.setEnabled(False)
        button_layout.addWidget(self._resolve_button)

        self._reset_button = QPushButton()
        self._reset_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._reset_button.setFixedWidth(BUTTON_WIDTH)
        self._reset_button.clicked.connect(self._on_reset_scan)
        self._reset_button.setEnabled(False)
        button_layout.addWidget(self._reset_button)

        layout.addLayout(button_layout)

        # Table selection controls
        table_selection_layout = QHBoxLayout()
        table_selection_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._select_button = QPushButton()
        self._select_button.setFixedWidth(BUTTON_WIDTH)
        self._select_button.setEnabled(False)
        self._select_button.clicked.connect(self._select_resolved)
        table_selection_layout.addWidget(self._select_button)

        self._deselect_button = QPushButton()
        self._deselect_button.setFixedWidth(BUTTON_WIDTH)
        self._deselect_button.setEnabled(False)
        self._deselect_button.clicked.connect(self._deselect_resolved)
        table_selection_layout.addWidget(self._deselect_button)

        self._auto_select_checkbox = QCheckBox()
        self._auto_select_checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._auto_select_checkbox.toggled.connect(self._on_auto_select_toggled)
        self._auto_select_checkbox.setChecked(True)
        table_selection_layout.addWidget(self._auto_select_checkbox)

        layout.addLayout(table_selection_layout)
        layout.addStretch()

        self._apply_translations()
        register_language_refresh(self, self._apply_translations)

        # Timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

    # -- Localization ---------------------------------------------------------

    def _clear_render_caches(self) -> None:
        self._prev_stability_pct = None
        self._prev_stability_format = None
        self._prev_stability_style = None
        self._prev_stability_text = None
        self._prev_sample_text = None
        self._prev_result_text = None

    @staticmethod
    def _format_stability_html(color: str, status_text: str) -> str:
        return tr('Stability: {status}', status=f'<span style="color:{color};">{status_text}</span>')

    def _format_sample_text(self, num_ips: int, sample_count: int) -> str:
        ips_part = tr_plural('{count} IP', '{count} IPs', num_ips)
        samples_part = tr_plural('{count} sample', '{count} samples', sample_count)
        return tr('{ips_part} · {samples_part}', ips_part=ips_part, samples_part=samples_part)

    def _update_resolve_button_translations(self) -> None:
        self._resolve_button.setText(tr('Resolve'))
        self._resolve_button.setToolTip(
            tr(
                'Step 2: Starts watching for traffic spikes.\n\n'
                'After clicking this, spectate the player you want to identify using '
                'the Orbital Cannon, a CCTV camera, or by physically approaching them.\n'
                'When your game loads that player, it sends more data to/from their IP, '
                'causing a spike compared to the baseline.\n\n'
                'An IP must spike for {seconds} consecutive seconds to be confirmed.\n\n'
                'Tip: Detection works best when the target player is moving — '
                'a moving player generates significantly more traffic than a stationary one.',
                seconds=self._spike_sustained_seconds,
            ),
        )

    def _apply_translations(self) -> None:
        """Apply translated text to controls, tooltips, and the active phase view."""
        self._clear_render_caches()

        self._stability_label.setToolTip(
            tr(
                'Shows whether the traffic measurements have settled down.\n\n'
                'GREEN = Traffic is steady. You can stop the baseline.\n'
                'YELLOW = Traffic is still changing. Keep waiting.\n'
                'ORANGE = Collecting initial data. Not enough samples yet.\n'
                'RED = Traffic is very erratic. Stay still and wait.',
            ),
        )
        self._stability_bar.setToolTip(
            tr(
                'Progress toward a stable baseline.\n\n'
                'During baseline: fills up as traffic patterns stabilize. '
                'When it reaches 100% and turns green, the data is reliable.\n\n'
                'During resolve: fills up as a candidate IP sustains a traffic spike. '
                'Reaches 100% when a match is confirmed.',
            ),
        )
        self._sample_label.setToolTip(
            tr(
                'Number of IPs being tracked and how many 1-second snapshots have been recorded.\nMore samples = more accurate baseline.',
            ),
        )
        self._update_baseline_button_state()
        self._update_resolve_button_translations()
        self._reset_button.setText(tr('Reset Scan'))
        self._reset_button.setToolTip(
            tr('Clears all candidate streaks and identified players from the current scan, preserving the baseline so you can immediately resolve another player.'),
        )
        self._select_button.setText(tr('Select in Table'))
        self._select_button.setToolTip(tr('Select and scroll to all identified players in the connected players table.'))
        self._deselect_button.setText(tr('Deselect in Table'))
        self._deselect_button.setToolTip(tr('Deselect all identified players in the connected players table.'))
        self._auto_select_checkbox.setText(tr('Auto-select in Table'))
        self._auto_select_checkbox.setToolTip(
            tr('Keep identified players selected in the connected players table automatically.\n\nLive updates occur with every scan. Turn off for manual selection control.'),
        )

        if self._phase == Phase.IDLE:
            if self._abort_state is not None:
                self._render_abort_state()
                if self._sample_count > 0:
                    self._update_sample_label(self._format_sample_text(len(self._baselines), self._sample_count))
            else:
                self._set_idle_instructions()
                self._stability_label.setText(tr('Stability: —'))
                self._stability_bar.setFormat(tr('Waiting...'))
        elif self._phase == Phase.BASELINE:
            self._set_baseline_instructions()
            if self._baseline_stability_snapshot is not None:
                self._render_baseline_stability()
                self._update_sample_label(self._format_sample_text(len(self._baselines), self._sample_count))
            else:
                self._stability_bar.setFormat(tr('Collecting…'))
                self._stability_label.setText(tr('Stability: —'))
        elif self._phase == Phase.READY:
            self._set_ready_instructions()
            self._update_stability(100, PROGRESS_BAR_CHUNK_GREEN_STYLESHEET, self._format_stability_html('green', tr('Locked')), bar_format=tr('Locked'))
            self._update_sample_label(self._format_sample_text(len(self._baselines), self._sample_count))
        else:
            self._set_resolving_instructions()
            self._update_sample_label(self._format_sample_text(len(self._baselines), self._sample_count))
            players = [player for player in PlayersRegistry.get_connected_players() if not player.is_third_party_server]
            self._update_resolving_display(players, self._last_max_streak)

    # -- Phase transitions ----------------------------------------------------

    def _update_baseline_button_state(self) -> None:
        if self._phase == Phase.IDLE:
            self._baseline_button.setText(tr('Start Baseline'))
            self._baseline_button.setToolTip(
                tr(
                    'Step 1: Records the normal traffic (PPS/BPS) for every IP currently in the session.\n\n'
                    'IMPORTANT: Make sure you are ALONE and standing still (e.g. inside a bunker, '
                    'facility, or away from all other players) before clicking this.\n\n'
                    'Only IPs connected RIGHT NOW will be tracked. Anyone who joins later is ignored.\n\n'
                    'The baseline runs until traffic is stable or {seconds}s have elapsed, then automatically locks in.',
                    seconds=self._baseline_max_seconds,
                ),
            )
            self._baseline_button.setEnabled(True)
        elif self._phase == Phase.BASELINE:
            self._baseline_button.setText(tr('Cancel Baseline'))
            self._baseline_button.setToolTip(tr('Cancel recording the baseline and return to the idle state.'))
            self._baseline_button.setEnabled(True)
        else:
            self._baseline_button.setText(tr('Reset Baseline'))
            self._baseline_button.setToolTip(tr('Discard the recorded baseline data and start over from scratch.'))
            self._baseline_button.setEnabled(True)

    def _on_baseline_button_clicked(self) -> None:
        if self._phase == Phase.IDLE:
            self._on_start_baseline()
        else:
            self.reset()

    def _set_idle_instructions(self) -> None:
        self._instructions.setText(
            tr(
                '<b>How to use the Player Identifier:</b><br><br>'
                '<b>1.</b> Go somewhere alone in-game where no other player is near you '
                '(e.g. a bunker, facility, or empty area).<br>'
                '<b>2.</b> Click <b>Start Baseline</b> to record the normal traffic for every IP in the session. '
                "Stand still and don't interact with anyone.<br>"
                '<b>3.</b> The baseline auto-locks once traffic is stable '
                '(or after {seconds}s).<br>'
                '<b>4.</b> Click <b>Resolve</b>, then spectate the player you want to identify '
                '(e.g. Orbital Cannon, CCTV camera, or physically approaching them).<br>'
                "The tool detects which IP's traffic increases when your game loads that player.<br><br>"
                '<small>Only IPs present when you start the baseline are tracked. '
                'Anyone who joins later is completely ignored.<br>'
                'Tip: Detection works best when the target player is <b>moving</b> — '
                'a moving player generates significantly more traffic than a stationary one.</small>',
                seconds=self._baseline_max_seconds,
            ),
        )

    def _set_baseline_instructions(self) -> None:
        num_ips = len(self._baseline_ips)
        self._instructions.setText(
            tr_plural(
                'Recording baseline for <b>{count}</b> IP…<br><br>'
                'Stay still while the baseline records. It will auto-lock once traffic is stable '
                '(or after {seconds}s).<br>'
                'Do <b>NOT</b> move or interact with anyone while recording.',
                'Recording baseline for <b>{count}</b> IPs…<br><br>'
                'Stay still while the baseline records. It will auto-lock once traffic is stable '
                '(or after {seconds}s).<br>'
                'Do <b>NOT</b> move or interact with anyone while recording.',
                num_ips,
                seconds=self._baseline_max_seconds,
            ),
        )

    def _set_resolving_instructions(self) -> None:
        self._instructions.setText(
            tr(
                'Spectate the player you want to identify (Orbital Cannon, CCTV, or walk up to them).<br><br>'
                'The tool is comparing live traffic against the baseline.<br>'
                "If any IP's traffic spikes for <b>{seconds}</b> consecutive seconds, "
                'it will be flagged as a match.<br>'
                '<small>Tip: Detection works best when the target player is <b>moving</b>.</small>',
                seconds=self._spike_sustained_seconds,
            ),
        )

    def _on_start_baseline(self) -> None:
        players = [player for player in PlayersRegistry.get_connected_players() if not player.is_third_party_server]
        if len(players) < MIN_CONNECTED_PLAYERS:
            QMessageBox.warning(
                self,
                tr('Not Enough Players'),
                tr(
                    'There must be at least {min_players} connected players to use the Player Identifier.\n\nWith only 0 or 1 players, there is nothing to resolve.',
                    min_players=MIN_CONNECTED_PLAYERS,
                ),
            )
            return

        self._phase = Phase.BASELINE
        self._abort_state = None
        self._ready_reason_kind = None
        self._baseline_stability_snapshot = None
        self._last_max_streak = 0
        self._baselines.clear()
        self._sample_count = 0
        self._spike_streak.clear()
        self._total_spike_duration.clear()
        self._contamination_streak.clear()
        self._identified_ips.clear()
        PlayerIdentifierTracker.set_identified_ips(set())
        self._clear_render_caches()
        self._result_label.setText('')
        self._update_baseline_button_state()
        self._resolve_button.setEnabled(False)
        self._reset_button.setEnabled(False)

        self._baseline_ips = {player.ip for player in players}
        for ip in self._baseline_ips:
            self._baselines[ip] = IPBaseline()

        self._set_baseline_instructions()
        collecting_text = tr('Collecting…')
        self._stability_bar.setFormat(collecting_text)
        self._stability_bar.setValue(0)
        self._stability_bar.setStyleSheet(PROGRESS_BAR_IDLE_STYLESHEET)
        self._prev_stability_pct = 0
        self._prev_stability_format = collecting_text
        self._prev_stability_style = PROGRESS_BAR_IDLE_STYLESHEET
        self._prev_stability_text = None
        self._stability_label.setText(tr('Stability: —'))
        self._stability_label.setVisible(True)
        self._stability_bar.setVisible(True)
        self._sample_label.setVisible(True)
        self._sample_label.setText('')
        self._timer.start(UPDATE_INTERVAL_MS)

    def _set_ready_instructions(self) -> None:
        """Update the instructions panel for the locked-baseline READY phase."""
        reason_text: str | None = None
        if self._ready_reason_kind is not None:
            reason_type, timeout_seconds = self._ready_reason_kind
            reason_text = tr('converged') if reason_type == 'converged' else tr('{seconds}s timeout', seconds=timeout_seconds)
        num_ips = len(self._baselines)
        reason_suffix = f' ({reason_text})' if reason_text is not None else ''
        ips_part = tr_plural('<b>{count}</b> IP', '<b>{count}</b> IPs', num_ips)
        samples_part = tr_plural('<b>{count}</b> sample', '<b>{count}</b> samples', self._sample_count)
        header = tr(
            'Baseline locked{reason_suffix} with {ips_part} over {samples_part}.',
            reason_suffix=reason_suffix,
            ips_part=ips_part,
            samples_part=samples_part,
        )
        body = tr(
            'Click <b>Resolve</b>, then spectate the target player (Orbital Cannon, CCTV, or walk up to them).<br>'
            "The tool will detect which IP's traffic spikes when your game loads that player.<br>"
            '<small>Tip: Detection works best when the target player is <b>moving</b>.</small>',
        )
        self._instructions.setText(f'{header}<br><br>{body}')

    def _auto_stop_baseline(self, reason_type: str, timeout_seconds: int = 0) -> None:
        """Finalize baselines and transition to READY (timer keeps running for contamination monitoring)."""
        for bl in self._baselines.values():
            bl.finalize()
        self._phase = Phase.READY
        self._ready_reason_kind = (reason_type, timeout_seconds)
        self._update_baseline_button_state()
        self._resolve_button.setEnabled(True)
        self._reset_button.setEnabled(False)
        self._set_ready_instructions()
        locked_text = tr('Locked')
        self._stability_bar.setFormat(locked_text)
        self._stability_bar.setValue(100)
        self._stability_bar.setStyleSheet(PROGRESS_BAR_CHUNK_GREEN_STYLESHEET)
        self._stability_label.setText(themed_qss(self._format_stability_html('green', locked_text)))
        self._contamination_streak.clear()

    def _on_resolve(self) -> None:
        self._phase = Phase.RESOLVING
        self._abort_state = None
        self._last_max_streak = 0
        self._spike_streak.clear()
        self._total_spike_duration.clear()
        self._identified_ips.clear()
        PlayerIdentifierTracker.set_identified_ips(set())
        self._resolve_button.setEnabled(False)
        self._reset_button.setEnabled(True)
        self._select_button.setEnabled(not self._auto_select)
        self._deselect_button.setEnabled(not self._auto_select)
        self._set_resolving_instructions()
        self._result_label.setText('')
        self._stability_bar.setFormat(tr('Resolving…'))
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
        self._last_max_streak = 0
        self._ready_reason_kind = None
        PlayerIdentifierTracker.set_identified_ips(set())

        self._phase = Phase.READY
        self._update_baseline_button_state()
        self._resolve_button.setEnabled(True)
        self._reset_button.setEnabled(False)
        self._select_button.setEnabled(False)
        self._deselect_button.setEnabled(False)

        num_ips = len(self._baselines)
        self._set_ready_instructions()
        locked_text = tr('Locked')
        self._update_stability(100, PROGRESS_BAR_CHUNK_GREEN_STYLESHEET, self._format_stability_html('green', locked_text), bar_format=locked_text)
        self._update_sample_label(self._format_sample_text(num_ips, self._sample_count))
        self._update_result_label('')
        self._contamination_streak.clear()

    def _on_auto_select_toggled(self) -> None:
        checked = self._auto_select_checkbox.isChecked()
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
        self._abort_state = None
        self._ready_reason_kind = None
        self._baseline_stability_snapshot = None
        self._last_max_streak = 0
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
        self._clear_render_caches()
        self._update_baseline_button_state()
        self._resolve_button.setEnabled(False)
        self._reset_button.setEnabled(False)
        self._select_button.setEnabled(False)
        self._deselect_button.setEnabled(False)
        self._set_idle_instructions()
        self._stability_label.setText(tr('Stability: —'))
        self._stability_label.setVisible(False)
        self._stability_bar.setValue(0)
        self._stability_bar.setFormat(tr('Waiting...'))
        self._stability_bar.setStyleSheet(PROGRESS_BAR_IDLE_STYLESHEET)
        self._stability_bar.setVisible(False)
        self._sample_label.setText('')
        self._sample_label.setVisible(False)
        self._result_label.setText('')

    def _abort_with_message(self, *, bar_format: str, stability_reason: str, instructions_html: str) -> None:
        """Stop the active scan, reset selection/button state, and show an abort reason."""
        self._timer.stop()
        self._phase = Phase.IDLE
        if self._currently_selected_ips and self._deselect_ips is not None:
            self._deselect_ips(list(self._currently_selected_ips))
        self._currently_selected_ips.clear()
        self._identified_ips.clear()
        PlayerIdentifierTracker.set_identified_ips(set())
        self._update_baseline_button_state()
        self._resolve_button.setEnabled(False)
        self._reset_button.setEnabled(True)
        self._select_button.setEnabled(False)
        self._deselect_button.setEnabled(False)
        self._apply_abort_widgets(bar_format=bar_format, stability_reason=stability_reason, instructions_html=instructions_html)

    def _apply_abort_widgets(self, *, bar_format: str, stability_reason: str, instructions_html: str) -> None:
        self._stability_bar.setValue(0)
        self._stability_bar.setFormat(bar_format)
        self._stability_bar.setStyleSheet(PROGRESS_BAR_CHUNK_RED_STYLESHEET)
        self._stability_label.setText(themed_qss(self._format_stability_html('red', stability_reason)))
        self._instructions.setText(themed_qss(instructions_html))

    def _abort_insufficient_players(self) -> None:
        """Stop the current phase because too many players disconnected."""
        self._abort_state = ('insufficient', None)
        self._abort_with_message(**self._build_abort_insufficient_payload())

    def _abort_contaminated(self, ip: str, zscore: float) -> None:
        """Stop the baseline because a dramatic traffic spike was detected (contamination)."""
        self._abort_state = ('contaminated', (ip, zscore))
        self._abort_with_message(**self._build_abort_contaminated_payload(ip, zscore))

    def _abort_session_changed(self) -> None:
        """Stop the current phase because overall session traffic drifted too far from the baseline."""
        self._abort_state = ('session_changed', None)
        self._abort_with_message(**self._build_abort_session_changed_payload())

    @staticmethod
    def _build_abort_insufficient_payload() -> dict[str, str]:
        return {
            'bar_format': tr('Aborted'),
            'stability_reason': tr('Aborted — not enough players remaining'),
            'instructions_html': tr(
                '<b style="color:#e74c3c;">Aborted:</b> fewer than {min_players} tracked players remain in the session.<br><br>'
                'Players disconnected while the scan was running. Click <b>Start Baseline</b> to try again…',
                min_players=MIN_CONNECTED_PLAYERS,
            ),
        }

    @staticmethod
    def _build_abort_contaminated_payload(ip: str, zscore: float) -> dict[str, str]:
        return {
            'bar_format': tr('Contaminated'),
            'stability_reason': tr('Aborted — baseline contaminated'),
            'instructions_html': tr(
                '<b style="color:#e74c3c;">Baseline contaminated!</b> IP <b>{ip}</b> showed a dramatic traffic spike '
                '(z-score: {zscore:.1f}) while recording.<br><br>'
                'This usually means you moved, spectated someone, or a player approached you. '
                'The baseline data is no longer reliable.<br><br>'
                'Click <b>Start Baseline</b> to start over. Make sure you stay completely still and isolated.',
                ip=ip,
                zscore=zscore,
            ),
        }

    @staticmethod
    def _build_abort_session_changed_payload() -> dict[str, str]:
        return {
            'bar_format': tr('Aborted'),
            'stability_reason': tr('Aborted — session conditions changed'),
            'instructions_html': tr(
                '<b style="color:#e74c3c;">Baseline invalidated:</b> overall session traffic shifted too dramatically '
                'from the recorded baseline.<br><br>'
                'The session may have ended, or a mass game event caused all traffic to spike or drop simultaneously. '
                'The baseline data is no longer reliable.<br><br>'
                'Click <b>Start Baseline</b> to start over.',
            ),
        }

    def _render_abort_state(self) -> None:
        if self._abort_state is None:
            return
        abort_kind, context = self._abort_state
        if abort_kind == 'insufficient':
            self._apply_abort_widgets(**self._build_abort_insufficient_payload())
        elif abort_kind == 'contaminated' and context is not None:
            ip, zscore = context
            self._apply_abort_widgets(**self._build_abort_contaminated_payload(ip, zscore))
        else:
            self._apply_abort_widgets(**self._build_abort_session_changed_payload())

    # -- Periodic tick --------------------------------------------------------

    def _tick(self) -> None:
        players = [player for player in PlayersRegistry.get_connected_players() if not player.is_third_party_server]
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

        status_spec: tuple[str, str, int | None]
        if avg_shift is None:
            remaining = CONVERGENCE_RECENT_WINDOW - self._sample_count
            pct = int(self._sample_count / CONVERGENCE_RECENT_WINDOW * 50)
            style = PROGRESS_BAR_CHUNK_ORANGE_STYLESHEET
            status_spec = ('orange', 'collecting', remaining)
        elif self._sample_count < self._baseline_min_samples:
            remaining = self._baseline_min_samples - self._sample_count
            shift_ok = avg_shift <= effective_green
            pct = int(self._sample_count / self._baseline_min_samples * 60)
            if shift_ok:
                style = PROGRESS_BAR_CHUNK_ORANGE_STYLESHEET
                status_spec = ('orange', 'looks_stable', remaining)
            else:
                style = PROGRESS_BAR_CHUNK_RED_STYLESHEET
                status_spec = ('red', 'unstable', None)
        elif converged:
            pct = 100
            style = PROGRESS_BAR_CHUNK_GREEN_STYLESHEET
            status_spec = ('green', 'stable', None)
        elif avg_shift <= effective_yellow:
            ratio = (effective_yellow - avg_shift) / (effective_yellow - effective_green)
            pct = int(60 + ratio * 39)
            style = PROGRESS_BAR_CHUNK_ORANGE_STYLESHEET
            status_spec = ('yellow', 'almost_stable', None)
        else:
            pct = max(int((1.0 - min(avg_shift, 1.0)) * 60), 5)
            style = PROGRESS_BAR_CHUNK_RED_STYLESHEET
            status_spec = ('red', 'unstable', None)

        self._baseline_stability_snapshot = (pct, style, f'{pct}%', status_spec)
        self._render_baseline_stability()
        num_ips = len(self._baselines)
        self._update_sample_label(self._format_sample_text(num_ips, self._sample_count))

        if converged:
            self._auto_stop_baseline('converged')
        elif self._sample_count >= self._baseline_max_seconds:
            self._auto_stop_baseline('timeout', self._baseline_max_seconds)

    def _render_baseline_stability(self) -> None:
        if self._baseline_stability_snapshot is None:
            return
        pct, style, _bar_fmt, (color, status_key, remaining) = self._baseline_stability_snapshot
        if status_key == 'collecting':
            status_text = tr('Collecting data ({seconds}s left)', seconds=remaining or 0)
        elif status_key == 'looks_stable':
            status_text = tr('Looks stable, need {seconds}s more data', seconds=remaining or 0)
        elif status_key == 'stable':
            status_text = tr('Stable — Ready to stop')
        elif status_key == 'almost_stable':
            status_text = tr('Almost stable… keep waiting')
        else:
            status_text = tr('Unstable — stay still')
        self._update_stability(pct, style, self._format_stability_html(color, status_text))

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

        self._last_max_streak = max_streak
        self._update_resolving_display(players, max_streak)

    def _format_spiking_player_bullet(self, player: Player, *, confirmed: bool) -> str:
        """Format a bullet-list HTML row for a confirmed or candidate spiking player."""
        name_part = f' ({html.escape(", ".join(player.usernames))})' if player.usernames else ''
        formatted_bps = PlayerBandwidth.format_bytes(player.bandwidth.bps.calculated_rate)
        streak = self._spike_streak.get(player.ip, 0)
        total_duration = self._total_spike_duration.get(player.ip, 0)
        if confirmed:
            streak_text = tr('streak: {streak}s (total: {total}s)', streak=streak, total=total_duration) if streak > 0 else tr('total spike: {total}s', total=total_duration)
        else:
            streak_text = tr(
                'streak: {streak}/{required}s (total: {total}s)',
                streak=streak,
                required=self._spike_sustained_seconds,
                total=total_duration,
            )
        return f'• <b>{player.ip}</b>{name_part} — {player.packets.pps.calculated_rate} PPS · {formatted_bps} · {streak_text}'

    def _update_resolving_display(self, players: list[Player], max_streak: int) -> None:
        player_by_ip = {player.ip: player for player in players}
        identified_players = [player_by_ip[ip] for ip in self._identified_ips if ip in player_by_ip]
        candidate_players = [player_by_ip[ip] for ip in self._spike_streak if ip in player_by_ip and ip not in self._identified_ips]

        if not identified_players and not candidate_players:
            num_ips = len(self._baselines)
            watching_text = tr_plural(
                'Watching {count} baselined IP for traffic spikes.',
                'Watching {count} baselined IPs for traffic spikes.',
                num_ips,
            )
            self._update_result_label(
                f"<b>{tr('No spiking players detected.')}</b><br><small>{watching_text}</small>",
            )
            self._update_stability(
                0,
                PROGRESS_BAR_IDLE_STYLESHEET,
                self._format_stability_html('green', tr('Locked')),
                bar_format=tr('Resolving…'),
            )
            return

        lines: list[str] = []
        if identified_players:
            num_identified = len(identified_players)
            identified_header = tr_plural('{count} player identified:', '{count} players identified:', num_identified)
            lines.append(f'<b style="color:#27ae60;">{identified_header}</b>')
            lines.extend(self._format_spiking_player_bullet(player, confirmed=True) for player in identified_players)

        if candidate_players:
            num_candidates = len(candidate_players)
            candidates_header = tr_plural('{count} candidate spiking:', '{count} candidates spiking:', num_candidates)
            lines.append(f'<b style="color:#f39c12;">{candidates_header}</b>')
            lines.extend(self._format_spiking_player_bullet(player, confirmed=False) for player in candidate_players)

        if identified_players:
            lines.append(f"<small>{tr('Identified players are marked with a target icon in the connected players table.')}</small>")
        else:
            needs_text = tr_plural(
                'Needs {count} consecutive second of elevated traffic to confirm.',
                'Needs {count} consecutive seconds of elevated traffic to confirm.',
                self._spike_sustained_seconds,
            )
            lines.append(f'<small>{needs_text}</small>')

        self._update_result_label('<br>'.join(lines))

        if identified_players:
            resolved_text = tr('Resolved')
            self._update_stability(
                100,
                PROGRESS_BAR_CHUNK_GREEN_STYLESHEET,
                self._format_stability_html('green', resolved_text),
                bar_format=resolved_text,
            )
        elif candidate_players:
            pct = min(int(max_streak / self._spike_sustained_seconds * 100), 99)
            self._update_stability(
                pct,
                PROGRESS_BAR_CHUNK_ORANGE_STYLESHEET,
                self._format_stability_html('orange', tr('Spike detected')),
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
            self._stability_label.setText(themed_qss(label_text))
            self._prev_stability_text = label_text

    def _update_sample_label(self, text: str) -> None:
        """Update sample label only when text actually changes."""
        if text != self._prev_sample_text:
            self._sample_label.setText(text)
            self._prev_sample_text = text

    def _update_result_label(self, text: str) -> None:
        """Update result label only when text actually changes."""
        if text != self._prev_result_text:
            self._result_label.setText(themed_qss(text))
            self._prev_result_text = text

    @property
    def _spike_min_zscore(self) -> float:
        return Settings.player_identifier_spike_zscore

    @property
    def _spike_sustained_seconds(self) -> int:
        return Settings.player_identifier_spike_seconds

    @property
    def _contamination_zscore(self) -> float:
        return Settings.player_identifier_contamination_zscore

    @property
    def _contamination_seconds(self) -> int:
        return Settings.player_identifier_contamination_seconds

    @property
    def _contamination_min_samples(self) -> int:
        return Settings.player_identifier_contamination_min_samples

    @property
    def _baseline_min_samples(self) -> int:
        return Settings.player_identifier_baseline_seconds

    @property
    def _baseline_max_seconds(self) -> int:
        return Settings.player_identifier_baseline_timeout

    @property
    def _session_drift_threshold(self) -> float:
        return Settings.player_identifier_session_drift_zscore

    def apply_settings(self) -> None:
        """Apply updated detection parameters from `Settings`."""
        self._update_baseline_button_state()
        self._update_resolve_button_translations()
