"""Dedicated dialog for inspecting Session Host detection diagnostics."""

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLayout,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.stylesheets import (
    COMPACT_BUTTON_STYLESHEET,
    DIALOG_BUTTON_STYLESHEET,
    HOST_BADGE_DANGER_STYLESHEET,
    HOST_BADGE_INFO_STYLESHEET,
    HOST_BADGE_MUTED_STYLESHEET,
    HOST_BADGE_SUCCESS_STYLESHEET,
    HOST_BADGE_WARNING_STYLESHEET,
    HOST_DIAGNOSTICS_CANDIDATE_CARD_STYLESHEET,
    HOST_DIAGNOSTICS_CANDIDATE_HOST_STYLESHEET,
    HOST_DIAGNOSTICS_CHECKLIST_ROW_STYLESHEET,
    HOST_DIAGNOSTICS_HERO_FAILURE_STYLESHEET,
    HOST_DIAGNOSTICS_HERO_SUCCESS_STYLESHEET,
    HOST_DIAGNOSTICS_SECTION_CARD_STYLESHEET,
    HOST_DIAGNOSTICS_STAT_BOX_STYLESHEET,
)
from session_sniffer.guis.utils import (
    ActiveDialogRegistry,
    animate_button_feedback,
    load_country_flag_icon,
    scale_by_ui,
    set_clipboard_text,
    set_dialog_window_flags,
)
from session_sniffer.text_utils import format_elapsed_time, pluralize

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.player.registry import HostCandidateDiagnostic, HostDiagnosticsSnapshot

_SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS: float = 50.0
_SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS: float = 1600.0
_MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST: int = 9
_SESSION_HOST_MAX_PACKETS_FOR_DETECTION: int = 1000


@dataclass(slots=True)
class _DetectionChecklistItem:
    """Internal model for a single evaluation checklist row."""

    title: str
    passed: bool
    detail: str


class SessionHostDiagnosticsDialog(QDialog):
    """A polished, structured dialog presenting session host detection results."""

    def __init__(
        self,
        parent: QWidget | None,
        snapshot: HostDiagnosticsSnapshot,
        *,
        redetect_callback: Callable[[], HostDiagnosticsSnapshot | None] | None = None,
    ) -> None:
        """Initialize the Session Host Diagnostics dialog."""
        super().__init__(parent)
        self._snapshot = snapshot
        self._redetect_callback = redetect_callback

        self.setWindowTitle(f'{TITLE} - Session Host Diagnostics')
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        set_dialog_window_flags(self)

        self.setMinimumWidth(scale_by_ui(660))
        self.setMinimumHeight(scale_by_ui(520))
        self.resize(scale_by_ui(720), scale_by_ui(620))

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(12, 12, 12, 12)
        root_layout.setSpacing(10)

        # Scroll area for clean viewing at any resolution
        self._scroll_area = QScrollArea(self)
        self._scroll_area.setWidgetResizable(True)
        self._scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self._content_widget = QWidget()
        self._content_layout = QVBoxLayout(self._content_widget)
        self._content_layout.setContentsMargins(4, 4, 8, 4)
        self._content_layout.setSpacing(12)

        self._scroll_area.setWidget(self._content_widget)
        root_layout.addWidget(self._scroll_area, stretch=1)

        # Footer action bar
        footer_widget = self._build_footer()
        root_layout.addWidget(footer_widget)

        self._rebuild_content()

    def update_snapshot(self, snapshot: HostDiagnosticsSnapshot) -> None:
        """Update the displayed snapshot and refresh the dialog contents."""
        self._snapshot = snapshot
        self._rebuild_content()

    def _clear_layout(self, layout: QLayout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            if item is None:
                continue
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
            sub_layout = item.layout()
            if sub_layout is not None:
                self._clear_layout(sub_layout)

    def _rebuild_content(self) -> None:
        self._clear_layout(self._content_layout)

        # 1. Hero banner
        hero_widget = self._build_hero_section()
        self._content_layout.addWidget(hero_widget)

        # 2. Key stats row
        stats_widget = self._build_stats_section()
        self._content_layout.addWidget(stats_widget)

        # 3. Detection criteria checklist
        checklist_widget = self._build_checklist_section()
        self._content_layout.addWidget(checklist_widget)

        # 4. Timing analysis
        timing_widget = self._build_timing_section()
        self._content_layout.addWidget(timing_widget)

        # 5. Candidates section
        candidates_widget = self._build_candidates_section()
        self._content_layout.addWidget(candidates_widget)

        # 5. Filtered servers section (if any)
        if self._snapshot.filtered_servers:
            servers_widget = self._build_servers_section()
            self._content_layout.addWidget(servers_widget)

        self._content_layout.addStretch(1)

    def _build_hero_section(self) -> QWidget:
        hero_frame = QFrame()
        is_success = self._snapshot.success and bool(self._snapshot.detected_host_ip)

        hero_frame.setObjectName('hostHeroSuccess' if is_success else 'hostHeroFailure')
        hero_frame.setStyleSheet(HOST_DIAGNOSTICS_HERO_SUCCESS_STYLESHEET if is_success else HOST_DIAGNOSTICS_HERO_FAILURE_STYLESHEET)

        layout = QHBoxLayout(hero_frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(14)

        icon_label = QLabel()
        icon_size = scale_by_ui(32)
        icon_filename = 'crown.svg' if is_success else 'warning.svg'
        icon_path = RESOURCES_DIR_PATH / 'icons' / icon_filename
        if icon_path.exists():
            icon_label.setPixmap(QIcon(str(icon_path)).pixmap(icon_size, icon_size))
        icon_label.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.addWidget(icon_label)

        info_layout = QVBoxLayout()
        info_layout.setSpacing(4)

        title_label = QLabel('Session Host Detected' if is_success else 'Host Not Detected')
        title_font = QFont()
        title_font.setPointSize(11)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet('color: #10b981;' if is_success else 'color: #fbbf24;')
        info_layout.addWidget(title_label)

        if is_success and self._snapshot.detected_host_ip:
            host_row = QHBoxLayout()
            host_row.setSpacing(8)

            if self._snapshot.detected_host_country_code:
                flag_icon = load_country_flag_icon(self._snapshot.detected_host_country_code)
                if flag_icon is not None:
                    flag_label = QLabel()
                    flag_label.setPixmap(flag_icon.pixmap(scale_by_ui(18), scale_by_ui(13)))
                    host_row.addWidget(flag_label)

            ip_label = QLabel(self._snapshot.detected_host_ip)
            ip_font = QFont()
            ip_font.setPointSize(13)
            ip_font.setBold(True)
            ip_label.setFont(ip_font)
            ip_label.setStyleSheet('color: #ffffff;')
            ip_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            host_row.addWidget(ip_label)

            if self._snapshot.detected_host_usernames:
                usernames_text = ', '.join(self._snapshot.detected_host_usernames)
                user_label = QLabel(f'(@{usernames_text})')
                user_label.setStyleSheet('color: #94a3b8; font-size: 9.5pt;')
                host_row.addWidget(user_label)

            host_row.addStretch(1)
            info_layout.addLayout(host_row)
        else:
            reason = self._snapshot.rejection_reason or self._snapshot.outcome
            reason_label = QLabel(reason)
            reason_label.setWordWrap(True)
            reason_label.setStyleSheet('color: #e2e8f0; font-size: 9pt;')
            reason_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            info_layout.addWidget(reason_label)

        time_str = self._snapshot.timestamp.strftime('%H:%M:%S')
        timestamp_label = QLabel(f'Evaluation performed at {time_str}')
        timestamp_label.setStyleSheet('color: #64748b; font-size: 8pt;')
        info_layout.addWidget(timestamp_label)

        layout.addLayout(info_layout, stretch=1)

        if is_success and self._snapshot.detected_host_ip:
            actions_container = QWidget()
            actions_layout = QVBoxLayout(actions_container)
            actions_layout.setContentsMargins(0, 0, 0, 0)
            actions_layout.setSpacing(6)

            copy_host_ip_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), ' Copy Host IP')
            copy_host_ip_button.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
            detected_ip = self._snapshot.detected_host_ip
            copy_host_ip_button.clicked.connect(lambda: self._copy_text(copy_host_ip_button, detected_ip))
            actions_layout.addWidget(copy_host_ip_button)

            if self._snapshot.detected_host_usernames:
                usernames_count = len(self._snapshot.detected_host_usernames)
                copy_host_usernames_button = QPushButton(
                    QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')),
                    f' Copy Host Username{pluralize(usernames_count)}',
                )
                copy_host_usernames_button.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
                detected_usernames = ', '.join(self._snapshot.detected_host_usernames)
                copy_host_usernames_button.clicked.connect(
                    lambda: self._copy_text(copy_host_usernames_button, detected_usernames)
                )
                actions_layout.addWidget(copy_host_usernames_button)

            layout.addWidget(actions_container, alignment=Qt.AlignmentFlag.AlignVCenter)

        return hero_frame

    def _build_stats_section(self) -> QWidget:
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        stats = [
            ('Total Evaluated', str(self._snapshot.total_evaluated_players), '#38bdf8'),
            ('Direct P2P Players', str(self._snapshot.direct_p2p_players), '#34d399'),
            ('Filtered Server IPs', str(self._snapshot.filtered_server_ips), '#94a3b8'),
        ]

        for label_text, value_text, accent_color in stats:
            box = QFrame()
            box.setObjectName('hostStatBox')
            box.setStyleSheet(HOST_DIAGNOSTICS_STAT_BOX_STYLESHEET)
            box_layout = QVBoxLayout(box)
            box_layout.setContentsMargins(10, 8, 10, 8)
            box_layout.setSpacing(2)

            title_lbl = QLabel(label_text)
            title_lbl.setStyleSheet('color: #8b9bb4; font-size: 8pt; font-weight: bold; text-transform: uppercase;')
            box_layout.addWidget(title_lbl)

            val_lbl = QLabel(value_text)
            val_font = QFont()
            val_font.setPointSize(14)
            val_font.setBold(True)
            val_lbl.setFont(val_font)
            val_lbl.setStyleSheet(f'color: {accent_color};')
            box_layout.addWidget(val_lbl)

            layout.addWidget(box)

        return container

    def _build_checklist_section(self) -> QWidget:
        card = QFrame()
        card.setObjectName('hostSectionCard')
        card.setStyleSheet(HOST_DIAGNOSTICS_SECTION_CARD_STYLESHEET)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)

        # Header
        header_layout = QHBoxLayout()
        header_layout.setSpacing(8)

        icon_label = QLabel()
        icon_path = RESOURCES_DIR_PATH / 'icons' / 'check.svg'
        if icon_path.exists():
            icon_label.setPixmap(QIcon(str(icon_path)).pixmap(scale_by_ui(16), scale_by_ui(16)))
        header_layout.addWidget(icon_label)

        title = QLabel('Detection Criteria Checklist')
        title.setStyleSheet('color: #f1f5f9; font-weight: bold; font-size: 9.5pt;')
        header_layout.addWidget(title)

        header_layout.addStretch(1)

        items = self._compute_checklist_items()
        passed_count = sum(1 for item in items if item.passed)
        total_count = len(items)

        summary_badge = QLabel(f'{passed_count}/{total_count} Passed')
        if passed_count == total_count:
            summary_badge.setStyleSheet(HOST_BADGE_SUCCESS_STYLESHEET)
        elif passed_count > 0:
            summary_badge.setStyleSheet(HOST_BADGE_WARNING_STYLESHEET)
        else:
            summary_badge.setStyleSheet(HOST_BADGE_DANGER_STYLESHEET)
        header_layout.addWidget(summary_badge)

        layout.addLayout(header_layout)

        # Rows
        for item in items:
            row = QFrame()
            row.setObjectName('hostChecklistRow')
            row.setStyleSheet(HOST_DIAGNOSTICS_CHECKLIST_ROW_STYLESHEET)

            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(8, 6, 8, 6)
            row_layout.setSpacing(10)

            status_badge = QLabel('PASS' if item.passed else 'FAIL')
            status_badge.setStyleSheet(HOST_BADGE_SUCCESS_STYLESHEET if item.passed else HOST_BADGE_DANGER_STYLESHEET)
            status_badge.setFixedWidth(scale_by_ui(44))
            status_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            row_layout.addWidget(status_badge)

            text_layout = QVBoxLayout()
            text_layout.setSpacing(2)

            title_label = QLabel(item.title)
            title_font = QFont()
            title_font.setBold(True)
            title_font.setPointSize(9)
            title_label.setFont(title_font)
            title_label.setStyleSheet('color: #e2e8f0;' if item.passed else 'color: #fca5a5;')
            text_layout.addWidget(title_label)

            detail_label = QLabel(item.detail)
            detail_label.setStyleSheet('color: #94a3b8; font-size: 8.5pt;')
            detail_label.setWordWrap(True)
            text_layout.addWidget(detail_label)

            row_layout.addLayout(text_layout, stretch=1)
            layout.addWidget(row)

        return card

    def _compute_checklist_items(self) -> list[_DetectionChecklistItem]:
        """Compute the evaluation status and explanation for each detection criterion."""
        items: list[_DetectionChecklistItem] = []

        # 1. Direct P2P Candidates
        p2p_count = self._snapshot.direct_p2p_players
        evaluated_count = self._snapshot.total_evaluated_players
        filtered_count = self._snapshot.filtered_server_ips

        if not evaluated_count:
            candidates_detail = 'No players found in session'
        elif not p2p_count:
            candidates_detail = f'All {evaluated_count} connected endpoint{pluralize(evaluated_count)} are game or relay servers'
        elif filtered_count > 0:
            candidates_detail = f'{p2p_count} direct P2P candidate{pluralize(p2p_count)} identified ({filtered_count} server{pluralize(filtered_count)} filtered)'
        else:
            candidates_detail = f'{p2p_count} direct P2P candidate{pluralize(p2p_count)} identified in session'

        items.append(
            _DetectionChecklistItem(
                title='Direct P2P Candidates',
                passed=p2p_count > 0,
                detail=candidates_detail,
            )
        )

        # 2. Candidate Activity
        if self._snapshot.success:
            activity_passed = True
            activity_detail = 'Candidate is active and connected'
        elif self._snapshot.candidates:
            active_candidates = [
                candidate
                for candidate in self._snapshot.candidates
                if not candidate.is_pending_disconnection and not candidate.is_disconnected
            ]
            activity_passed = bool(active_candidates)
            active_count = len(active_candidates)
            activity_detail = (
                f'{active_count} candidate{pluralize(active_count)} active and connected'
                if activity_passed
                else 'All candidates are disconnected or pending disconnection'
            )
        else:
            activity_passed = False
            activity_detail = 'No candidates available to evaluate activity'

        items.append(
            _DetectionChecklistItem(
                title='Candidate Activity',
                passed=activity_passed,
                detail=activity_detail,
            )
        )

        # 4. Connection Timing Window
        if self._snapshot.success:
            timing_passed = True
            if self._snapshot.timing_gap_seconds is not None:
                gap_ms = self._snapshot.timing_gap_seconds * 1000
                timing_detail = f'Join separation ({gap_ms:.1f}ms) within valid window (50ms - 1,600ms)'
            else:
                timing_detail = 'Single candidate in session (timing comparison not required)'
        elif self._snapshot.timing_gap_seconds is not None:
            gap_ms = self._snapshot.timing_gap_seconds * 1000
            if _SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS <= gap_ms <= _SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS:
                timing_passed = True
                timing_detail = f'Join separation ({gap_ms:.1f}ms) within valid window (50ms - 1,600ms)'
            elif gap_ms < _SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS:
                timing_passed = False
                timing_detail = f'Ambiguous ({gap_ms:.1f}ms < 50ms): players connected simultaneously'
            else:
                timing_passed = False
                gap_text = f'{self._snapshot.timing_gap_seconds:.3f}s' if self._snapshot.timing_gap_seconds >= 1.0 else f'{gap_ms:.1f}ms'
                timing_detail = f'Gap too large ({gap_text} > 1,600ms): candidates did not join together'
        elif len(self._snapshot.candidates) == 1:
            timing_passed = True
            timing_detail = 'Single candidate in session (timing comparison not required)'
        else:
            timing_passed = False
            timing_detail = 'No candidates available for timing comparison'

        items.append(
            _DetectionChecklistItem(
                title='Connection Timing Window',
                passed=timing_passed,
                detail=timing_detail,
            )
        )

        # 5. Packet Threshold Criteria
        if self._snapshot.success:
            packet_passed = True
            host_candidate = next(
                (candidate for candidate in self._snapshot.candidates if candidate.is_host),
                self._snapshot.candidates[0] if self._snapshot.candidates else None,
            )
            if host_candidate is not None:
                packet_detail = (
                    f'Candidate sent >= 9 packets ({host_candidate.packets_sent}) '
                    f'and exchanged <= 1,000 ({host_candidate.packets_exchanged})'
                )
            else:
                packet_detail = 'Candidate packet counts within valid bounds (>= 9 sent, <= 1,000 exchanged)'
        elif self._snapshot.candidates:
            has_under_sent = any(
                candidate.packet_status == 'Not enough sent' or candidate.packets_sent < _MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST
                for candidate in self._snapshot.candidates
            )
            has_over_exchanged = any(
                candidate.packet_status == 'Exceeds maximum exchanged' or candidate.packets_exchanged > _SESSION_HOST_MAX_PACKETS_FOR_DETECTION
                for candidate in self._snapshot.candidates
            )
            if has_under_sent:
                packet_passed = False
                packet_detail = f'Candidate has not sent enough packets (>= {_MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST} required to rule out transient probes)'
            elif has_over_exchanged:
                packet_passed = False
                packet_detail = f'Candidate exchanged > {_SESSION_HOST_MAX_PACKETS_FOR_DETECTION:,} packets (session already in progress)'
            else:
                packet_passed = True
                packet_detail = (
                    f'Candidate packet counts within valid bounds (>= {_MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST} sent, '
                    f'<= {_SESSION_HOST_MAX_PACKETS_FOR_DETECTION:,} exchanged)'
                )
        else:
            packet_passed = False
            packet_detail = 'No candidates to evaluate packet thresholds'

        items.append(
            _DetectionChecklistItem(
                title='Packet Threshold Criteria',
                passed=packet_passed,
                detail=packet_detail,
            )
        )

        return items

    def _build_timing_section(self) -> QWidget:
        card = QFrame()
        card.setObjectName('hostSectionCard')
        card.setStyleSheet(HOST_DIAGNOSTICS_SECTION_CARD_STYLESHEET)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(8)

        # Header
        header_layout = QHBoxLayout()
        header_layout.setSpacing(8)

        icon_label = QLabel()
        icon_path = RESOURCES_DIR_PATH / 'icons' / 'timer.svg'
        if icon_path.exists():
            icon_label.setPixmap(QIcon(str(icon_path)).pixmap(scale_by_ui(16), scale_by_ui(16)))
        header_layout.addWidget(icon_label)

        title = QLabel('Timing Analysis')
        title.setStyleSheet('color: #f1f5f9; font-weight: bold; font-size: 9.5pt;')
        header_layout.addWidget(title)

        header_layout.addStretch(1)

        # Timing status pill badge
        badge = QLabel()
        if self._snapshot.timing_gap_seconds is not None:
            gap_ms = self._snapshot.timing_gap_seconds * 1000
            if _SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS <= gap_ms <= _SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS:
                badge.setText(f'✓ Within Window ({gap_ms:.1f}ms)')
                badge.setStyleSheet(HOST_BADGE_SUCCESS_STYLESHEET)
            elif gap_ms < _SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS:
                badge.setText(f'✕ Too Close ({gap_ms:.1f}ms < 50ms)')
                badge.setStyleSheet(HOST_BADGE_WARNING_STYLESHEET)
            else:
                badge.setText(f'✕ Exceeds Window ({gap_ms:.1f}ms > 1600ms)')
                badge.setStyleSheet(HOST_BADGE_DANGER_STYLESHEET)
        elif len(self._snapshot.candidates) == 1:
            badge.setText('Single Candidate')
            badge.setStyleSheet(HOST_BADGE_INFO_STYLESHEET)
        else:
            badge.setText('N/A')
            badge.setStyleSheet(HOST_BADGE_MUTED_STYLESHEET)

        header_layout.addWidget(badge)
        layout.addLayout(header_layout)

        # Criteria & Resolution text
        criteria_label = QLabel(
            f'Window Criterion: {_SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS:.0f}ms - {_SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS:.0f}ms '
            f'between Candidate #1 and #2 connection times.'
        )
        criteria_label.setStyleSheet('color: #64748b; font-size: 8pt;')
        layout.addWidget(criteria_label)

        resolution_text = self._snapshot.timing_resolution or 'Timing comparison was not required.'
        desc = QLabel(resolution_text)
        desc.setWordWrap(True)
        desc.setStyleSheet('color: #cbd5e1; font-size: 8.5pt;')
        desc.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(desc)

        return card

    def _build_candidates_section(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        count = len(self._snapshot.candidates)
        section_title = QLabel(f'Evaluated Candidates ({count})')
        section_title.setStyleSheet('color: #e2e8f0; font-weight: bold; font-size: 10pt;')
        layout.addWidget(section_title)

        if not self._snapshot.candidates:
            empty_card = QFrame()
            empty_card.setObjectName('hostSectionCard')
            empty_card.setStyleSheet(HOST_DIAGNOSTICS_SECTION_CARD_STYLESHEET)
            empty_layout = QVBoxLayout(empty_card)
            empty_lbl = QLabel('No direct peer-to-peer player candidates were evaluated in this session.')
            empty_lbl.setStyleSheet('color: #64748b; font-style: italic; font-size: 9pt;')
            empty_layout.addWidget(empty_lbl)
            layout.addWidget(empty_card)
            return container

        for index, candidate in enumerate(self._snapshot.candidates, start=1):
            card = self._build_candidate_card(index, candidate)
            layout.addWidget(card)

        return container

    def _build_candidate_card(self, index: int, candidate: HostCandidateDiagnostic) -> QFrame:
        card = QFrame()
        card.setObjectName('hostCandidateCard')
        card.setStyleSheet(HOST_DIAGNOSTICS_CANDIDATE_HOST_STYLESHEET if candidate.is_host else HOST_DIAGNOSTICS_CANDIDATE_CARD_STYLESHEET)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(8)

        # Header row
        header = QHBoxLayout()
        header.setSpacing(8)

        index_badge = QLabel(f'#{index}')
        index_badge.setStyleSheet('color: #64748b; font-weight: bold; font-size: 8.5pt;')
        header.addWidget(index_badge)

        if candidate.country_code:
            flag_icon = load_country_flag_icon(candidate.country_code)
            if flag_icon is not None:
                flag_lbl = QLabel()
                flag_lbl.setPixmap(flag_icon.pixmap(scale_by_ui(16), scale_by_ui(12)))
                header.addWidget(flag_lbl)

        ip_lbl = QLabel(candidate.ip)
        ip_lbl.setStyleSheet('color: #ffffff; font-weight: bold; font-size: 10pt;')
        ip_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        header.addWidget(ip_lbl)

        if candidate.usernames:
            users_lbl = QLabel(f'(@{", ".join(candidate.usernames)})')
            users_lbl.setStyleSheet('color: #94a3b8; font-size: 9pt;')
            header.addWidget(users_lbl)

        # Status pills
        if candidate.is_host:
            host_pill = QLabel('✓ SESSION HOST')
            host_pill.setStyleSheet(HOST_BADGE_SUCCESS_STYLESHEET)
            header.addWidget(host_pill)
        if candidate.is_pending_disconnection:
            pending_pill = QLabel('Pending Disconnect')
            pending_pill.setStyleSheet(HOST_BADGE_WARNING_STYLESHEET)
            header.addWidget(pending_pill)
        if candidate.is_relayed:
            relay_pill = QLabel('Relayed')
            relay_pill.setStyleSheet(HOST_BADGE_INFO_STYLESHEET)
            header.addWidget(relay_pill)
        if candidate.is_disconnected:
            dc_pill = QLabel('Disconnected')
            dc_pill.setStyleSheet(HOST_BADGE_MUTED_STYLESHEET)
            header.addWidget(dc_pill)

        header.addStretch(1)

        copy_btn = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), ' Copy')
        copy_btn.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
        cand_ip = candidate.ip
        copy_btn.clicked.connect(lambda: self._copy_text(copy_btn, cand_ip))
        header.addWidget(copy_btn)

        layout.addLayout(header)

        # Grid of metrics
        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(4)

        now = datetime.now(tz=candidate.last_rejoin.tzinfo)
        rejoin_str = candidate.last_rejoin.strftime('%H:%M:%S.%f')[:-3]
        elapsed_str = format_elapsed_time(now - candidate.last_rejoin)

        # Row 0: Connection time
        rejoin_title = QLabel('Last Rejoin:')
        rejoin_title.setStyleSheet('color: #64748b; font-size: 8.5pt;')
        rejoin_val = QLabel(f'{rejoin_str} ({elapsed_str} ago)')
        rejoin_val.setStyleSheet('color: #cbd5e1; font-size: 8.5pt;')
        grid.addWidget(rejoin_title, 0, 0)
        grid.addWidget(rejoin_val, 0, 1)

        # Row 1: Sent packets & eligibility
        sent_title = QLabel('Packets Sent:')
        sent_title.setStyleSheet('color: #64748b; font-size: 8.5pt;')

        sent_val_box = QHBoxLayout()
        sent_val_box.setSpacing(6)
        sent_val = QLabel(str(candidate.packets_sent))
        sent_val.setStyleSheet('color: #f1f5f9; font-weight: bold; font-size: 8.5pt;')
        sent_val_box.addWidget(sent_val)

        packet_pill = QLabel()
        if candidate.packet_status == 'Eligible':
            packet_pill.setText('✓ Eligible')
            packet_pill.setStyleSheet(HOST_BADGE_SUCCESS_STYLESHEET)
        elif candidate.packet_status == 'Not enough sent':
            packet_pill.setText('✕ < 9 Sent')
            packet_pill.setStyleSheet(HOST_BADGE_WARNING_STYLESHEET)
        else:
            packet_pill.setText('✕ > 1000 Exchanged')
            packet_pill.setStyleSheet(HOST_BADGE_DANGER_STYLESHEET)
        sent_val_box.addWidget(packet_pill)
        sent_val_box.addStretch(1)

        grid.addWidget(sent_title, 1, 0)
        grid.addLayout(sent_val_box, 1, 1)

        # Row 2: Received & Exchanged
        recv_title = QLabel('Packets Received / Exchanged:')
        recv_title.setStyleSheet('color: #64748b; font-size: 8.5pt;')
        recv_val = QLabel(f'{candidate.packets_received} recv / {candidate.packets_exchanged} total')
        recv_val.setStyleSheet('color: #94a3b8; font-size: 8.5pt;')
        grid.addWidget(recv_title, 2, 0)
        grid.addWidget(recv_val, 2, 1)

        layout.addLayout(grid)

        return card

    def _build_servers_section(self) -> QWidget:
        card = QFrame()
        card.setObjectName('hostSectionCard')
        card.setStyleSheet(HOST_DIAGNOSTICS_SECTION_CARD_STYLESHEET)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)

        count = len(self._snapshot.filtered_servers)
        title = QLabel(f'Filtered Game & Relay Server{pluralize(count)} ({count})')
        title.setStyleSheet('color: #8b9bb4; font-weight: bold; font-size: 9pt;')
        layout.addWidget(title)

        servers_text = ', '.join(f'{server_ip} ({exchanged} pkts)' for server_ip, exchanged in self._snapshot.filtered_servers)
        desc = QLabel(servers_text)
        desc.setWordWrap(True)
        desc.setStyleSheet('color: #64748b; font-size: 8pt;')
        desc.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(desc)

        return card

    def _build_footer(self) -> QWidget:
        footer = QWidget()
        layout = QHBoxLayout(footer)
        layout.setContentsMargins(4, 6, 4, 4)
        layout.setSpacing(10)

        # Copy full host details button
        copy_details_btn = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), ' Copy Host Details')
        copy_details_btn.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
        copy_details_btn.clicked.connect(lambda: self._copy_details(copy_details_btn))
        layout.addWidget(copy_details_btn)

        # In-place re-detect host button
        if self._redetect_callback is not None:
            redetect_btn = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh.svg')), ' Re-detect Host')
            redetect_btn.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
            redetect_btn.clicked.connect(self._on_redetect_clicked)
            layout.addWidget(redetect_btn)

        layout.addStretch(1)

        close_btn = QPushButton('Close')
        close_btn.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        close_btn.setDefault(True)
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)

        return footer

    def _copy_text(self, button: QPushButton, text: str, *, feedback_text: str = ' Copied!') -> None:
        set_clipboard_text(text)
        animate_button_feedback(button, feedback_text=feedback_text, duration_milliseconds=1500)

    def _copy_details(self, button: QPushButton) -> None:
        self._copy_text(button, self._snapshot.raw_details, feedback_text=' Copied Host Details!')

    def _on_redetect_clicked(self) -> None:
        if self._redetect_callback is not None:
            new_snapshot = self._redetect_callback()
            if new_snapshot is not None:
                self.update_snapshot(new_snapshot)


_active_host_diagnostics_dialogs: ActiveDialogRegistry[str, SessionHostDiagnosticsDialog] = ActiveDialogRegistry()


def show_session_host_diagnostics_dialog(
    parent: QWidget | None,
    snapshot: HostDiagnosticsSnapshot,
    *,
    redetect_callback: Callable[[], HostDiagnosticsSnapshot | None] | None = None,
) -> SessionHostDiagnosticsDialog:
    """Open or focus the Session Host Diagnostics dialog with the given snapshot."""
    dialog = _active_host_diagnostics_dialogs.show_or_focus(
        'host_diagnostics',
        lambda: SessionHostDiagnosticsDialog(parent, snapshot, redetect_callback=redetect_callback),
    )
    dialog.update_snapshot(snapshot)
    return dialog
