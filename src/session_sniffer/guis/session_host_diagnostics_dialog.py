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

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.live_language import register_language_refresh
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
from session_sniffer.guis.theming import ICONS_DIR_PATH, themed_qss
from session_sniffer.guis.utils import (
    ActiveDialogRegistry,
    animate_button_feedback,
    load_country_flag_icon,
    render_svg_pixmap_from_resource,
    scale_by_ui,
    set_clipboard_text,
    set_dialog_window_flags,
)
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.text_utils import format_elapsed_time

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.player.session_host import HostCandidateDiagnostic, HostDiagnosticsSnapshot

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
    badge_text: str | None = None
    badge_stylesheet: str | None = None


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

        self._update_window_title()
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
        register_language_refresh(self, self._on_language_changed)

    def _update_window_title(self) -> None:
        title_prefix = tr('Session Host Diagnostics')
        if self._snapshot.detected_host_ip is not None:
            time_string = self._snapshot.timestamp.strftime('%H:%M:%S')
            self.setWindowTitle(f'{TITLE} - {title_prefix} - {self._snapshot.detected_host_ip} ({time_string})')
        else:
            self.setWindowTitle(f'{TITLE} - {title_prefix}')

    def _on_language_changed(self) -> None:
        """Re-translate the dialog title, footer buttons, and dynamic diagnostic cards."""
        self._update_window_title()
        self._retranslate_footer()
        self._rebuild_content()

    def update_snapshot(self, snapshot: HostDiagnosticsSnapshot) -> None:
        """Update the displayed snapshot and refresh the dialog contents."""
        self._snapshot = snapshot
        self._update_window_title()
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

        # 4. Candidates section
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
        if is_success:
            icon_label.setPixmap(render_svg_pixmap_from_resource('crown.svg', icon_size, icon_size))
        else:
            icon_label.setPixmap(render_svg_pixmap_from_resource('triangle-alert.svg', icon_size, icon_size, '#f59e0b'))
        icon_label.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.addWidget(icon_label)

        info_layout = QVBoxLayout()
        info_layout.setSpacing(4)

        title_label = QLabel(tr('Session Host Detected') if is_success else tr('Host Not Detected'))
        title_font = QFont()
        title_font.setPointSize(11)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet(themed_qss('color: #10b981;' if is_success else 'color: #fbbf24;'))
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
            ip_label.setStyleSheet(themed_qss('color: #ffffff;'))
            ip_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            host_row.addWidget(ip_label)

            if self._snapshot.detected_host_usernames:
                usernames_text = ', '.join(self._snapshot.detected_host_usernames)
                user_label = QLabel(f'(@{usernames_text})')
                user_label.setStyleSheet(themed_qss('color: #94a3b8; font-size: 9.5pt;'))
                host_row.addWidget(user_label)

            host_row.addStretch(1)
            info_layout.addLayout(host_row)
        else:
            reason = self._snapshot.rejection_reason or self._snapshot.outcome
            reason_label = QLabel(reason)
            reason_label.setWordWrap(True)
            reason_label.setStyleSheet(themed_qss('color: #e2e8f0; font-size: 9pt;'))
            reason_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            info_layout.addWidget(reason_label)

        time_str = self._snapshot.timestamp.strftime('%H:%M:%S')
        timestamp_label = QLabel(tr('Evaluation performed at {time}', time=time_str))
        timestamp_label.setStyleSheet(themed_qss('color: #64748b; font-size: 8pt;'))
        info_layout.addWidget(timestamp_label)

        layout.addLayout(info_layout, stretch=1)

        if is_success and self._snapshot.detected_host_ip:
            actions_layout = QVBoxLayout()
            actions_layout.setContentsMargins(0, 0, 0, 0)
            actions_layout.setSpacing(6)

            copy_host_ip_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'copy.svg')), f" {tr('Copy Host IP')}")
            copy_host_ip_button.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
            detected_ip = self._snapshot.detected_host_ip
            copy_host_ip_button.clicked.connect(lambda: self._copy_text(copy_host_ip_button, detected_ip))
            actions_layout.addWidget(copy_host_ip_button)

            if self._snapshot.detected_host_usernames:
                usernames_count = len(self._snapshot.detected_host_usernames)
                copy_host_usernames_button = QPushButton(
                    QIcon(str(ICONS_DIR_PATH / 'copy.svg')),
                    f" {tr_plural('Copy Host Username', 'Copy Host Usernames', usernames_count)}",
                )
                copy_host_usernames_button.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
                detected_usernames = ', '.join(self._snapshot.detected_host_usernames)
                copy_host_usernames_button.clicked.connect(
                    lambda: self._copy_text(copy_host_usernames_button, detected_usernames),
                )
                actions_layout.addWidget(copy_host_usernames_button)

            layout.addLayout(actions_layout)

        return hero_frame

    def _build_stats_section(self) -> QWidget:
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        stats = [
            (tr('Total Evaluated'), str(self._snapshot.total_evaluated_players), '#38bdf8'),
            (tr('Direct P2P Players'), str(self._snapshot.direct_p2p_players), '#34d399'),
            (tr('Filtered Server IPs'), str(self._snapshot.filtered_server_ips), '#94a3b8'),
        ]

        for label_text, value_text, accent_color in stats:
            box = QFrame()
            box.setObjectName('hostStatBox')
            box.setStyleSheet(HOST_DIAGNOSTICS_STAT_BOX_STYLESHEET)
            box_layout = QVBoxLayout(box)
            box_layout.setContentsMargins(10, 8, 10, 8)
            box_layout.setSpacing(2)

            title_lbl = QLabel(label_text)
            title_lbl.setStyleSheet(themed_qss('color: #8b9bb4; font-size: 8pt; font-weight: bold; text-transform: uppercase;'))
            box_layout.addWidget(title_lbl)

            val_lbl = QLabel(value_text)
            val_font = QFont()
            val_font.setPointSize(14)
            val_font.setBold(True)
            val_lbl.setFont(val_font)
            val_lbl.setStyleSheet(themed_qss(f'color: {accent_color};'))
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
        icon_path = ICONS_DIR_PATH / 'check.svg'
        if icon_path.exists():
            icon_label.setPixmap(QIcon(str(icon_path)).pixmap(scale_by_ui(16), scale_by_ui(16)))
        header_layout.addWidget(icon_label)

        title = QLabel(tr('Detection Criteria Checklist'))
        title.setStyleSheet(themed_qss('color: #f1f5f9; font-weight: bold; font-size: 9.5pt;'))
        header_layout.addWidget(title)

        header_layout.addStretch(1)

        items = self._compute_checklist_items()
        passed_count = sum(1 for item in items if item.passed)
        total_count = len(items)

        summary_badge = QLabel(tr('{passed}/{total} Passed', passed=passed_count, total=total_count))
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

            status_badge = QLabel(tr('PASS') if item.passed else tr('FAIL'))
            status_badge.setStyleSheet(HOST_BADGE_SUCCESS_STYLESHEET if item.passed else HOST_BADGE_DANGER_STYLESHEET)
            status_badge.setFixedWidth(scale_by_ui(44))
            status_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            row_layout.addWidget(status_badge, alignment=Qt.AlignmentFlag.AlignTop)

            text_layout = QVBoxLayout()
            text_layout.setContentsMargins(0, 0, 0, 0)
            text_layout.setSpacing(3)

            title_label = QLabel(item.title)
            title_font = QFont()
            title_font.setBold(True)
            title_font.setPointSize(9)
            title_label.setFont(title_font)
            title_label.setStyleSheet(themed_qss('color: #e2e8f0;' if item.passed else 'color: #fca5a5;'))
            text_layout.addWidget(title_label)

            detail_label = QLabel(item.detail)
            detail_label.setStyleSheet(themed_qss('color: #94a3b8; font-size: 8.5pt;'))
            detail_label.setWordWrap(True)
            text_layout.addWidget(detail_label)

            row_layout.addLayout(text_layout, stretch=1)

            if item.badge_text is not None and item.badge_stylesheet is not None:
                metric_badge = QLabel(item.badge_text)
                metric_badge.setStyleSheet(item.badge_stylesheet)
                metric_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
                row_layout.addWidget(metric_badge, alignment=Qt.AlignmentFlag.AlignTop)

            layout.addWidget(row)

        return card

    def _compute_checklist_items(self) -> list[_DetectionChecklistItem]:
        """Compute the evaluation status and explanation for each detection criterion."""
        if self._snapshot.modmenu_source is not None:
            return self._compute_modmenu_checklist_items()

        items: list[_DetectionChecklistItem] = []

        # 1. Direct P2P Candidates
        p2p_count = self._snapshot.direct_p2p_players
        evaluated_count = self._snapshot.total_evaluated_players
        filtered_count = self._snapshot.filtered_server_ips

        if not evaluated_count:
            candidates_detail = tr('No players found in session')
        elif not p2p_count:
            candidates_detail = tr_plural(
                'All {count} connected endpoint is a game or relay server',
                'All {count} connected endpoints are game or relay servers',
                evaluated_count,
            )
        elif filtered_count > 0:
            candidates_phrase = tr_plural(
                '{count} direct P2P candidate identified',
                '{count} direct P2P candidates identified',
                p2p_count,
            )
            filtered_phrase = tr_plural(
                '{count} server filtered',
                '{count} servers filtered',
                filtered_count,
            )
            candidates_detail = tr('{candidates} ({filtered})', candidates=candidates_phrase, filtered=filtered_phrase)
        else:
            candidates_detail = tr_plural(
                '{count} direct P2P candidate identified in session',
                '{count} direct P2P candidates identified in session',
                p2p_count,
            )

        p2p_passed = p2p_count > 0
        p2p_badge = tr('{count} Direct P2P', count=p2p_count) if p2p_passed else tr('0 Direct P2P')
        p2p_badge_style = HOST_BADGE_SUCCESS_STYLESHEET if p2p_passed else HOST_BADGE_DANGER_STYLESHEET

        items.append(
            _DetectionChecklistItem(
                title=tr('Direct P2P Candidates'),
                passed=p2p_passed,
                detail=candidates_detail,
                badge_text=p2p_badge,
                badge_stylesheet=p2p_badge_style,
            ),
        )

        # 2. Candidate Activity
        if self._snapshot.success:
            activity_passed = True
            activity_detail = tr('Candidate is active and connected')
            activity_badge = tr('Active & Connected')
            activity_badge_style = HOST_BADGE_SUCCESS_STYLESHEET
        elif self._snapshot.candidates:
            active_candidates = [candidate for candidate in self._snapshot.candidates if not candidate.is_pending_disconnection and not candidate.is_disconnected]
            activity_passed = bool(active_candidates)
            active_count = len(active_candidates)
            if activity_passed:
                activity_detail = tr_plural(
                    '{count} candidate active and connected',
                    '{count} candidates active and connected',
                    active_count,
                )
                activity_badge = tr('{count} Active', count=active_count)
                activity_badge_style = HOST_BADGE_SUCCESS_STYLESHEET
            else:
                activity_detail = tr('All candidates are disconnected or pending disconnection')
                activity_badge = tr('Disconnected')
                activity_badge_style = HOST_BADGE_DANGER_STYLESHEET
        else:
            activity_passed = False
            activity_detail = tr('No candidates available to evaluate activity')
            activity_badge = tr('No Candidates')
            activity_badge_style = HOST_BADGE_MUTED_STYLESHEET

        items.append(
            _DetectionChecklistItem(
                title=tr('Candidate Activity'),
                passed=activity_passed,
                detail=activity_detail,
                badge_text=activity_badge,
                badge_stylesheet=activity_badge_style,
            ),
        )

        # 3. Connection Timing Window
        timing_badge: str
        timing_badge_style: str
        if self._snapshot.success:
            timing_passed = True
            if self._snapshot.timing_gap_seconds is not None:
                gap_ms = self._snapshot.timing_gap_seconds * 1000
                gap_ms_str = f'{gap_ms:.1f}'
                timing_badge = tr('✓ Within Window ({gap_ms}ms)', gap_ms=gap_ms_str)
                timing_badge_style = HOST_BADGE_SUCCESS_STYLESHEET
                timing_detail = self._snapshot.timing_resolution or tr(
                    'Join separation ({gap_ms}ms) within valid window (50ms - 1,600ms)',
                    gap_ms=gap_ms_str,
                )
            else:
                timing_badge = tr('Single Candidate')
                timing_badge_style = HOST_BADGE_INFO_STYLESHEET
                timing_detail = self._snapshot.timing_resolution or tr('Single candidate in session (timing comparison not required)')
        elif self._snapshot.timing_gap_seconds is not None:
            gap_ms = self._snapshot.timing_gap_seconds * 1000
            gap_ms_str = f'{gap_ms:.1f}'
            gap_text = f'{self._snapshot.timing_gap_seconds:.3f}s' if self._snapshot.timing_gap_seconds >= 1.0 else f'{gap_ms:.1f}ms'
            if _SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS <= gap_ms <= _SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS:
                timing_passed = True
                timing_badge = tr('✓ Within Window ({gap_ms}ms)', gap_ms=gap_ms_str)
                timing_badge_style = HOST_BADGE_SUCCESS_STYLESHEET
                timing_detail = self._snapshot.timing_resolution or tr(
                    'Join separation ({gap_ms}ms) within valid window (50ms - 1,600ms)',
                    gap_ms=gap_ms_str,
                )
            elif gap_ms < _SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS:
                timing_passed = False
                timing_badge = tr('✕ Too Close ({gap_ms}ms < 50ms)', gap_ms=gap_ms_str)
                timing_badge_style = HOST_BADGE_WARNING_STYLESHEET
                timing_detail = self._snapshot.timing_resolution or tr(
                    'Ambiguous ({gap_ms}ms < 50ms): players connected simultaneously',
                    gap_ms=gap_ms_str,
                )
            else:
                timing_passed = False
                timing_badge = tr('✕ Exceeds Window ({gap_text} > 1600ms)', gap_text=gap_text)
                timing_badge_style = HOST_BADGE_DANGER_STYLESHEET
                timing_detail = self._snapshot.timing_resolution or tr(
                    'Gap too large ({gap_text} > 1,600ms): candidates did not join together',
                    gap_text=gap_text,
                )
        elif len(self._snapshot.candidates) == 1:
            timing_passed = True
            timing_badge = tr('Single Candidate')
            timing_badge_style = HOST_BADGE_INFO_STYLESHEET
            timing_detail = self._snapshot.timing_resolution or tr('Single candidate in session (timing comparison not required)')
        else:
            timing_passed = False
            timing_badge = tr('N/A')
            timing_badge_style = HOST_BADGE_MUTED_STYLESHEET
            timing_detail = self._snapshot.timing_resolution or tr('No candidates available for timing comparison')

        items.append(
            _DetectionChecklistItem(
                title=tr('Connection Timing Window'),
                passed=timing_passed,
                detail=timing_detail,
                badge_text=timing_badge,
                badge_stylesheet=timing_badge_style,
            ),
        )

        # 4. Packet Threshold Criteria
        if self._snapshot.success:
            packet_passed = True
            host_candidate = next(
                (candidate for candidate in self._snapshot.candidates if candidate.is_host),
                self._snapshot.candidates[0] if self._snapshot.candidates else None,
            )
            if host_candidate is not None:
                packet_detail = tr(
                    'Candidate sent >= 9 packets ({sent}) and exchanged <= 1,000 ({exchanged})',
                    sent=host_candidate.packets_sent,
                    exchanged=host_candidate.packets_exchanged,
                )
            else:
                packet_detail = tr('Candidate packet counts within valid bounds (>= 9 sent, <= 1,000 exchanged)')
            packet_badge = tr('Eligible Packets')
            packet_badge_style = HOST_BADGE_SUCCESS_STYLESHEET
        elif self._snapshot.candidates:
            has_under_sent = any(
                candidate.packet_status == 'Not enough sent' or candidate.packets_sent < _MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST for candidate in self._snapshot.candidates
            )
            has_over_exchanged = any(
                candidate.packet_status == 'Exceeds maximum exchanged' or candidate.packets_exchanged > _SESSION_HOST_MAX_PACKETS_FOR_DETECTION
                for candidate in self._snapshot.candidates
            )
            if has_under_sent:
                packet_passed = False
                packet_detail = tr(
                    'Candidate has not sent enough packets (>= {min_packets} required to rule out transient probes)',
                    min_packets=_MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST,
                )
                packet_badge = tr('✕ < {min_packets} Sent', min_packets=_MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST)
                packet_badge_style = HOST_BADGE_WARNING_STYLESHEET
            elif has_over_exchanged:
                packet_passed = False
                max_packets_str = f'{_SESSION_HOST_MAX_PACKETS_FOR_DETECTION:,}'
                packet_detail = tr(
                    'Candidate exchanged > {max_packets} packets (session already in progress)',
                    max_packets=max_packets_str,
                )
                packet_badge = tr('✕ > {max_packets} Exchanged', max_packets=max_packets_str)
                packet_badge_style = HOST_BADGE_DANGER_STYLESHEET
            else:
                packet_passed = True
                packet_detail = tr(
                    'Candidate packet counts within valid bounds (>= {min_packets} sent, <= {max_packets} exchanged)',
                    min_packets=_MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST,
                    max_packets=f'{_SESSION_HOST_MAX_PACKETS_FOR_DETECTION:,}',
                )
                packet_badge = tr('Eligible Packets')
                packet_badge_style = HOST_BADGE_SUCCESS_STYLESHEET
        else:
            packet_passed = False
            packet_detail = tr('No candidates to evaluate packet thresholds')
            packet_badge = tr('No Candidates')
            packet_badge_style = HOST_BADGE_MUTED_STYLESHEET

        items.append(
            _DetectionChecklistItem(
                title=tr('Packet Threshold Criteria'),
                passed=packet_passed,
                detail=packet_detail,
                badge_text=packet_badge,
                badge_stylesheet=packet_badge_style,
            ),
        )

        return items

    def _compute_modmenu_checklist_items(self) -> list[_DetectionChecklistItem]:
        """Compute checklist items when session host resolution is governed by a mod menu Lua plugin."""
        source_name = self._snapshot.modmenu_source or tr('Mod Menu')
        host_ip = self._snapshot.modmenu_host_ip
        host_username = self._snapshot.modmenu_host_username

        if host_ip is not None:
            lua_passed = True
            username_suffix = f' (@{host_username})' if bool(host_username) else ''
            lua_detail = tr(
                '{source} Lua plugin reported session host {host_ip}{username_suffix}',
                source=source_name,
                host_ip=host_ip,
                username_suffix=username_suffix,
            )
            lua_badge = tr('✓ {source} Lua', source=source_name)
            lua_badge_style = HOST_BADGE_SUCCESS_STYLESHEET
        else:
            lua_passed = False
            lua_detail = self._snapshot.rejection_reason or self._snapshot.outcome
            lua_badge = tr('No Remote Host')
            lua_badge_style = HOST_BADGE_WARNING_STYLESHEET

        if self._snapshot.success and self._snapshot.detected_host_ip is not None:
            match_passed = True
            match_detail = tr(
                'Reported host {host_ip} matched an active GTA V UDP-confirmed P2P player in your session',
                host_ip=self._snapshot.detected_host_ip,
            )
            match_badge = tr('✓ Matched in Session')
            match_badge_style = HOST_BADGE_SUCCESS_STYLESHEET
        elif host_ip is not None:
            match_passed = False
            match_detail = tr(
                'Reported host {host_ip} is not currently connected in confirmed GTA V P2P session traffic',
                host_ip=host_ip,
            )
            match_badge = tr('✕ Not Connected')
            match_badge_style = HOST_BADGE_WARNING_STYLESHEET
        else:
            p2p_count = self._snapshot.direct_p2p_players
            match_passed = False
            match_detail = tr_plural(
                '{count} direct P2P player currently connected in session',
                '{count} direct P2P players currently connected in session',
                p2p_count,
            )
            match_badge = tr('{count} Direct P2P', count=p2p_count)
            match_badge_style = HOST_BADGE_INFO_STYLESHEET if p2p_count > 0 else HOST_BADGE_MUTED_STYLESHEET

        return [
            _DetectionChecklistItem(
                title=tr('{source} Lua Plugin (Source of Truth)', source=source_name),
                passed=lua_passed,
                detail=lua_detail,
                badge_text=lua_badge,
                badge_stylesheet=lua_badge_style,
            ),
            _DetectionChecklistItem(
                title=tr('Direct P2P Session Match'),
                passed=match_passed,
                detail=match_detail,
                badge_text=match_badge,
                badge_stylesheet=match_badge_style,
            ),
        ]

    def _build_candidates_section(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        count = len(self._snapshot.candidates)
        section_title = QLabel(tr('Evaluated Candidates ({count})', count=count))
        section_title.setStyleSheet(themed_qss('color: #e2e8f0; font-weight: bold; font-size: 10pt;'))
        layout.addWidget(section_title)

        if not self._snapshot.candidates:
            empty_card = QFrame()
            empty_card.setObjectName('hostSectionCard')
            empty_card.setStyleSheet(HOST_DIAGNOSTICS_SECTION_CARD_STYLESHEET)
            empty_layout = QVBoxLayout(empty_card)
            empty_lbl = QLabel(tr('No direct peer-to-peer player candidates were evaluated in this session.'))
            empty_lbl.setStyleSheet(themed_qss('color: #64748b; font-style: italic; font-size: 9pt;'))
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
        index_badge.setStyleSheet(themed_qss('color: #64748b; font-weight: bold; font-size: 8.5pt;'))
        header.addWidget(index_badge)

        if candidate.country_code:
            flag_icon = load_country_flag_icon(candidate.country_code)
            if flag_icon is not None:
                flag_lbl = QLabel()
                flag_lbl.setPixmap(flag_icon.pixmap(scale_by_ui(16), scale_by_ui(12)))
                header.addWidget(flag_lbl)

        ip_lbl = QLabel(candidate.ip)
        ip_lbl.setStyleSheet(themed_qss('color: #ffffff; font-weight: bold; font-size: 10pt;'))
        ip_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        header.addWidget(ip_lbl)

        if candidate.usernames:
            users_lbl = QLabel(f'(@{", ".join(candidate.usernames)})')
            users_lbl.setStyleSheet(themed_qss('color: #94a3b8; font-size: 9pt;'))
            header.addWidget(users_lbl)

        # Status pills
        if candidate.is_host:
            host_pill = QLabel(tr('✓ SESSION HOST'))
            host_pill.setStyleSheet(HOST_BADGE_SUCCESS_STYLESHEET)
            header.addWidget(host_pill)
        if candidate.is_pending_disconnection:
            pending_pill = QLabel(tr('Pending Disconnect'))
            pending_pill.setStyleSheet(HOST_BADGE_WARNING_STYLESHEET)
            header.addWidget(pending_pill)
        if candidate.is_relayed:
            relay_pill = QLabel(tr('Relayed'))
            relay_pill.setStyleSheet(HOST_BADGE_INFO_STYLESHEET)
            header.addWidget(relay_pill)
        if candidate.is_disconnected:
            dc_pill = QLabel(tr('Disconnected'))
            dc_pill.setStyleSheet(HOST_BADGE_MUTED_STYLESHEET)
            header.addWidget(dc_pill)

        header.addStretch(1)

        copy_btn = QPushButton(QIcon(str(ICONS_DIR_PATH / 'copy.svg')), f" {tr('Copy')}")
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
        rejoin_title = QLabel(tr('Last Rejoin:'))
        rejoin_title.setStyleSheet(themed_qss('color: #64748b; font-size: 8.5pt;'))
        rejoin_val = QLabel(tr('{rejoin_str} ({elapsed_str} ago)', rejoin_str=rejoin_str, elapsed_str=elapsed_str))
        rejoin_val.setStyleSheet(themed_qss('color: #cbd5e1; font-size: 8.5pt;'))
        grid.addWidget(rejoin_title, 0, 0)
        grid.addWidget(rejoin_val, 0, 1)

        # Row 1: Sent packets & eligibility
        sent_title = QLabel(tr('Packets Sent:'))
        sent_title.setStyleSheet(themed_qss('color: #64748b; font-size: 8.5pt;'))

        sent_val_box = QHBoxLayout()
        sent_val_box.setSpacing(6)
        sent_val = QLabel(str(candidate.packets_sent))
        sent_val.setStyleSheet(themed_qss('color: #f1f5f9; font-weight: bold; font-size: 8.5pt;'))
        sent_val_box.addWidget(sent_val)

        packet_pill = QLabel()
        if candidate.packet_status == 'Authoritative (Mod Menu Lua)':
            packet_pill.setText(tr('✓ Mod Menu Lua'))
            packet_pill.setStyleSheet(HOST_BADGE_SUCCESS_STYLESHEET)
        elif candidate.packet_status == 'Connected P2P':
            packet_pill.setText(tr('Connected P2P'))
            packet_pill.setStyleSheet(HOST_BADGE_INFO_STYLESHEET)
        elif candidate.packet_status == 'Eligible':
            packet_pill.setText(tr('✓ Eligible'))
            packet_pill.setStyleSheet(HOST_BADGE_SUCCESS_STYLESHEET)
        elif candidate.packet_status == 'Not enough sent':
            packet_pill.setText(tr('✕ < 9 Sent'))
            packet_pill.setStyleSheet(HOST_BADGE_WARNING_STYLESHEET)
        else:
            packet_pill.setText(tr('✕ > 1000 Exchanged'))
            packet_pill.setStyleSheet(HOST_BADGE_DANGER_STYLESHEET)
        sent_val_box.addWidget(packet_pill)
        sent_val_box.addStretch(1)

        grid.addWidget(sent_title, 1, 0)
        grid.addLayout(sent_val_box, 1, 1)

        # Row 2: Received & Exchanged
        recv_title = QLabel(tr('Packets Received / Exchanged:'))
        recv_title.setStyleSheet(themed_qss('color: #64748b; font-size: 8.5pt;'))
        recv_val = QLabel(
            tr(
                '{recv} recv / {total} total',
                recv=candidate.packets_received,
                total=candidate.packets_exchanged,
            ),
        )
        recv_val.setStyleSheet(themed_qss('color: #94a3b8; font-size: 8.5pt;'))
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
        title = QLabel(
            tr_plural(
                'Filtered Game & Relay Server ({count})',
                'Filtered Game & Relay Servers ({count})',
                count,
            ),
        )
        title.setStyleSheet(themed_qss('color: #8b9bb4; font-weight: bold; font-size: 9pt;'))
        layout.addWidget(title)

        servers_text = ', '.join(
            tr('{server_ip} ({exchanged} pkts)', server_ip=server_ip, exchanged=exchanged)
            for server_ip, exchanged in self._snapshot.filtered_servers
        )
        desc = QLabel(servers_text)
        desc.setWordWrap(True)
        desc.setStyleSheet(themed_qss('color: #64748b; font-size: 8pt;'))
        desc.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(desc)

        return card

    def _build_footer(self) -> QWidget:
        footer = QWidget()
        layout = QHBoxLayout(footer)
        layout.setContentsMargins(4, 6, 4, 4)
        layout.setSpacing(10)

        # Copy full host details button
        copy_details_btn = QPushButton(QIcon(str(ICONS_DIR_PATH / 'copy.svg')), '')
        copy_details_btn.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
        copy_details_btn.clicked.connect(lambda: self._copy_details(copy_details_btn))
        layout.addWidget(copy_details_btn)
        self._copy_details_button = copy_details_btn

        # In-place re-detect host button
        self._redetect_button: QPushButton | None = None
        if self._redetect_callback is not None:
            redetect_btn = QPushButton(QIcon(str(ICONS_DIR_PATH / 'refresh-cw.svg')), '')
            redetect_btn.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
            redetect_btn.clicked.connect(self._on_redetect_clicked)
            layout.addWidget(redetect_btn)
            self._redetect_button = redetect_btn

        layout.addStretch(1)

        close_btn = QPushButton()
        close_btn.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        close_btn.setDefault(True)
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)
        self._close_button = close_btn

        self._retranslate_footer()
        return footer

    def _retranslate_footer(self) -> None:
        """Apply current translations to footer action buttons."""
        self._copy_details_button.setText(f" {tr('Copy Host Details')}")
        if self._redetect_button is not None:
            self._redetect_button.setText(f" {tr('Re-detect Host')}")
        self._close_button.setText(tr('Close'))

    def _copy_text(self, button: QPushButton, text: str, *, feedback_text: str | None = None) -> None:
        set_clipboard_text(text)
        animate_button_feedback(
            button,
            feedback_text=feedback_text if feedback_text is not None else f" {tr('Copied!')}",
        )

    def _copy_details(self, button: QPushButton) -> None:
        self._copy_text(button, self._snapshot.raw_details, feedback_text=f" {tr('Copied Host Details!')}")

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
    dialog_key: str = 'host_diagnostics',
    redetect_callback: Callable[[], HostDiagnosticsSnapshot | None] | None = None,
) -> None:
    """Open or focus the Session Host Diagnostics dialog with the given snapshot."""
    dialog = _active_host_diagnostics_dialogs.show_or_focus(
        dialog_key,
        lambda: SessionHostDiagnosticsDialog(parent, snapshot, redetect_callback=redetect_callback),
    )
    dialog.update_snapshot(snapshot)
