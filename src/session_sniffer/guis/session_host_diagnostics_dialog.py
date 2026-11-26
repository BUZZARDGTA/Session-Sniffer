"""Dedicated dialog for inspecting Session Host detection diagnostics."""

from datetime import datetime
from typing import TYPE_CHECKING, override

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent, QFont, QIcon, QShowEvent
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
from session_sniffer.guis.window_layout import apply_maximize_on_show, restore_window_layout, save_window_layout
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.player.host_diagnostics_checklist import ChecklistBadgeTone, build_host_diagnostics_checklist
from session_sniffer.text_utils import format_elapsed_time

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.player.session_host import HostCandidateDiagnostic, HostDiagnosticsSnapshot

_CHECKLIST_BADGE_STYLESHEETS: dict[ChecklistBadgeTone, str] = {
    'success': HOST_BADGE_SUCCESS_STYLESHEET,
    'warning': HOST_BADGE_WARNING_STYLESHEET,
    'danger': HOST_BADGE_DANGER_STYLESHEET,
    'accent': HOST_BADGE_INFO_STYLESHEET,
    'muted': HOST_BADGE_MUTED_STYLESHEET,
}


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
        self._layout_saved = False
        restore_window_layout(self, 'session_host_diagnostics', fallback_resize=lambda: self.resize(scale_by_ui(720), scale_by_ui(620)))

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

        items = build_host_diagnostics_checklist(self._snapshot)
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

            badge_stylesheet = _CHECKLIST_BADGE_STYLESHEETS[item.badge_tone]
            metric_badge = QLabel(item.badge_text)
            metric_badge.setStyleSheet(badge_stylesheet)
            metric_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            row_layout.addWidget(metric_badge, alignment=Qt.AlignmentFlag.AlignTop)

            layout.addWidget(row)

        return card

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
        sent_val = QLabel(f'{candidate.packets_sent:,}')
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
                recv=f'{candidate.packets_received:,}',
                total=f'{candidate.packets_exchanged:,}',
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

    def _save_dialog_layout_once(self) -> None:
        if not self._layout_saved:
            self._layout_saved = True
            save_window_layout(self, 'session_host_diagnostics')

    @override
    def showEvent(self, arg__1: QShowEvent) -> None:
        """Apply deferred maximization when the diagnostics dialog is shown."""
        super().showEvent(arg__1)
        apply_maximize_on_show(self)

    @override
    def done(self, arg__1: int) -> None:
        """Persist dialog geometry before closing via accept/reject."""
        self._save_dialog_layout_once()
        super().done(arg__1)

    @override
    def closeEvent(self, arg__1: QCloseEvent) -> None:
        """Persist dialog geometry when closed directly."""
        self._save_dialog_layout_once()
        super().closeEvent(arg__1)


_active_host_diagnostics_dialogs: ActiveDialogRegistry[str, SessionHostDiagnosticsDialog] = ActiveDialogRegistry()


def close_all_session_host_diagnostics_dialogs() -> None:
    """Close all active Session Host Diagnostics dialogs so their layouts persist cleanly on exit."""
    _active_host_diagnostics_dialogs.close_all()


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
