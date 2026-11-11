"""Main application dashboard header widget with global search and live metrics."""

from typing import TYPE_CHECKING, override

from PySide6.QtCore import QEvent, QObject, QSize, Qt, Signal
from PySide6.QtGui import QIcon, QKeyEvent, QMouseEvent
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import VERSION
from session_sniffer.constants.standalone import TITLE
from session_sniffer.constants.tables import SEARCHABLE_COLUMN_EXCLUSIONS
from session_sniffer.guis.stylesheets import (
    HEADER_NOTIFICATION_BUTTON_ENABLED_STYLESHEET,
    HEADER_NOTIFICATION_BUTTON_MUTED_STYLESHEET,
    HEADER_SEARCH_BAR_STYLESHEET,
    HEADER_SEARCH_COMBO_STYLESHEET,
    HEADER_STAT_CARD_STYLESHEET,
    HEADER_STATS_DIVIDER_STYLESHEET,
    HEADER_STOPPED_BADGE_STYLESHEET,
    HEADER_SUBTITLE_STYLESHEET,
    HEADER_TITLE_STYLESHEET,
    HEADER_VERSION_BADGE_STYLESHEET,
    MAIN_HEADER_CONTAINER_STYLESHEET,
    STAT_CARD_TITLE_STYLESHEET,
    STAT_CARD_VALUE_STYLESHEET,
)
from session_sniffer.guis.utils import render_svg_icon_from_resource, render_svg_pixmap_from_resource, scale_by_ui
from session_sniffer.rendering_core.types import TableMergeState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Sequence


class _SearchInputFilter(QObject):
    """Handle Escape key on the header search bar to clear text or drop focus."""

    def __init__(self, search_bar: QLineEdit) -> None:
        super().__init__(search_bar)
        self._search_bar = search_bar

    @override
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if watched == self._search_bar and event.type() == QEvent.Type.KeyPress and isinstance(event, QKeyEvent) and event.key() == Qt.Key.Key_Escape:
            if self._search_bar.text():
                self._search_bar.clear()
            else:
                self._search_bar.clearFocus()
            return True
        return super().eventFilter(watched, event)


class _HeaderSearchBar(QLineEdit):
    """Global search bar with responsive sizing."""

    @override
    def sizeHint(self) -> QSize:
        default_hint = super().sizeHint()
        return QSize(scale_by_ui(360), default_hint.height())

    @override
    def minimumSizeHint(self) -> QSize:
        default_hint = super().minimumSizeHint()
        return QSize(scale_by_ui(120), default_hint.height())


class _NotificationToggleButton(QPushButton):
    """Compact header icon button supporting left-click single toggle and right-click toggle-all."""

    right_clicked = Signal()

    @override
    def mouseReleaseEvent(self, e: QMouseEvent) -> None:
        if e.button() == Qt.MouseButton.RightButton and self.rect().contains(e.position().toPoint()):
            self.right_clicked.emit()
            e.accept()
            return
        super().mouseReleaseEvent(e)


class SessionHeader(QFrame):
    """Application dashboard header with branding, unified global search, and live metrics."""

    search_changed = Signal(str, str)
    visual_notifications_toggle_requested = Signal()
    voice_notifications_toggle_requested = Signal()
    all_notifications_toggle_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName('mainHeader')
        self.setStyleSheet(MAIN_HEADER_CONTAINER_STYLESHEET)
        self.setFixedHeight(scale_by_ui(54))

        main_layout = QGridLayout(self)
        main_layout.setContentsMargins(scale_by_ui(6), scale_by_ui(2), scale_by_ui(6), scale_by_ui(2))
        main_layout.setSpacing(scale_by_ui(8))

        # ---------------------------------------------------------------------
        # Left Section: Branding & Status
        # ---------------------------------------------------------------------
        brand_container = QWidget()
        brand_layout = QVBoxLayout(brand_container)
        brand_layout.setSpacing(scale_by_ui(3))
        brand_layout.setContentsMargins(0, 0, 0, 0)

        title_row = QHBoxLayout()
        title_row.setSpacing(scale_by_ui(8))
        title_row.setContentsMargins(0, 0, 0, 0)

        title_label = QLabel(TITLE)
        title_label.setObjectName('headerTitle')
        title_label.setStyleSheet(HEADER_TITLE_STYLESHEET)
        title_row.addWidget(title_label)

        version_badge = QLabel(VERSION)
        version_badge.setObjectName('headerVersionBadge')
        version_badge.setStyleSheet(HEADER_VERSION_BADGE_STYLESHEET)
        title_row.addWidget(version_badge)

        self._stopped_badge = QLabel('CAPTURE STOPPED')
        self._stopped_badge.setObjectName('headerStoppedBadge')
        self._stopped_badge.setStyleSheet(HEADER_STOPPED_BADGE_STYLESHEET)
        self._stopped_badge.setVisible(False)
        title_row.addWidget(self._stopped_badge)
        title_row.addStretch(1)

        brand_layout.addLayout(title_row)

        subtitle_label = QLabel(
            'The best <span style="color: #22c55e; font-weight: 600;">FREE</span> and <span style="color: #22c55e; font-weight: 600;">Open-Source</span> packet sniffer',
        )
        subtitle_label.setObjectName('headerSubtitle')
        subtitle_label.setStyleSheet(HEADER_SUBTITLE_STYLESHEET)
        brand_layout.addWidget(subtitle_label)

        main_layout.addWidget(brand_container, 0, 0, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        # ---------------------------------------------------------------------
        # Center Section: Global Search & Column Selector
        # ---------------------------------------------------------------------
        search_layout = QHBoxLayout()
        search_layout.setSpacing(scale_by_ui(6))
        search_layout.setContentsMargins(0, 0, 0, 0)

        self.search_bar = _HeaderSearchBar()
        self.search_bar.setObjectName('headerSearchBar')
        self.search_bar.setStyleSheet(HEADER_SEARCH_BAR_STYLESHEET)
        self.search_bar.setMinimumWidth(scale_by_ui(120))
        self.search_bar.setMaximumWidth(scale_by_ui(460))
        self.search_bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        search_pixmap = render_svg_pixmap_from_resource('search.svg', scale_by_ui(14), scale_by_ui(14), '#64748b')
        self.search_bar.addAction(QIcon(search_pixmap), QLineEdit.ActionPosition.LeadingPosition)
        self.search_bar.setClearButtonEnabled(True)
        self._search_filter_guard = _SearchInputFilter(self.search_bar)
        self.search_bar.installEventFilter(self._search_filter_guard)
        self.search_bar.textChanged.connect(self._on_search_query_changed)

        self.search_combo = QComboBox()
        self.search_combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.search_combo.setObjectName('headerSearchCombo')
        self.search_combo.setStyleSheet(HEADER_SEARCH_COMBO_STYLESHEET)
        self.search_combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)
        self.search_combo.setMinimumWidth(scale_by_ui(116))
        self._populate_searchable_columns()
        self.search_combo.currentIndexChanged.connect(self._on_search_column_changed)

        self.set_search_placeholder_merged(is_merged=TableMergeState.is_merged())

        search_layout.addWidget(self.search_bar)
        search_layout.addWidget(self.search_combo)
        main_layout.addLayout(search_layout, 0, 1, Qt.AlignmentFlag.AlignCenter)

        # ---------------------------------------------------------------------
        # Right Section: Notification Toggles + Live Metrics Container
        # ---------------------------------------------------------------------
        right_layout = QHBoxLayout()
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(scale_by_ui(8))

        notifications_card = QFrame()
        notifications_card.setObjectName('headerNotificationsContainer')
        notifications_card.setStyleSheet(HEADER_STAT_CARD_STYLESHEET)
        notifications_layout = QHBoxLayout(notifications_card)
        notifications_layout.setContentsMargins(scale_by_ui(4), scale_by_ui(4), scale_by_ui(4), scale_by_ui(4))
        notifications_layout.setSpacing(scale_by_ui(4))

        btn_size = QSize(scale_by_ui(30), scale_by_ui(28))
        icon_size = QSize(scale_by_ui(16), scale_by_ui(16))

        self._visual_btn = _NotificationToggleButton()
        self._visual_btn.setFixedSize(btn_size)
        self._visual_btn.setIconSize(icon_size)
        self._visual_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._visual_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._visual_btn.clicked.connect(self.visual_notifications_toggle_requested.emit)
        self._visual_btn.right_clicked.connect(self.all_notifications_toggle_requested.emit)
        notifications_layout.addWidget(self._visual_btn)

        self._voice_btn = _NotificationToggleButton()
        self._voice_btn.setFixedSize(btn_size)
        self._voice_btn.setIconSize(icon_size)
        self._voice_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._voice_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._voice_btn.clicked.connect(self.voice_notifications_toggle_requested.emit)
        self._voice_btn.right_clicked.connect(self.all_notifications_toggle_requested.emit)
        notifications_layout.addWidget(self._voice_btn)

        right_layout.addWidget(notifications_card)

        stats_card = QFrame()
        stats_card.setObjectName('headerStatsContainer')
        stats_card.setStyleSheet(HEADER_STAT_CARD_STYLESHEET)
        stats_card_layout = QHBoxLayout(stats_card)
        stats_card_layout.setContentsMargins(scale_by_ui(8), scale_by_ui(4), scale_by_ui(10), scale_by_ui(4))
        stats_card_layout.setSpacing(scale_by_ui(8))

        pulse_icon = QLabel()
        pulse_icon.setFixedSize(scale_by_ui(18), scale_by_ui(18))
        pulse_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pulse_icon.setPixmap(render_svg_pixmap_from_resource('activity.svg', scale_by_ui(16), scale_by_ui(16), '#22c55e'))
        stats_card_layout.addWidget(pulse_icon)

        uptime_layout = QVBoxLayout()
        uptime_layout.setSpacing(0)
        uptime_layout.setContentsMargins(0, 0, 0, 0)

        uptime_title = QLabel('Uptime')
        uptime_title.setStyleSheet(STAT_CARD_TITLE_STYLESHEET)
        uptime_layout.addWidget(uptime_title)

        self._uptime_value = QLabel('00:00:00')
        self._uptime_value.setStyleSheet(STAT_CARD_VALUE_STYLESHEET)
        uptime_layout.addWidget(self._uptime_value)
        stats_card_layout.addLayout(uptime_layout)

        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.VLine)
        divider.setStyleSheet(HEADER_STATS_DIVIDER_STYLESHEET)
        stats_card_layout.addWidget(divider)

        packets_layout = QVBoxLayout()
        packets_layout.setSpacing(0)
        packets_layout.setContentsMargins(0, 0, 0, 0)

        packets_title = QLabel('Captured Packets')
        packets_title.setStyleSheet(STAT_CARD_TITLE_STYLESHEET)
        packets_layout.addWidget(packets_title)

        self._packets_value = QLabel('0')
        self._packets_value.setStyleSheet(STAT_CARD_VALUE_STYLESHEET)
        packets_layout.addWidget(self._packets_value)
        stats_card_layout.addLayout(packets_layout)

        right_layout.addWidget(stats_card)

        main_layout.addLayout(right_layout, 0, 2, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        main_layout.setColumnStretch(0, 1)
        main_layout.setColumnStretch(1, 0)
        main_layout.setColumnStretch(2, 1)

        self.sync_notification_buttons(
            visual_enabled=Settings.visual_notifications_enabled,
            voice_enabled=Settings.voice_notifications_enabled,
        )

    def sync_notification_buttons(self, *, visual_enabled: bool, voice_enabled: bool) -> None:
        """Update visual and voice quick-toggle button icons, styles, and tooltips."""
        icon_px = scale_by_ui(16)
        all_hint = 'Mute all notifications' if (visual_enabled or voice_enabled) else 'Enable all notifications'

        self._visual_btn.setIcon(
            render_svg_icon_from_resource('bell.svg' if visual_enabled else 'bell-off.svg', icon_px, icon_px, '#22c55e' if visual_enabled else '#f87171'),
        )
        self._visual_btn.setStyleSheet(HEADER_NOTIFICATION_BUTTON_ENABLED_STYLESHEET if visual_enabled else HEADER_NOTIFICATION_BUTTON_MUTED_STYLESHEET)
        visual_status = 'Enabled' if visual_enabled else 'Muted'
        visual_action = 'Mute visual popup notifications' if visual_enabled else 'Enable visual popup notifications'
        self._visual_btn.setToolTip(f'Visual Notifications: {visual_status}\nLeft-click: {visual_action}\nRight-click: {all_hint}')

        self._voice_btn.setIcon(
            render_svg_icon_from_resource('volume-2.svg' if voice_enabled else 'volume-x.svg', icon_px, icon_px, '#22c55e' if voice_enabled else '#f87171'),
        )
        self._voice_btn.setStyleSheet(HEADER_NOTIFICATION_BUTTON_ENABLED_STYLESHEET if voice_enabled else HEADER_NOTIFICATION_BUTTON_MUTED_STYLESHEET)
        voice_status = 'Enabled' if voice_enabled else 'Muted'
        voice_action = 'Mute voice notifications' if voice_enabled else 'Enable voice notifications'
        self._voice_btn.setToolTip(f'Voice Notifications: {voice_status}\nLeft-click: {voice_action}\nRight-click: {all_hint}')

    def _populate_searchable_columns(self) -> None:
        """Populate the column chooser with All Columns and common searchable columns."""
        self.search_combo.clear()
        self.search_combo.addItem('All Columns')

        seen_columns: set[str] = set()
        candidate_columns: Sequence[str] = (*Settings.GUI_ALL_CONNECTED_COLUMNS, *Settings.GUI_ALL_DISCONNECTED_COLUMNS)
        for column_name in candidate_columns:
            if column_name not in SEARCHABLE_COLUMN_EXCLUSIONS and column_name not in seen_columns:
                seen_columns.add(column_name)
                self.search_combo.addItem(column_name)

    def focus_search(self) -> None:
        """Focus the global search input and select all current query text."""
        self.search_bar.setFocus()
        self.search_bar.selectAll()

    def set_search_placeholder_merged(self, *, is_merged: bool) -> None:
        """Update search placeholder and tooltip based on whether tables are merged."""
        if is_merged:
            self.search_bar.setPlaceholderText('Search players...')
            self.search_combo.setToolTip('Filter search to a specific column')
        else:
            self.search_bar.setPlaceholderText('Search connected + disconnected players...')
            self.search_combo.setToolTip('Filter search to a specific column across both tables')

    def set_capture_running(self, *, is_running: bool) -> None:
        """Toggle the visibility of the capture stopped badge."""
        self._stopped_badge.setVisible(not is_running)

    def update_stats(self, *, uptime_seconds: int, total_packets: int) -> None:
        """Update the live uptime and captured packet count card labels."""
        hours = uptime_seconds // 3600
        minutes = (uptime_seconds % 3600) // 60
        seconds = uptime_seconds % 60
        self._uptime_value.setText(f'{hours:02d}:{minutes:02d}:{seconds:02d}')
        self._packets_value.setText(f'{total_packets:,}')

    def _on_search_query_changed(self, text: str) -> None:
        selected_column = self.search_combo.currentText()
        self.search_changed.emit(text.strip(), selected_column)

    def _on_search_column_changed(self, _index: int) -> None:
        text = self.search_bar.text().strip()
        selected_column = self.search_combo.currentText()
        self.search_changed.emit(text, selected_column)
