"""User-friendly process selector widget for SettingsDialog."""

from typing import override

from PySide6.QtCore import QEvent, QObject, QSignalBlocker, Qt, Signal
from PySide6.QtGui import QIcon, QKeyEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.capture.process import (
    get_process_image_path,
    get_running_applications,
    is_process_running,
    matches_process_name,
)
from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.guis._settings_widget_builders import format_setting_tooltip
from session_sniffer.guis.target_process_dialog import TargetProcessDialog
from session_sniffer.guis.utils import get_process_icon, render_svg_icon_from_resource
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import SettingMeta, Settings

_PROCESS_NAME_ROLE = Qt.ItemDataRole.UserRole + 1
_NON_RUNNING_ITEM_ROLE = Qt.ItemDataRole.UserRole + 2


class _ProcessComboBoxViewFilter(QObject):
    """Scroll a searched process to the top of the process list."""

    @override
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if event.type() == QEvent.Type.KeyPress and isinstance(event, QKeyEvent):
            text = event.text()
            if text and text.isprintable() and isinstance(watched, QAbstractItemView):
                watched.keyPressEvent(event)
                current_index = watched.currentIndex()
                if current_index.isValid() and current_index.row() > 0:
                    watched.scrollTo(current_index, QAbstractItemView.ScrollHint.PositionAtTop)
                return True
        return super().eventFilter(watched, event)


class _ProcessComboBox(QComboBox):
    """Process dropdown with a visible, per-pixel scroll bar."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._view_filter = _ProcessComboBoxViewFilter(self.view())
        self.view().installEventFilter(self._view_filter)
        self.view().setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.view().setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

    @override
    def showPopup(self) -> None:
        super().showPopup()
        current_index = self.view().currentIndex()
        if current_index.isValid() and current_index.row() > 0:
            self.view().scrollTo(current_index, QAbstractItemView.ScrollHint.PositionAtTop)


class ProcessSelectorWidget(QWidget):
    """Capture-scope control with a built-in process list and compact advanced picker."""

    process_selection_applied = Signal()
    process_target_changed = Signal()

    def __init__(self, parent: QWidget | None = None, meta: SettingMeta | None = None) -> None:
        """Initialize the process selector widget."""
        super().__init__(parent)
        self._setting_tooltip: str | None = format_setting_tooltip(meta) if meta is not None else None
        self._selected_pid = Settings.capture_filter_process_pid
        self._selected_name: str | None = Settings.capture_filter_process_name
        self._track_by_name = Settings.capture_filter_process_track_by_name
        self._specific_process_requested = self._selected_pid > 0 or (self._track_by_name and bool(self._selected_name))
        self._stashed_untracked_target: tuple[int, str | None] | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)

        scope_layout = QHBoxLayout()
        scope_layout.setContentsMargins(0, 0, 0, 0)
        scope_layout.setSpacing(6)
        self._scope_button_group = QButtonGroup(self)
        self._scope_button_group.setExclusive(True)
        scope_button_style = (
            'QPushButton#captureScopeButton { padding: 5px 14px; }'
            'QPushButton#captureScopeButton:checked { background-color: #347fa8; color: #ffffff; border: 1px solid #61b2df; }'
            'QPushButton#captureScopeButton:checked:hover { background-color: #3c91bd; }'
        )

        self._all_traffic_button = QPushButton('All Traffic', self)
        self._all_traffic_button.setCheckable(True)
        self._all_traffic_button.setObjectName('captureScopeButton')
        self._all_traffic_button.setMinimumWidth(120)
        self._all_traffic_button.setStyleSheet(scope_button_style)
        self._all_traffic_button.setToolTip('Capture all network traffic without filtering by process.')
        self._scope_button_group.addButton(self._all_traffic_button, 0)
        scope_layout.addWidget(self._all_traffic_button)

        self._specific_process_button = QPushButton('Specific Process', self)
        self._specific_process_button.setCheckable(True)
        self._specific_process_button.setObjectName('captureScopeButton')
        self._specific_process_button.setMinimumWidth(140)
        self._specific_process_button.setStyleSheet(scope_button_style)
        self._specific_process_button.setToolTip('Choose a running process and capture its network traffic.')
        self._scope_button_group.addButton(self._specific_process_button, 1)
        scope_layout.addWidget(self._specific_process_button)
        scope_layout.addStretch()
        layout.addLayout(scope_layout)

        process_layout = QHBoxLayout()
        process_layout.setContentsMargins(0, 0, 0, 0)
        process_layout.setSpacing(6)
        self._process_row = QWidget(self)
        self._process_row.setLayout(process_layout)

        self._process_label = QLabel('Target Process:')
        self._process_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._process_label.setMinimumWidth(120)
        process_layout.addWidget(self._process_label)

        self._combo = _ProcessComboBox(self)
        self._combo.setMinimumWidth(240)
        self._combo.setPlaceholderText('Select a process…')
        self._combo.currentIndexChanged.connect(self._on_combo_index_changed)
        process_layout.addWidget(self._combo, 1)

        browse_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'target.svg'))
        self._browse_button = QPushButton(browse_icon, '', self)
        self._browse_button.setAccessibleName('Open advanced process selector')
        self._browse_button.setToolTip('Open the advanced process selector.')
        self._browse_button.setFlat(True)
        self._browse_button.setFixedSize(34, 34)
        self._browse_button.clicked.connect(self._on_browse_clicked)
        process_layout.addWidget(self._browse_button)

        refresh_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh-cw.svg'))
        self._refresh_button = QPushButton(refresh_icon, '', self)
        self._refresh_button.setToolTip('Refresh running processes list.')
        self._refresh_button.setFixedSize(34, 34)
        self._refresh_button.clicked.connect(self.refresh_process_list)
        process_layout.addWidget(self._refresh_button)
        process_layout.addStretch()
        layout.addWidget(self._process_row)

        self._all_traffic_button.clicked.connect(self._on_sniff_all_traffic_clicked)
        self._specific_process_button.clicked.connect(self._on_specific_process_clicked)

        if self._setting_tooltip is not None:
            self.setToolTip(self._setting_tooltip)

        if not CaptureState.is_local_capture():
            self.setEnabled(False)
            disabled_tooltip = 'Process PID sniffing is disabled when capturing an external device (ARP spoofing / neighbour capture).'
            self.setToolTip(disabled_tooltip)
            self._combo.setToolTip(disabled_tooltip)
            self._browse_button.setToolTip(disabled_tooltip)
            self._refresh_button.setToolTip(disabled_tooltip)
        self.refresh_process_list()

    def _on_combo_index_changed(self) -> None:
        """Update the selected process and capture scope after a dropdown selection."""
        self._stashed_untracked_target = None
        self._selected_pid = self.value()
        self._selected_name = self.process_name()
        if self._selected_pid > 0 or (self._track_by_name and self._selected_name is not None):
            self._specific_process_requested = True
        self.sync_scope_state()
        self.process_target_changed.emit()

    def _update_combo_tooltip(self) -> None:
        """Combine selected process details with the setting explanation."""
        current_index = self._combo.currentIndex()
        item_tooltip = self._combo.itemData(current_index, Qt.ItemDataRole.ToolTipRole) if current_index >= 0 else None
        tooltip_parts: list[str] = []
        if isinstance(item_tooltip, str) and item_tooltip:
            tooltip_parts.append(item_tooltip)
        if self._setting_tooltip is not None and self._setting_tooltip:
            tooltip_parts.append(self._setting_tooltip)
        self._combo.setToolTip('\n\n'.join(tooltip_parts))

    def refresh_process_list(self) -> None:
        """Refresh running processes while preserving the current selection."""
        if not CaptureState.is_local_capture():
            with QSignalBlocker(self._combo):
                self._combo.clear()
                self._combo.setPlaceholderText('Disabled (External Device Capture)')
                self._combo.setCurrentIndex(-1)
            self.setEnabled(False)
            self.sync_scope_state()
            return

        current_pid = self._selected_pid
        current_name = self._selected_name
        scope_was_requested = self._specific_process_requested
        stashed_target = self._stashed_untracked_target
        with QSignalBlocker(self._combo):
            self._combo.clear()
            for pid, name, exe_path in get_running_applications(user_apps_only=True):
                self._combo.addItem(get_process_icon(exe_path), f'{name} (PID: {pid})', pid)
                index = self._combo.count() - 1
                item_tooltip = f'{name} (PID: {pid})\n{exe_path}' if exe_path else f'{name} (PID: {pid})'
                self._combo.setItemData(index, item_tooltip, Qt.ItemDataRole.ToolTipRole)
                self._combo.setItemData(index, name, _PROCESS_NAME_ROLE)

            self.set_value(current_pid, current_name)
            if self.value() <= 0:
                self._stashed_untracked_target = stashed_target
            if current_pid <= 0 and current_name is None and scope_was_requested:
                self._specific_process_requested = True
                self.sync_scope_state()
        self._update_combo_tooltip()

    def _find_combo_index_by_name(self, target_name: str) -> int:
        """Return the combo index of a running process matching *target_name*."""
        for index in range(self._combo.count()):
            item_pid = self._combo.itemData(index)
            if not (isinstance(item_pid, int) and item_pid > 0):
                continue
            item_name = self._combo.itemData(index, _PROCESS_NAME_ROLE)
            if isinstance(item_name, str) and matches_process_name(item_name, target_name):
                return index
        for bg_pid, bg_name, bg_exe_path in get_running_applications(user_apps_only=False):
            if matches_process_name(bg_name, target_name):
                display_text = f'{bg_name} (PID: {bg_pid})'
                self._combo.addItem(get_process_icon(bg_exe_path), display_text, bg_pid)
                matched_index = self._combo.count() - 1
                item_tooltip = f'{display_text}\n{bg_exe_path}' if bg_exe_path else display_text
                self._combo.setItemData(matched_index, item_tooltip, Qt.ItemDataRole.ToolTipRole)
                self._combo.setItemData(matched_index, bg_name, _PROCESS_NAME_ROLE)
                return matched_index
        return -1

    @property
    def track_by_name(self) -> bool:
        """Return whether executable-name tracking is enabled."""
        return self._track_by_name

    def value(self) -> int:
        """Return the currently selected PID (0 when sniffing all traffic)."""
        combo_data = self._combo.currentData()
        return combo_data if isinstance(combo_data, int) else 0

    def process_name(self) -> str | None:
        """Return the selected process name, if name tracking is configured."""
        current_index = self._combo.currentIndex()
        if current_index < 0:
            return None
        data = self._combo.itemData(current_index, _PROCESS_NAME_ROLE)
        return str(data) if data is not None else None

    def set_value(
        self,
        pid: int,
        process_name: str | None = None,
        *,
        track_by_name: bool | None = None,
    ) -> None:
        """Set the selected process in the built-in dropdown."""
        self._stashed_untracked_target = None
        if track_by_name is not None:
            self._track_by_name = track_by_name
        if not CaptureState.is_local_capture():
            with QSignalBlocker(self._combo):
                self._combo.clear()
                self._combo.setPlaceholderText('Disabled (External Device Capture)')
                self._combo.setCurrentIndex(-1)
            self._selected_pid = 0
            self._selected_name = None
            self._specific_process_requested = False
            self.setEnabled(False)
            self.sync_scope_state()
            self._update_combo_tooltip()
            return

        target_name = process_name
        self._selected_pid = max(0, pid)
        self._selected_name = target_name
        self._specific_process_requested = self._selected_pid > 0 or (self._track_by_name and bool(target_name))
        with QSignalBlocker(self._combo):
            for index in range(self._combo.count() - 1, -1, -1):
                if bool(self._combo.itemData(index, _NON_RUNNING_ITEM_ROLE)):
                    self._combo.removeItem(index)

            if pid > 0:
                matched_index = -1
                for index in range(self._combo.count()):
                    if self._combo.itemData(index) == pid:
                        item_name = self._combo.itemData(index, _PROCESS_NAME_ROLE)
                        if (
                            target_name is not None
                            and isinstance(item_name, str)
                            and not matches_process_name(item_name, target_name)
                        ):
                            continue
                        matched_index = index
                        break
                if matched_index < 0 and is_process_running(pid):
                    image_path = get_process_image_path(pid)
                    exe_path = str(image_path) if image_path is not None else ''
                    actual_name = image_path.name if image_path is not None else None
                    if (
                        target_name is None
                        or (actual_name is not None and matches_process_name(actual_name, target_name))
                    ):
                        resolved_name = actual_name or target_name
                        display_text = f'{resolved_name} (PID: {pid})' if resolved_name is not None else f'Process PID {pid}'
                        self._combo.addItem(get_process_icon(exe_path), display_text, pid)
                        matched_index = self._combo.count() - 1
                        item_tooltip = f'{display_text}\n{exe_path}' if exe_path else display_text
                        self._combo.setItemData(matched_index, item_tooltip, Qt.ItemDataRole.ToolTipRole)
                        if resolved_name is not None:
                            self._combo.setItemData(matched_index, resolved_name, _PROCESS_NAME_ROLE)
                if matched_index < 0:
                    if self._track_by_name and target_name is not None:
                        pid = 0
                    else:
                        warning_icon = render_svg_icon_from_resource('triangle-alert.svg', 16, 16, '#f59e0b')
                        display_text = f'{target_name} (PID: {pid} - Not Running)' if target_name is not None else f'Process PID {pid} (Not Running)'
                        self._combo.addItem(warning_icon, display_text, pid)
                        matched_index = self._combo.count() - 1
                        self._combo.setItemData(matched_index, display_text, Qt.ItemDataRole.ToolTipRole)
                        self._combo.setItemData(matched_index, 1, _NON_RUNNING_ITEM_ROLE)
                        if target_name is not None:
                            self._combo.setItemData(matched_index, target_name, _PROCESS_NAME_ROLE)
                if pid > 0:
                    self._combo.setCurrentIndex(matched_index)
                    self._selected_pid = self.value()
                    self._selected_name = self.process_name()
                    self._specific_process_requested = True

            if pid <= 0:
                if target_name is not None and self._track_by_name:
                    matched_index = self._find_combo_index_by_name(target_name)
                    if matched_index < 0:
                        warning_icon = render_svg_icon_from_resource('triangle-alert.svg', 16, 16, '#f59e0b')
                        self._combo.addItem(warning_icon, f'{target_name} (Not Running)', 0)
                        matched_index = self._combo.count() - 1
                        self._combo.setItemData(matched_index, f'{target_name} (Waiting to launch)', Qt.ItemDataRole.ToolTipRole)
                        self._combo.setItemData(matched_index, target_name, _PROCESS_NAME_ROLE)
                        self._combo.setItemData(matched_index, 1, _NON_RUNNING_ITEM_ROLE)
                    self._combo.setCurrentIndex(matched_index)
                    self._selected_pid = self.value()
                    self._selected_name = self.process_name()
                    self._specific_process_requested = True
                else:
                    self._combo.setCurrentIndex(-1)
                    self._selected_pid = 0
                    self._selected_name = None
        self.sync_scope_state()
        self._update_combo_tooltip()
        self.process_target_changed.emit()

    def sync_scope_state(self, *, track_by_name: bool | None = None) -> None:
        """Keep the scope selection and process controls in sync with the current target."""
        if track_by_name is not None:
            self._track_by_name = track_by_name
            current_index = self._combo.currentIndex()
            if track_by_name:
                if (
                    current_index >= 0
                    and bool(self._combo.itemData(current_index, _NON_RUNNING_ITEM_ROLE))
                    and self.value() > 0
                    and self._selected_name is not None
                ):
                    stashed_target = (self._selected_pid, self._selected_name)
                    self.set_value(self._selected_pid, self._selected_name)
                    if self.value() <= 0:
                        self._stashed_untracked_target = stashed_target
                    return
                if (
                    self.value() <= 0
                    and current_index < 0
                    and self._stashed_untracked_target is not None
                ):
                    stashed_pid, stashed_name = self._stashed_untracked_target
                    self._stashed_untracked_target = None
                    self.set_value(stashed_pid, stashed_name)
                    return
            else:
                cleared_zero_pid_selection = self.value() <= 0 and (
                    current_index >= 0 or self._selected_name is not None
                )
                if cleared_zero_pid_selection:
                    if (
                        self._stashed_untracked_target is not None
                        and self._stashed_untracked_target[0] > 0
                        and self._stashed_untracked_target[1] == self._selected_name
                    ):
                        stashed_pid, stashed_name = self._stashed_untracked_target
                        self._stashed_untracked_target = None
                        self.set_value(stashed_pid, stashed_name)
                        return
                    if self._selected_name is not None:
                        self._stashed_untracked_target = (0, self._selected_name)
                    self._specific_process_requested = False
                    self._selected_name = None
                with QSignalBlocker(self._combo):
                    if cleared_zero_pid_selection:
                        self._combo.setCurrentIndex(-1)
                    for index in range(self._combo.count() - 1, -1, -1):
                        if not self._combo.itemData(index):
                            self._combo.removeItem(index)
                if cleared_zero_pid_selection:
                    self._update_combo_tooltip()
                    self.process_target_changed.emit()
        process_selected = self._specific_process_requested or self.value() > 0 or (
            self._track_by_name and self.process_name() is not None
        )
        with QSignalBlocker(self._scope_button_group):
            self._specific_process_button.setChecked(process_selected)
            self._all_traffic_button.setChecked(not process_selected)
        self._process_row.setVisible(process_selected)
        self._browse_button.setEnabled(CaptureState.is_local_capture())

    def _on_sniff_all_traffic_clicked(self) -> None:
        """Clear process selection so capture includes traffic from every process."""
        self._stashed_untracked_target = None
        self._specific_process_requested = False
        self._selected_name = None
        self.set_value(0)
        self.sync_scope_state()

    def _on_specific_process_clicked(self) -> None:
        """Enable process-specific capture controls without opening the advanced picker."""
        self._specific_process_requested = True
        self.sync_scope_state()

    def _on_browse_clicked(self) -> None:
        """Open the target process selection dialog and update combo if changed."""
        if not CaptureState.is_local_capture():
            return
        dialog = TargetProcessDialog(
            self,
            initial_pid=self.value(),
            initial_process_name=self.process_name(),
            initial_track_by_name=self._track_by_name,
        )
        if not dialog.exec():
            return
        self._stashed_untracked_target = None
        self._selected_pid = dialog.selected_pid
        self._selected_name = dialog.selected_process_name
        self._track_by_name = dialog.selected_track_by_name
        self.refresh_process_list()
        self.process_selection_applied.emit()
        self.sync_scope_state()
