"""User-friendly process selector widget for SettingsDialog."""

from typing import override

from PySide6.QtCore import QEvent, QObject, QSignalBlocker, Qt
from PySide6.QtGui import QIcon, QKeyEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QPushButton,
    QWidget,
)

from session_sniffer.capture.process import get_running_applications
from session_sniffer.capture.process_monitor import ensure_process_monitor_running
from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.guis._settings_widget_builders import format_setting_tooltip
from session_sniffer.guis.target_process_dialog import TargetProcessDialog
from session_sniffer.guis.utils import get_process_icon
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import SettingMeta, Settings


class _ProcessComboBoxViewFilter(QObject):
    """Event filter for process combo box popup view that scrolls keyboard search matches to the top."""

    @override
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        """Intercept key presses on the popup view to scroll matching process to top of viewport."""
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
    """Custom combo box preserving native view styling while scrolling active/searched items to top."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._view_filter = _ProcessComboBoxViewFilter(self.view())
        self.view().installEventFilter(self._view_filter)

    @override
    def showPopup(self) -> None:
        """Show popup and scroll active selection to top of viewport."""
        super().showPopup()
        current_index = self.view().currentIndex()
        if current_index.isValid() and current_index.row() > 0:
            self.view().scrollTo(current_index, QAbstractItemView.ScrollHint.PositionAtTop)


class ProcessSelectorWidget(QWidget):
    """Composite widget combining a friendly process dropdown with a browse dialog button."""

    def __init__(self, parent: QWidget | None = None, meta: SettingMeta | None = None) -> None:
        """Initialize the process selector widget."""
        super().__init__(parent)
        self._setting_tooltip: str | None = format_setting_tooltip(meta) if meta is not None else None

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self._combo = _ProcessComboBox(self)
        self._combo.setMinimumWidth(240)
        self._combo.currentIndexChanged.connect(self._update_combo_tooltip)
        layout.addWidget(self._combo, 1)

        browse_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'target.svg'))
        self._browse_button = QPushButton(browse_icon, ' Select Process…', self)
        self._browse_button.setToolTip('Select a running game or application.')
        self._browse_button.clicked.connect(self._on_browse_clicked)
        layout.addWidget(self._browse_button)

        refresh_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh.svg'))
        self._refresh_button = QPushButton(refresh_icon, '', self)
        self._refresh_button.setToolTip('Refresh running processes list.')
        self._refresh_button.clicked.connect(self.refresh_process_list)
        layout.addWidget(self._refresh_button)

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

    def _update_combo_tooltip(self) -> None:
        """Update the combo box tooltip to reflect the selected process details and setting explanation."""
        current_index = self._combo.currentIndex()
        item_tooltip = self._combo.itemData(current_index, Qt.ItemDataRole.ToolTipRole) if current_index > 0 else None

        tooltip_parts: list[str] = []
        if isinstance(item_tooltip, str) and item_tooltip:
            tooltip_parts.append(item_tooltip)
        if self._setting_tooltip is not None and self._setting_tooltip:
            tooltip_parts.append(self._setting_tooltip)

        self._combo.setToolTip('\n\n'.join(tooltip_parts))

    def refresh_process_list(self) -> None:
        """Refresh the running processes list in the combo box while maintaining the current selection."""
        if not CaptureState.is_local_capture():
            globe_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'globe.svg'))
            with QSignalBlocker(self._combo):
                self._combo.clear()
                self._combo.addItem(globe_icon, 'Disabled (External Device Capture)', 0)
                self._combo.setCurrentIndex(0)
            self.setEnabled(False)
            disabled_tooltip = 'Process PID sniffing is disabled when capturing an external device (ARP spoofing / neighbour capture).'
            self._combo.setToolTip(disabled_tooltip)
            return

        current_pid = self.value()
        globe_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'globe.svg'))
        warning_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'warning.svg'))

        with QSignalBlocker(self._combo):
            self._combo.clear()

            # Item 0 is always Disabled (All Traffic)
            self._combo.addItem(globe_icon, 'Disabled (Sniff All Traffic)', 0)
            self._combo.setItemData(0, 'Capture all network traffic without process filtering.', Qt.ItemDataRole.ToolTipRole)

            processes = get_running_applications(user_apps_only=True)
            found_current = False

            for pid, name, exe_path in processes:
                display_text = f'{name} (PID: {pid})'
                icon = get_process_icon(exe_path)
                self._combo.addItem(icon, display_text, pid)
                item_index = self._combo.count() - 1
                item_tooltip = f'{name} (PID: {pid})\n{exe_path}' if exe_path else f'{name} (PID: {pid})'
                self._combo.setItemData(item_index, item_tooltip, Qt.ItemDataRole.ToolTipRole)
                self._combo.setItemData(item_index, name, Qt.ItemDataRole.UserRole + 1)
                if pid == current_pid > 0:
                    found_current = True

            # If current PID was set to a process that is not running right now, append it so setting is preserved
            if not found_current and current_pid > 0:
                tracked_name = Settings.capture_filter_process_name
                display_text = f'{tracked_name} (PID: {current_pid} - Not Running)' if tracked_name is not None else f'Process PID {current_pid} (Not Running)'
                self._combo.addItem(warning_icon, display_text, current_pid)
                not_running_index = self._combo.count() - 1
                self._combo.setItemData(not_running_index, display_text, Qt.ItemDataRole.ToolTipRole)
                if tracked_name is not None:
                    self._combo.setItemData(not_running_index, tracked_name, Qt.ItemDataRole.UserRole + 1)
            elif not found_current and current_pid <= 0 and Settings.capture_filter_process_track_by_name and Settings.capture_filter_process_name is not None:
                tracked_name = Settings.capture_filter_process_name
                display_text = f'{tracked_name} (Not Running)'
                self._combo.addItem(warning_icon, display_text, 0)
                not_running_index = self._combo.count() - 1
                self._combo.setItemData(not_running_index, f'{tracked_name} (Waiting to launch)', Qt.ItemDataRole.ToolTipRole)
                self._combo.setItemData(not_running_index, tracked_name, Qt.ItemDataRole.UserRole + 1)

            self.set_value(current_pid)

        self._update_combo_tooltip()

    def value(self) -> int:
        """Return the currently selected PID (0 for Disabled, or PID > 0)."""
        combo_data = self._combo.currentData()
        return combo_data if isinstance(combo_data, int) else 0

    def process_name(self) -> str | None:
        """Return the currently selected process name (or None)."""
        current_index = self._combo.currentIndex()
        if current_index <= 0:
            return None
        data = self._combo.itemData(current_index, Qt.ItemDataRole.UserRole + 1)
        return str(data) if data is not None else None

    def set_value(self, pid: int, process_name: str | None = None) -> None:
        """Set the selected PID in the combo box."""
        target_name = process_name or Settings.capture_filter_process_name
        for index in range(self._combo.count()):
            if self._combo.itemData(index) == pid:
                if not pid and index > 0:
                    if target_name is not None and self._combo.itemData(index, Qt.ItemDataRole.UserRole + 1) == target_name:
                        self._combo.setCurrentIndex(index)
                        self._update_combo_tooltip()
                        return
                    continue
                self._combo.setCurrentIndex(index)
                self._update_combo_tooltip()
                return

        # If PID is not in combo, add it and select
        if pid > 0:
            warning_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'warning.svg'))
            display_text = f'{target_name} (PID: {pid} - Not Running)' if target_name is not None else f'Process PID {pid} (Not Running)'
            self._combo.addItem(warning_icon, display_text, pid)
            item_index = self._combo.count() - 1
            self._combo.setItemData(item_index, display_text, Qt.ItemDataRole.ToolTipRole)
            if target_name is not None:
                self._combo.setItemData(item_index, target_name, Qt.ItemDataRole.UserRole + 1)
            self._combo.setCurrentIndex(item_index)
        elif target_name is not None and Settings.capture_filter_process_track_by_name:
            warning_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'warning.svg'))
            display_text = f'{target_name} (Not Running)'
            self._combo.addItem(warning_icon, display_text, 0)
            item_index = self._combo.count() - 1
            self._combo.setItemData(item_index, f'{target_name} (Waiting to launch)', Qt.ItemDataRole.ToolTipRole)
            self._combo.setItemData(item_index, target_name, Qt.ItemDataRole.UserRole + 1)
            self._combo.setCurrentIndex(item_index)
        else:
            self._combo.setCurrentIndex(0)
        self._update_combo_tooltip()

    def _on_browse_clicked(self) -> None:
        """Open the target process selection dialog and update combo if changed."""
        if not CaptureState.is_local_capture():
            return
        dialog = TargetProcessDialog(self)
        if dialog.exec():
            selected_pid = dialog.selected_pid
            selected_name = dialog.selected_process_name
            Settings.capture_filter_process_pid = selected_pid
            Settings.capture_filter_process_name = selected_name
            ensure_process_monitor_running()
            self.refresh_process_list()
            self.set_value(selected_pid, selected_name)
