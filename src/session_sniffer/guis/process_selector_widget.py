"""User-friendly process selector widget for SettingsDialog."""

from PySide6.QtCore import QFileInfo, QSignalBlocker, Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QComboBox,
    QFileIconProvider,
    QHBoxLayout,
    QPushButton,
    QWidget,
)

from session_sniffer.capture.process import get_running_applications
from session_sniffer.capture.process_monitor import ensure_process_monitor_running
from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.guis._settings_widget_builders import format_setting_tooltip
from session_sniffer.guis.target_process_dialog import TargetProcessDialog
from session_sniffer.settings import SettingMeta, Settings


class ProcessSelectorWidget(QWidget):
    """Composite widget combining a friendly process dropdown with a browse dialog button."""

    def __init__(self, parent: QWidget | None = None, meta: SettingMeta | None = None) -> None:
        """Initialize the process selector widget."""
        super().__init__(parent)
        self._setting_tooltip: str | None = format_setting_tooltip(meta) if meta is not None else None

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self._combo = QComboBox(self)
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

        if self._setting_tooltip:
            self.setToolTip(self._setting_tooltip)

        self.refresh_process_list()

    def _update_combo_tooltip(self) -> None:
        """Update the combo box tooltip to reflect the selected process details and setting explanation."""
        current_index = self._combo.currentIndex()
        item_tooltip = self._combo.itemData(current_index, Qt.ItemDataRole.ToolTipRole) if current_index > 0 else None

        tooltip_parts: list[str] = []
        if isinstance(item_tooltip, str) and item_tooltip:
            tooltip_parts.append(item_tooltip)
        if self._setting_tooltip:
            tooltip_parts.append(self._setting_tooltip)

        self._combo.setToolTip('\n\n'.join(tooltip_parts))

    def refresh_process_list(self) -> None:
        """Refresh the running processes list in the combo box while maintaining the current selection."""
        current_pid = self.value()
        globe_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'globe.svg'))
        warning_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'warning.svg'))

        with QSignalBlocker(self._combo):
            self._combo.clear()

            # Item 0 is always Disabled (All Traffic)
            self._combo.addItem(globe_icon, 'Disabled (Sniff All Traffic)', 0)
            self._combo.setItemData(0, 'Capture all network traffic without process filtering.', Qt.ItemDataRole.ToolTipRole)

            processes = get_running_applications(user_apps_only=True)
            found_current = not current_pid
            provider = QFileIconProvider()
            default_file_icon = provider.icon(QFileIconProvider.IconType.File)
            icon_cache: dict[str, QIcon] = {}

            for pid, name, exe_path in processes:
                display_text = f'{name} (PID: {pid})'
                if exe_path and exe_path not in icon_cache:
                    file_info = QFileInfo(exe_path)
                    icon = provider.icon(file_info) if file_info.exists() else default_file_icon
                    icon_cache[exe_path] = default_file_icon if icon.isNull() else icon
                icon = icon_cache.get(exe_path, default_file_icon)
                self._combo.addItem(icon, display_text, pid)
                item_index = self._combo.count() - 1
                item_tooltip = f'{name} (PID: {pid})\n{exe_path}' if exe_path else f'{name} (PID: {pid})'
                self._combo.setItemData(item_index, item_tooltip, Qt.ItemDataRole.ToolTipRole)
                if pid == current_pid:
                    found_current = True

            # If current PID was set to a process that is not running right now, append it so setting is preserved
            if not found_current and current_pid > 0:
                self._combo.addItem(warning_icon, f'Process PID {current_pid} (Not Running)', current_pid)
                not_running_index = self._combo.count() - 1
                self._combo.setItemData(not_running_index, f'Process PID {current_pid} (Not Running)', Qt.ItemDataRole.ToolTipRole)

            self.set_value(current_pid)

        self._update_combo_tooltip()

    def value(self) -> int:
        """Return the currently selected PID (0 for Disabled, or PID > 0)."""
        combo_data = self._combo.currentData()
        return combo_data if isinstance(combo_data, int) else 0

    def set_value(self, pid: int) -> None:
        """Set the selected PID in the combo box."""
        for index in range(self._combo.count()):
            if self._combo.itemData(index) == pid:
                self._combo.setCurrentIndex(index)
                self._update_combo_tooltip()
                return

        # If PID is not in combo, add it and select
        if pid > 0:
            warning_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'warning.svg'))
            display_text = f'Process PID {pid} (Not Running)'
            self._combo.addItem(warning_icon, display_text, pid)
            item_index = self._combo.count() - 1
            self._combo.setItemData(item_index, f'Process PID {pid} (Not Running)', Qt.ItemDataRole.ToolTipRole)
            self._combo.setCurrentIndex(item_index)
        else:
            self._combo.setCurrentIndex(0)
        self._update_combo_tooltip()

    def _on_browse_clicked(self) -> None:
        """Open the target process selection dialog and update combo if changed."""
        dialog = TargetProcessDialog(self)
        if dialog.exec():
            selected_pid = dialog.selected_pid
            Settings.capture_filter_process_pid = selected_pid
            ensure_process_monitor_running()
            self.refresh_process_list()
            self.set_value(selected_pid)
