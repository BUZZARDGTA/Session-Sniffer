"""Logs Manager dialog — main entry point combining all log tabs."""

from typing import TYPE_CHECKING, override

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import (
    CRASH_LOG_PATH,
    DEBUG_LOG_PATH,
    DETECTION_LOGGING_PATH,
    PROTECTION_LOGGING_PATH,
    RESOURCES_DIR_PATH,
    SESSIONS_LOGGING_DIR_PATH,
    USERIP_LOGGING_PATH,
)
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.logs_manager._csv_tab import CsvLogTab, CsvLogTabConfig
from session_sniffer.guis.logs_manager._helpers import backup_file
from session_sniffer.guis.logs_manager._sessions_tab import SessionsLogTab
from session_sniffer.guis.logs_manager._text_tab import TextLogTab
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET
from session_sniffer.guis.utils import consume_maximize_on_show, resize_window_for_screen, scale_by_ui, set_dialog_window_flags
from session_sniffer.logging_setup import purge_crash_log, purge_debug_log
from session_sniffer.rendering_core.renderer import SESSIONS_LOGGING_PATH
from session_sniffer.settings import Settings
from session_sniffer.utils import cleanup_session_logs

if TYPE_CHECKING:
    from PySide6.QtGui import QCloseEvent, QHideEvent, QShowEvent


class LogsManager(QDialog):
    """Non-modal dialog for viewing, searching, filtering, and managing application log files."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Build the Logs Manager dialog with tabs for each log file type."""
        super().__init__(parent)
        self.setWindowTitle(f'Logs Manager - {TITLE}')
        set_dialog_window_flags(self)
        self.setMinimumSize(scale_by_ui(880), scale_by_ui(520))
        resize_window_for_screen(self)

        root_layout = QVBoxLayout(self)

        # --- Tab widget ---
        tabs = QTabWidget()

        self._userip_tab = CsvLogTab(
            CsvLogTabConfig(
                file_path=USERIP_LOGGING_PATH,
                expected_headers=('Database', 'Usernames', 'IP', 'Date', 'Time', 'Country'),
                default_sort_columns=('Date', 'Time'),
                stretch_column=1,
                column_min_widths={5: 160},
            ),
        )
        tabs.addTab(self._userip_tab, QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'database.svg')), 'UserIP Logging')

        self._detection_tab = CsvLogTab(
            CsvLogTabConfig(
                file_path=DETECTION_LOGGING_PATH,
                expected_headers=('Detection', 'Usernames', 'IP', 'Date', 'Time', 'Country'),
                default_sort_columns=('Date', 'Time'),
                stretch_column=1,
                column_min_widths={0: 220, 5: 160},
            ),
        )
        tabs.addTab(self._detection_tab, QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'bell.svg')), 'Detection Logging')
        self._protection_tab = CsvLogTab(
            CsvLogTabConfig(
                file_path=PROTECTION_LOGGING_PATH,
                expected_headers=('Detection', 'Usernames', 'IP', 'Date', 'Time', 'Country'),
                default_sort_columns=('Date', 'Time'),
                stretch_column=1,
                column_min_widths={0: 220, 5: 160},
            ),
        )
        tabs.addTab(self._protection_tab, QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'shield.svg')), 'Protection Logging')
        self._sessions_tab = SessionsLogTab(sessions_dir=SESSIONS_LOGGING_DIR_PATH)
        tabs.addTab(self._sessions_tab, QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'Sessions Logging')
        self._debug_tab = TextLogTab(file_path=DEBUG_LOG_PATH, enable_severity_filter=True)
        tabs.addTab(self._debug_tab, QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'bug.svg')), 'Debug Log')
        self._crash_tab = TextLogTab(file_path=CRASH_LOG_PATH)
        tabs.addTab(self._crash_tab, QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'crash.svg')), 'Crash Log')

        self._tabs = tabs
        root_layout.addWidget(tabs, stretch=1)

        # --- Bottom button row ---
        button_row = QHBoxLayout()
        button_row.addStretch()

        purge_all_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), ' Purge All Logs')
        purge_all_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        purge_all_button.setToolTip('Clear ALL log files at once (creates backups first)')
        purge_all_button.clicked.connect(self.purge_all_logs)
        button_row.addWidget(purge_all_button)

        clean_empty_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'clear_all.svg')), ' Clean Empty Sessions')
        clean_empty_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        clean_empty_button.setToolTip('Delete empty session logs and empty folders (keeps active session)')
        clean_empty_button.clicked.connect(self.clean_empty_sessions)
        button_row.addWidget(clean_empty_button)

        close_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'close.svg')), ' Close')
        close_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        close_button.setToolTip('Close the Logs Manager')
        close_button.clicked.connect(self.close)
        button_row.addWidget(close_button)

        root_layout.addLayout(button_row)

    # ------------------------------------------------------------------
    # Programmatic search entry points
    # ------------------------------------------------------------------

    def search_in_userip_logging(self, text: str) -> None:
        """Switch to the UserIP Logging tab and apply `text` as the search filter."""
        self._tabs.setCurrentWidget(self._userip_tab)
        self._userip_tab.set_search(text)

    def search_in_sessions_logging(self, text: str) -> None:
        """Switch to the Sessions Logging tab and start a global search for `text`."""
        self._tabs.setCurrentWidget(self._sessions_tab)
        self._sessions_tab.set_search_global(text)

    def show_debug_log(self, severity: str | None = None) -> None:
        """Switch to the Debug Log tab, optionally applying a severity filter."""
        self._tabs.setCurrentWidget(self._debug_tab)
        if severity is not None:
            self._debug_tab.set_severity(severity)

    def show_crash_log(self) -> None:
        """Switch to the Crash Log tab."""
        self._tabs.setCurrentWidget(self._crash_tab)

    # ------------------------------------------------------------------
    # Clean empty sessions
    # ------------------------------------------------------------------

    def clean_empty_sessions(self) -> None:
        """Manually clean up empty session log files and empty directories."""
        files_deleted, folders_deleted = cleanup_session_logs(
            sessions_dir=SESSIONS_LOGGING_DIR_PATH,
            delete_empty_files=True,
            delete_empty_folders=True,
            gui_sessions_logging=Settings.gui_sessions_logging,
            active_session_path=SESSIONS_LOGGING_PATH.with_suffix('.json'),
        )
        QMessageBox.information(
            self,
            TITLE,
            f'Cleaned up empty session logs:\n\n  • Files deleted: {files_deleted}\n  • Folders deleted: {folders_deleted}',
        )

    # ------------------------------------------------------------------
    # Purge all
    # ------------------------------------------------------------------

    def purge_all_logs(self) -> None:
        """Purge all CSV log files, debug.log, and crash.log after strong confirmation."""
        reply = QMessageBox.warning(
            self,
            TITLE,
            'This will purge ALL log files:\n\n'
            '  • UserIP_Logging.csv\n'
            '  • Detection_Logging.csv\n'
            '  • Protection_Logging.csv\n'
            '  • debug.log\n'
            '  • crash.log\n\n'
            'Backups (.bak) will be created first.\n'
            'Are you sure?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        purged: list[str] = []
        errors: list[str] = []

        for path in (USERIP_LOGGING_PATH, DETECTION_LOGGING_PATH, PROTECTION_LOGGING_PATH, DEBUG_LOG_PATH, CRASH_LOG_PATH):
            if not path.exists():
                continue
            backup_file(path)
            if path == DEBUG_LOG_PATH:
                purge_debug_log()
            elif path == CRASH_LOG_PATH:
                purge_crash_log()
            else:
                path.write_text('', encoding='utf-8')
            purged.append(path.name)

        self._userip_tab.load_data()
        self._detection_tab.load_data()
        self._protection_tab.load_data()
        self._debug_tab.load_data()
        self._crash_tab.load_data()

        parts: list[str] = []
        if purged:
            parts.append(f'Purged: {", ".join(purged)}')
        if errors:
            parts.append(f'Errors: {"; ".join(errors)}')
        if not parts:
            parts.append('No log files to purge.')

        QMessageBox.information(self, TITLE, '\n'.join(parts))

    @override
    def showEvent(self, a0: QShowEvent) -> None:
        """Handle the window show event, maximize if required, and resume file watching."""
        super().showEvent(a0)
        if consume_maximize_on_show(self):
            self.showMaximized()
        self._start_all_watchers()

    @override
    def hideEvent(self, a0: QHideEvent) -> None:
        """Stop all background filesystem watchers when the dialog is hidden or closed."""
        self._stop_all_watchers()
        super().hideEvent(a0)

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Stop all background filesystem watchers when the dialog is closed."""
        self._stop_all_watchers()
        super().closeEvent(event)

    def _start_all_watchers(self) -> None:
        """Start filesystem watchers for all tabs."""
        self._userip_tab.start_watching()
        self._detection_tab.start_watching()
        self._protection_tab.start_watching()
        self._sessions_tab.start_watching()
        self._debug_tab.start_watching()
        self._crash_tab.start_watching()

    def _stop_all_watchers(self) -> None:
        """Stop filesystem watchers for all tabs."""
        self._userip_tab.stop_watching()
        self._detection_tab.stop_watching()
        self._protection_tab.stop_watching()
        self._sessions_tab.stop_watching()
        self._debug_tab.stop_watching()
        self._crash_tab.stop_watching()
