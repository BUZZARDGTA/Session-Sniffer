"""Logs Manager dialog — main entry point combining all log tabs."""
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import (
    DETECTION_LOGGING_PATH,
    ERRORS_LOG_PATH,
    PROTECTION_LOGGING_PATH,
    SESSIONS_LOGGING_DIR_PATH,
    USERIP_LOGGING_PATH,
    WARNINGS_LOG_PATH,
)
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.logs_manager._csv_tab import CsvLogTab, CsvLogTabConfig
from session_sniffer.guis.logs_manager._helpers import backup_file
from session_sniffer.guis.logs_manager._sessions_tab import SessionsLogTab
from session_sniffer.guis.logs_manager._text_tab import TextLogTab
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET
from session_sniffer.guis.utils import set_dialog_window_flags


class LogsManager(QDialog):
    """Modal dialog for viewing, searching, filtering, and managing application log files."""

    def __init__(self, parent: QWidget | None) -> None:
        """Build the Logs Manager dialog with tabs for each log file type."""
        super().__init__(parent)
        self.setWindowTitle(f'Logs Manager - {TITLE}')
        set_dialog_window_flags(self)
        self.setMinimumSize(1000, 600)
        self.resize(1100, 700)

        root_layout = QVBoxLayout(self)

        # --- Tab widget ---
        tabs = QTabWidget()

        self._userip_tab = CsvLogTab(
            CsvLogTabConfig(
                file_path=USERIP_LOGGING_PATH,
                expected_headers=('Database', 'Username', 'IP', 'Date', 'Time', 'Country'),
                default_sort_columns=('Date', 'Time'),
                stretch_column=1,
                column_min_widths={5: 160},
            ),
        )
        tabs.addTab(self._userip_tab, '📄 UserIP Logging')

        self._detection_tab = CsvLogTab(
            CsvLogTabConfig(
                file_path=DETECTION_LOGGING_PATH,
                expected_headers=('Detection', 'Username', 'IP', 'Date', 'Time', 'Country'),
                default_sort_columns=('Date', 'Time'),
                stretch_column=1,
                column_min_widths={0: 220, 5: 160},
            ),
        )
        tabs.addTab(self._detection_tab, '🔍 Detection Logging')
        self._protection_tab = CsvLogTab(
            CsvLogTabConfig(
                file_path=PROTECTION_LOGGING_PATH,
                expected_headers=('Detection', 'Username', 'IP', 'Date', 'Time', 'Country'),
                default_sort_columns=('Date', 'Time'),
                stretch_column=1,
                column_min_widths={0: 220, 5: 160},
            ),
        )
        tabs.addTab(self._protection_tab, '\U0001f6e1\ufe0f Protection Logging')
        self._warnings_tab = TextLogTab(file_path=WARNINGS_LOG_PATH)
        tabs.addTab(self._warnings_tab, '⚠️ Warnings Log')
        self._errors_tab = TextLogTab(file_path=ERRORS_LOG_PATH)
        tabs.addTab(self._errors_tab, '❌ Errors Log')
        self._sessions_tab = SessionsLogTab(sessions_dir=SESSIONS_LOGGING_DIR_PATH)
        tabs.addTab(self._sessions_tab, '📂 Sessions Logging')

        root_layout.addWidget(tabs, stretch=1)

        # --- Bottom button row ---
        button_row = QHBoxLayout()
        button_row.addStretch()

        purge_all_button = QPushButton('🗑️ Purge All Logs')
        purge_all_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        purge_all_button.setToolTip('Clear ALL log files at once (creates backups first)')
        purge_all_button.clicked.connect(self.purge_all_logs)
        button_row.addWidget(purge_all_button)

        close_button = QPushButton('\u2716 Close')
        close_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        close_button.setToolTip('Close the Logs Manager')
        close_button.clicked.connect(self.close)
        button_row.addWidget(close_button)

        root_layout.addLayout(button_row)

    # ------------------------------------------------------------------
    # Purge all
    # ------------------------------------------------------------------

    def purge_all_logs(self) -> None:
        """Purge all CSV log files, warnings.log, and errors.log after strong confirmation."""
        reply = QMessageBox.warning(
            self, TITLE,
            'This will purge ALL log files:\n\n'
            '  • UserIP_Logging.csv\n'
            '  • Detection_Logging.csv\n'
            '  • Protection_Logging.csv\n'
            '  • warnings.log\n'
            '  • errors.log\n\n'
            'Backups (.bak) will be created first.\n'
            'Are you sure?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        purged: list[str] = []
        errors: list[str] = []

        for path in (USERIP_LOGGING_PATH, DETECTION_LOGGING_PATH, PROTECTION_LOGGING_PATH, WARNINGS_LOG_PATH, ERRORS_LOG_PATH):
            if not path.exists():
                continue
            backup_file(path)
            path.write_text('', encoding='utf-8')
            purged.append(path.name)

        self._userip_tab.load_data()
        self._detection_tab.load_data()
        self._protection_tab.load_data()
        self._warnings_tab.load_data()
        self._errors_tab.load_data()

        parts: list[str] = []
        if purged:
            parts.append(f'Purged: {", ".join(purged)}')
        if errors:
            parts.append(f'Errors: {"; ".join(errors)}')
        if not parts:
            parts.append('No log files to purge.')

        QMessageBox.information(self, TITLE, '\n'.join(parts))
