"""Logs Manager dialog — main entry point combining all log tabs."""

from functools import partial
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
    SESSIONS_LOGGING_DIR_PATH,
    USERIP_LOGGING_PATH,
)
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.live_language import register_language_refresh
from session_sniffer.guis.loading_overlay import run_async_with_loading
from session_sniffer.guis.logs_manager._csv_tab import CsvLogTab, CsvLogTabConfig
from session_sniffer.guis.logs_manager._helpers import backup_and_truncate_log_file
from session_sniffer.guis.logs_manager._sessions_tab import SessionsLogTab
from session_sniffer.guis.logs_manager._text_tab import TextLogTab
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET
from session_sniffer.guis.theming import ICONS_DIR_PATH
from session_sniffer.guis.utils import resize_window_for_screen, scale_by_ui, set_dialog_window_flags
from session_sniffer.guis.window_layout import (
    apply_maximize_on_show,
    clear_table_layout,
    restore_window_layout,
    save_window_layout,
    should_save_window_layout,
)
from session_sniffer.i18n import tr
from session_sniffer.models import GUIState
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
        self.setWindowTitle(tr('Logs Manager - {title}', title=TITLE))
        set_dialog_window_flags(self)
        self.setMinimumSize(scale_by_ui(880), scale_by_ui(520))
        gui_state = GUIState.load() if Settings.gui_remember_window_layout else None
        win_state = restore_window_layout(self, 'logs_manager', fallback_resize=lambda: resize_window_for_screen(self), gui_state=gui_state)

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
                on_reset_persisted_widths=partial(clear_table_layout, 'logs_manager_userip', reset_widths=True),
                on_reset_persisted_order=partial(clear_table_layout, 'logs_manager_userip', reset_order=True),
            ),
        )
        tabs.addTab(self._userip_tab, QIcon(str(ICONS_DIR_PATH / 'database.svg')), tr('UserIP Logging'))

        self._detection_tab = CsvLogTab(
            CsvLogTabConfig(
                file_path=DETECTION_LOGGING_PATH,
                expected_headers=('Detection', 'Usernames', 'IP', 'Date', 'Time', 'Country'),
                default_sort_columns=('Date', 'Time'),
                stretch_column=1,
                column_min_widths={0: 220, 5: 160},
                on_reset_persisted_widths=partial(clear_table_layout, 'logs_manager_detection', reset_widths=True),
                on_reset_persisted_order=partial(clear_table_layout, 'logs_manager_detection', reset_order=True),
            ),
        )
        tabs.addTab(self._detection_tab, QIcon(str(ICONS_DIR_PATH / 'bell.svg')), tr('Detection Logging'))
        self._protection_tab = CsvLogTab(
            CsvLogTabConfig(
                file_path=PROTECTION_LOGGING_PATH,
                expected_headers=('Detection', 'Usernames', 'IP', 'Date', 'Time', 'Country'),
                default_sort_columns=('Date', 'Time'),
                stretch_column=1,
                column_min_widths={0: 220, 5: 160},
                on_reset_persisted_widths=partial(clear_table_layout, 'logs_manager_protection', reset_widths=True),
                on_reset_persisted_order=partial(clear_table_layout, 'logs_manager_protection', reset_order=True),
            ),
        )
        tabs.addTab(self._protection_tab, QIcon(str(ICONS_DIR_PATH / 'shield.svg')), tr('Protection Logging'))

        self._sessions_tab = SessionsLogTab(sessions_dir=SESSIONS_LOGGING_DIR_PATH)
        tabs.addTab(self._sessions_tab, QIcon(str(ICONS_DIR_PATH / 'folder.svg')), tr('Sessions Logging'))
        self._debug_tab = TextLogTab(file_path=DEBUG_LOG_PATH, enable_severity_filter=True)
        tabs.addTab(self._debug_tab, QIcon(str(ICONS_DIR_PATH / 'bug.svg')), tr('Debug Log'))
        self._crash_tab = TextLogTab(file_path=CRASH_LOG_PATH)
        tabs.addTab(self._crash_tab, QIcon(str(ICONS_DIR_PATH / 'triangle-alert.svg')), tr('Crash Log'))

        if gui_state is not None:
            for csv_tab, table_key in (
                (self._userip_tab, 'logs_manager_userip'),
                (self._detection_tab, 'logs_manager_detection'),
                (self._protection_tab, 'logs_manager_protection'),
            ):
                csv_tab.apply_table_layout(gui_state.get_table(table_key))
            if win_state is not None:
                self._sessions_tab.restore_splitter_state(win_state.splitter)
                if win_state.active_tab is not None and 0 <= win_state.active_tab < tabs.count():
                    tabs.setCurrentIndex(win_state.active_tab)

        self._tab_titles = (
            'UserIP Logging',
            'Detection Logging',
            'Protection Logging',
            'Sessions Logging',
            'Debug Log',
            'Crash Log',
        )
        self._purgeable_tabs = (self._userip_tab, self._detection_tab, self._protection_tab, self._debug_tab, self._crash_tab)
        self._all_tabs = (self._userip_tab, self._detection_tab, self._protection_tab, self._sessions_tab, self._debug_tab, self._crash_tab)

        self._tabs = tabs
        root_layout.addWidget(tabs, stretch=1)

        # --- Bottom button row ---
        button_row = QHBoxLayout()
        button_row.addStretch()

        purge_all_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), f" {tr('Purge All Logs')}")
        purge_all_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        purge_all_button.setToolTip(tr('Clear ALL log files at once (creates backups first)'))
        purge_all_button.clicked.connect(self.purge_all_logs)
        button_row.addWidget(purge_all_button)
        self._purge_all_button = purge_all_button
        for tab in self._purgeable_tabs:
            tab.purge_state_changed.connect(self._update_purge_all_button)
        self._update_purge_all_button()

        clean_empty_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'trash.svg')), f" {tr('Clean Empty Sessions')}")
        clean_empty_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        clean_empty_button.setToolTip(tr('Delete empty session logs and empty folders (keeps active session)'))
        clean_empty_button.clicked.connect(self.clean_empty_sessions)
        button_row.addWidget(clean_empty_button)
        self._clean_empty_button = clean_empty_button

        close_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'x.svg')), f" {tr('Close')}")
        close_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        close_button.setToolTip(tr('Close the Logs Manager'))
        close_button.clicked.connect(self.close)
        button_row.addWidget(close_button)
        self._close_button = close_button

        root_layout.addLayout(button_row)
        register_language_refresh(self, self._retranslate)

    def _retranslate(self) -> None:
        """Refresh the dialog title, tab titles, and bottom action buttons after a language change."""
        self.setWindowTitle(tr('Logs Manager - {title}', title=TITLE))
        for idx, title in enumerate(self._tab_titles):
            self._tabs.setTabText(idx, tr(title))
        self._purge_all_button.setText(f" {tr('Purge All Logs')}")
        self._purge_all_button.setToolTip(tr('Clear ALL log files at once (creates backups first)'))
        self._clean_empty_button.setText(f" {tr('Clean Empty Sessions')}")
        self._clean_empty_button.setToolTip(tr('Delete empty session logs and empty folders (keeps active session)'))
        self._close_button.setText(f" {tr('Close')}")
        self._close_button.setToolTip(tr('Close the Logs Manager'))

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

    # ------------------------------------------------------------------
    # Clean empty sessions
    # ------------------------------------------------------------------

    def clean_empty_sessions(self) -> None:
        """Manually clean up empty session log files and empty directories."""
        gui_sessions_logging = Settings.gui_sessions_logging

        def _run_cleanup() -> tuple[int, int]:
            return cleanup_session_logs(
                sessions_dir=SESSIONS_LOGGING_DIR_PATH,
                delete_empty_files=True,
                delete_empty_folders=True,
                gui_sessions_logging=gui_sessions_logging,
                active_session_path=SESSIONS_LOGGING_PATH,
            )

        def _on_cleanup_done(outcome: tuple[int, int]) -> None:
            files_deleted, folders_deleted = outcome
            self._sessions_tab.update_dir_metadata()
            QMessageBox.information(
                self,
                TITLE,
                tr(
                    'Cleaned up empty session logs:\n\n  • Files deleted: {files}\n  • Folders deleted: {folders}',
                    files=files_deleted,
                    folders=folders_deleted,
                ),
            )

        run_async_with_loading(
            self,
            tr('Cleaning Session Logs\u2026'),
            tr('Scanning and removing empty session logs\u2026'),
            _run_cleanup,
            _on_cleanup_done,
        )

    # ------------------------------------------------------------------
    # Purge all
    # ------------------------------------------------------------------

    def _update_purge_all_button(self) -> None:
        """Enable the bulk purge action only when at least one log has content."""
        self._purge_all_button.setEnabled(any(tab.can_purge for tab in self._purgeable_tabs))

    def purge_all_logs(self) -> None:
        """Purge all CSV log files, debug.log, and crash.log after strong confirmation."""
        if not self._purge_all_button.isEnabled():
            return
        reply = QMessageBox.warning(
            self,
            TITLE,
            tr(
                'This will purge ALL log files:\n\n'
                '  • UserIP_Logging.csv\n'
                '  • Detection_Logging.csv\n'
                '  • Protection_Logging.csv\n'
                '  • debug.log\n'
                '  • crash.log\n\n'
                'Backups (.bak) will be created first.\n'
                'Are you sure?',
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        paths_to_purge = [
            path
            for path, tab in (
                (USERIP_LOGGING_PATH, self._userip_tab),
                (DETECTION_LOGGING_PATH, self._detection_tab),
                (PROTECTION_LOGGING_PATH, self._protection_tab),
                (DEBUG_LOG_PATH, self._debug_tab),
                (CRASH_LOG_PATH, self._crash_tab),
            )
            if tab.can_purge and path.exists()
        ]

        def _backup_and_purge() -> tuple[list[str], list[str]]:
            purged: list[str] = []
            errors: list[str] = []
            for path in paths_to_purge:
                try:
                    backup_and_truncate_log_file(path)
                except OSError as e:
                    errors.append(f'{path.name} ({e.strerror or e})')
                    continue
                purged.append(path.name)
            return purged, errors

        def _on_purge_done(outcome: tuple[list[str], list[str]]) -> None:
            purged, errors = outcome
            for tab in self._purgeable_tabs:
                tab.load_data()

            parts: list[str] = []
            if purged:
                parts.append(tr('Purged: {files}', files=', '.join(purged)))
            if errors:
                parts.append(tr('Errors: {errors}', errors='; '.join(errors)))
            if not parts:
                parts.append(tr('No log files to purge.'))

            QMessageBox.information(self, TITLE, '\n'.join(parts))

        run_async_with_loading(
            self,
            tr('Purging Logs\u2026'),
            tr('Creating backups and clearing log files\u2026'),
            _backup_and_purge,
            _on_purge_done,
        )

    @override
    def showEvent(self, a0: QShowEvent) -> None:
        """Handle the window show event, maximize if required, and resume file watching."""
        super().showEvent(a0)
        apply_maximize_on_show(self)
        self._start_all_watchers()

    @override
    def hideEvent(self, a0: QHideEvent) -> None:
        """Stop all background filesystem watchers when the dialog is hidden or closed."""
        self._stop_all_watchers()
        super().hideEvent(a0)

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Stop all background filesystem watchers and persist window, splitter, and CSV table layouts when closed."""
        self._stop_all_watchers()
        super().closeEvent(event)
        if event.isAccepted() and should_save_window_layout(self):
            gui_state = GUIState.load()
            win_state = save_window_layout(self, 'logs_manager', gui_state=gui_state)
            if win_state is not None:
                win_state.active_tab = self._tabs.currentIndex()
                win_state.splitter = self._sessions_tab.get_splitter_state()
            for tab, table_key in (
                (self._userip_tab, 'logs_manager_userip'),
                (self._detection_tab, 'logs_manager_detection'),
                (self._protection_tab, 'logs_manager_protection'),
            ):
                tab.populate_table_layout_state(gui_state.ensure_table(table_key))
            gui_state.save()

    def select_tab(self, title_key: str) -> None:
        """Switch the active logs tab to *title_key* when present."""
        if title_key in self._tab_titles:
            self._tabs.setCurrentIndex(self._tab_titles.index(title_key))

    def _start_all_watchers(self) -> None:
        """Start filesystem watchers for all tabs."""
        for tab in self._all_tabs:
            tab.start_watching()

    def _stop_all_watchers(self) -> None:
        """Stop filesystem watchers for all tabs."""
        for tab in self._all_tabs:
            tab.stop_watching()
