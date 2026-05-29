"""File, folder, and URL open helpers mixin for `MainWindow`."""

import os
import webbrowser
from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QMainWindow, QMessageBox

from session_sniffer.constants.local import (
    APP_DIR_LOCAL,
    APP_DIR_ROAMING,
    DEBUG_DIR_PATH,
    DEBUG_LOG_PATH,
    DETECTION_LOGGING_PATH,
    ERRORS_LOG_PATH,
    LOGGING_DIR_PATH,
    PROTECTION_LOGGING_PATH,
    SESSIONS_LOGGING_DIR_PATH,
    SETTINGS_PATH,
    USER_SCRIPTS_DIR_PATH,
    USERIP_DATABASES_DIR_PATH,
    USERIP_LOGGING_PATH,
    WARNINGS_LOG_PATH,
)
from session_sniffer.constants.standalone import DISCORD_INVITE_URL, GITHUB_REPO_URL, GITHUB_WIKI_URL, TITLE
from session_sniffer.settings import Settings
from session_sniffer.updater import UpdateCheckOutcome, check_for_updates

if TYPE_CHECKING:
    from pathlib import Path


class FilesMixin(QMainWindow):
    """File, folder, and URL open helpers mixin for `MainWindow`."""

    def _open_project_repo(self) -> None:
        """Open the GitHub repository in the default browser."""
        webbrowser.open(GITHUB_REPO_URL)

    def _open_documentation(self) -> None:
        """Open the documentation URL in the default browser."""
        webbrowser.open(GITHUB_WIKI_URL)

    def _join_discord(self) -> None:
        """Open the Discord invite URL in the default browser."""
        webbrowser.open(DISCORD_INVITE_URL)

    def _check_for_updates(self) -> None:
        """Manually trigger an update check against GitHub."""
        outcome, pending_download = check_for_updates(updater_channel=Settings.updater_channel)
        if pending_download is not None:
            pending_download()
        elif outcome is UpdateCheckOutcome.PROCEED:
            QMessageBox.information(
                self,
                TITLE,
                'You are running the latest version.',
            )

    @staticmethod
    def open_directory(directory_path: Path) -> None:
        """Ensure a directory exists and open it in Windows Explorer."""
        directory_path.mkdir(parents=True, exist_ok=True)
        os.startfile(str(directory_path))

    @staticmethod
    def open_file(file_path: Path) -> None:
        """Ensure a file path exists and open the file using the default Windows association."""
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.touch(exist_ok=True)
        os.startfile(str(file_path))

    def _open_local_appdata_folder(self) -> None:
        """Open the Local AppData Session Sniffer directory."""
        self.open_directory(APP_DIR_LOCAL)

    def _open_roaming_appdata_folder(self) -> None:
        """Open the Roaming AppData Session Sniffer directory."""
        self.open_directory(APP_DIR_ROAMING)

    def _open_userip_databases_folder(self) -> None:
        """Open the UserIP databases directory."""
        self.open_directory(USERIP_DATABASES_DIR_PATH)

    def _open_sessions_logging_folder(self) -> None:
        """Open the sessions logging directory."""
        self.open_directory(SESSIONS_LOGGING_DIR_PATH)

    def _open_user_scripts_folder(self) -> None:
        """Open the user scripts directory."""
        self.open_directory(USER_SCRIPTS_DIR_PATH)

    def _open_settings_file(self) -> None:
        """Open the Settings.ini file."""
        self.open_file(SETTINGS_PATH)

    def _open_userip_log_file(self) -> None:
        """Open the UserIP_Logging.csv file."""
        self.open_file(USERIP_LOGGING_PATH)

    def _open_detection_log_file(self) -> None:
        """Open the Detection_Logging.csv file."""
        self.open_file(DETECTION_LOGGING_PATH)

    def _open_protection_log_file(self) -> None:
        """Open the Protection_Logging.csv file."""
        self.open_file(PROTECTION_LOGGING_PATH)

    def _open_error_log_file(self) -> None:
        """Open the errors.log file."""
        self.open_file(ERRORS_LOG_PATH)

    def _open_warnings_log_file(self) -> None:
        """Open the warnings.log file."""
        self.open_file(WARNINGS_LOG_PATH)

    def _open_debug_log_file(self) -> None:
        """Open the debug.log file."""
        self.open_file(DEBUG_LOG_PATH)

    def _open_debug_logs_folder(self) -> None:
        """Open the Debug logs directory."""
        self.open_directory(DEBUG_DIR_PATH)

    def _open_logging_folder(self) -> None:
        """Open the Logging directory."""
        self.open_directory(LOGGING_DIR_PATH)
