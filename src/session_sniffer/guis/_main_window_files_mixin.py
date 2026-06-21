"""File, folder, and URL open helpers mixin for `MainWindow`."""

import os
import webbrowser
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QLabel,
    QMainWindow,
    QMessageBox,
    QStyle,
    QVBoxLayout,
)

from session_sniffer.constants._build_info import COMMIT_DATE, COMMIT_SHA, OS_INFO, PYQT_VERSION, RELEASE_DATE, RELEASE_TAG
from session_sniffer.constants.local import (
    APP_DIR_LOCAL,
    APP_DIR_ROAMING,
    DEBUG_DIR_PATH,
    DEBUG_LOG_PATH,
    DETECTION_LOGGING_PATH,
    LOGGING_DIR_PATH,
    PROTECTION_LOGGING_PATH,
    SESSIONS_LOGGING_DIR_PATH,
    SETTINGS_PATH,
    USER_SCRIPTS_DIR_PATH,
    USERIP_DATABASES_DIR_PATH,
    USERIP_LOGGING_PATH,
    VERSION,
)
from session_sniffer.constants.standalone import (
    DISCORD_INVITE_URL,
    GITHUB_ISSUES_URL,
    GITHUB_LICENSE_URL,
    GITHUB_RELEASES_URL,
    GITHUB_REPO_URL,
    GITHUB_WIKI_TIPS_URL,
    GITHUB_WIKI_URL,
    LOOKY_BASE_HOST,
    TITLE,
)
from session_sniffer.settings import Settings
from session_sniffer.updater import UpdateCheckOutcome, check_for_updates

if TYPE_CHECKING:
    from pathlib import Path


class FilesMixin(QMainWindow):
    """File, folder, and URL open helpers mixin for `MainWindow`."""

    def _open_looky_website(self) -> None:
        """Open the Looky System website in the default browser."""
        webbrowser.open(LOOKY_BASE_HOST)

    def _open_project_repo(self) -> None:
        """Open the GitHub repository in the default browser."""
        webbrowser.open(GITHUB_REPO_URL)

    def _open_documentation(self) -> None:
        """Open the documentation URL in the default browser."""
        webbrowser.open(GITHUB_WIKI_URL)

    def _open_tips_and_tricks(self) -> None:
        """Open the Tips and Tricks wiki page in the default browser."""
        webbrowser.open(GITHUB_WIKI_TIPS_URL)

    def _join_discord(self) -> None:
        """Open the Discord invite URL in the default browser."""
        webbrowser.open(DISCORD_INVITE_URL)

    def _open_release_notes(self) -> None:
        """Open the GitHub releases page in the default browser."""
        webbrowser.open(GITHUB_RELEASES_URL)

    def _view_license(self) -> None:
        """Open the project license on GitHub in the default browser."""
        webbrowser.open(GITHUB_LICENSE_URL)

    def _report_issue(self) -> None:
        """Open the GitHub issues page in the default browser."""
        webbrowser.open(GITHUB_ISSUES_URL)

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

    def _open_debug_log_file(self) -> None:
        """Open the debug.log file."""
        self.open_file(DEBUG_LOG_PATH)

    def _open_debug_logs_folder(self) -> None:
        """Open the Debug logs directory."""
        self.open_directory(DEBUG_DIR_PATH)

    def _open_logging_folder(self) -> None:
        """Open the Logging directory."""
        self.open_directory(LOGGING_DIR_PATH)

    def _show_about_dialog(self) -> None:
        """Show the About dialog with version, build, and system info."""
        copy_text = '\n'.join(
            [
                f'Version: {VERSION}',
                '',
                f'Release Tag: {RELEASE_TAG}',
                f'Release Date: {RELEASE_DATE}',
                f'Commit Sha: {COMMIT_SHA}',
                f'Commit Date: {COMMIT_DATE}',
                '',
                f'PyQt Version: {PYQT_VERSION}',
                f'OS Info: {OS_INFO}',
            ],
        )

        dialog = QDialog(self)
        dialog.setWindowTitle(f'About {TITLE}')
        dialog.setMinimumWidth(440)

        layout = QVBoxLayout(dialog)
        layout.setSpacing(6)

        style = dialog.style()
        if style is not None:
            icon_label = QLabel()
            icon_label.setPixmap(style.standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation).pixmap(32, 32))
            icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(icon_label)

        title_label = QLabel(f'<b style="font-size:13pt">{TITLE}</b>')
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)

        desc_label = QLabel('A packet sniffer designed for Peer-To-Peer (P2P) video games on PC and consoles.')
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)

        layout.addSpacing(6)

        build_header = QLabel('<b>Build Information</b>')
        layout.addWidget(build_header)
        build_sep = QFrame()
        build_sep.setFrameShape(QFrame.Shape.HLine)
        build_sep.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(build_sep)
        build_info = QLabel(
            '<table cellspacing="2">'
            f'<tr><td><b>Version</b></td><td>&nbsp;&nbsp;{VERSION}</td></tr>'
            '<tr><td style="padding-top:0px"></td></tr>'
            f'<tr><td><b>Release Tag</b></td><td>&nbsp;&nbsp;{RELEASE_TAG}</td></tr>'
            f'<tr><td><b>Release Date</b></td><td>&nbsp;&nbsp;{RELEASE_DATE}</td></tr>'
            f'<tr><td><b>Commit Sha</b></td><td>&nbsp;&nbsp;{COMMIT_SHA}</td></tr>'
            f'<tr><td><b>Commit Date</b></td><td>&nbsp;&nbsp;{COMMIT_DATE}</td></tr>'
            '<tr><td style="padding-top:0px"></td></tr>'
            f'<tr><td><b>PyQt Version</b></td><td>&nbsp;&nbsp;{PYQT_VERSION}</td></tr>'
            f'<tr><td><b>OS Info</b></td><td>&nbsp;&nbsp;{OS_INFO}</td></tr>'
            '</table>',
        )
        build_info.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(build_info)

        layout.addSpacing(8)

        button_box = QDialogButtonBox()
        copy_button = button_box.addButton('Copy Details', QDialogButtonBox.ButtonRole.ActionRole)
        button_box.addButton(QDialogButtonBox.StandardButton.Close)

        if copy_button is not None:
            copy_button.setCursor(Qt.CursorShape.PointingHandCursor)
            clipboard = QApplication.clipboard()
            if clipboard is not None:
                copy_button.clicked.connect(lambda: clipboard.setText(copy_text))

        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)

        dialog.exec()
