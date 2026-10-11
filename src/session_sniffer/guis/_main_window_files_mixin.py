"""File, folder, and URL open helpers mixin for `MainWindow`."""

import webbrowser
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QIcon
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFrame,
    QLabel,
    QMainWindow,
    QMenuBar,
    QMessageBox,
    QStyle,
    QVBoxLayout,
)

from session_sniffer.constants._build_info import COMMIT_DATE, COMMIT_SHA, OS_INFO, PYSIDE6_VERSION, RELEASE_DATE, RELEASE_TAG
from session_sniffer.constants.local import (
    APP_DIR_LOCAL,
    APP_DIR_ROAMING,
    CRASH_LOG_PATH,
    DEBUG_DIR_PATH,
    DEBUG_LOG_PATH,
    DETECTION_LOGGING_PATH,
    LOGGING_DIR_PATH,
    PROTECTION_LOGGING_PATH,
    RESOURCES_DIR_PATH,
    SESSIONS_LOGGING_DIR_PATH,
    SETTINGS_PATH,
    USER_SCRIPTS_DIR_PATH,
    USERIP_DATABASES_BACKUP_DIR_PATH,
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
from session_sniffer.guis.detections_manager import DetectionsManagerDialog
from session_sniffer.guis.interface_selection_dialog import InterfaceSelectionDialog
from session_sniffer.guis.logs_manager import LogsManager
from session_sniffer.guis.userip_manager import UserIPDatabasesManager
from session_sniffer.guis.utils import activate_window, animate_button_feedback, set_clipboard_text, show_or_focus_window
from session_sniffer.settings import Settings
from session_sniffer.updater import UpdateCheckOutcome, check_for_updates

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


class FilesMixin(QMainWindow):
    """File, folder, and URL open helpers mixin for `MainWindow`."""

    _detections_manager_window: DetectionsManagerDialog | None
    _logs_manager_window: LogsManager | None
    _userip_manager_window: UserIPDatabasesManager | None
    _on_open_hotspot: Callable[[], None]

    def _open_userip_manager(self) -> UserIPDatabasesManager:
        """Open the UserIP Databases Manager window, or focus the existing one."""
        return show_or_focus_window(self, '_userip_manager_window', lambda: UserIPDatabasesManager(None))

    def open_userip_manager_and_search(self, text: str) -> None:
        """Open the UserIP Databases Manager, activate global search, and populate the search field with `text`."""
        self._open_userip_manager().search_global(text)

    def _open_logs_manager(self) -> LogsManager:
        """Open the Logs Manager window, or focus the existing one."""
        return show_or_focus_window(self, '_logs_manager_window', lambda: LogsManager(None))

    def open_logs_manager_and_search_userip(self, text: str) -> None:
        """Open the Logs Manager on the UserIP Logging tab and filter by `text`."""
        self._open_logs_manager().search_in_userip_logging(text)

    def open_logs_manager_and_search_sessions(self, text: str) -> None:
        """Open the Logs Manager on the Sessions Logging tab and start a global search for `text`."""
        self._open_logs_manager().search_in_sessions_logging(text)

    def open_logs_manager_and_show_debug_log(self, severity: str | None = None) -> None:
        """Open the Logs Manager on the Debug Log tab, optionally filtering by severity."""
        self._open_logs_manager().show_debug_log(severity=severity)

    def open_logs_manager_and_show_crash_log(self) -> None:
        """Open the Logs Manager on the Crash Log tab."""
        self._open_logs_manager().show_crash_log()

    def _open_detections_manager(self) -> None:
        """Open the Detections Manager window, or focus the existing one."""
        show_or_focus_window(self, '_detections_manager_window', lambda: DetectionsManagerDialog(None))

    def _open_hotspot_manager(self) -> None:
        """Open the Hotspot & Connection Sharing window, or focus the existing one."""
        active_interface_dialog = InterfaceSelectionDialog.get_active_instance()
        if active_interface_dialog is not None:
            active_interface_dialog.select_hotspot_tab()
            activate_window(active_interface_dialog)
            return
        self._on_open_hotspot()

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
        outcome, pending_download = check_for_updates(
            updater_channel=Settings.updater_channel,
            ignore_skipped=True,
        )
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
        """Ensure a directory exists and open it in the default file manager."""
        directory_path.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(directory_path)))

    @staticmethod
    def open_file(file_path: Path) -> None:
        """Ensure a file path exists and open the file using the default association."""
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.touch(exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(file_path)))

    def _open_local_appdata_folder(self) -> None:
        """Open the Local AppData Session Sniffer directory."""
        self.open_directory(APP_DIR_LOCAL)

    def _open_roaming_appdata_folder(self) -> None:
        """Open the Roaming AppData Session Sniffer directory."""
        self.open_directory(APP_DIR_ROAMING)

    def _open_userip_databases_folder(self) -> None:
        """Open the UserIP databases directory."""
        self.open_directory(USERIP_DATABASES_DIR_PATH)

    def _open_userip_databases_backups_folder(self) -> None:
        """Open the UserIP databases backups directory."""
        self.open_directory(USERIP_DATABASES_BACKUP_DIR_PATH)

    def _open_sessions_logging_folder(self) -> None:
        """Open the sessions logging directory."""
        self.open_directory(SESSIONS_LOGGING_DIR_PATH)

    def _open_user_scripts_folder(self) -> None:
        """Open the user scripts directory."""
        self.open_directory(USER_SCRIPTS_DIR_PATH)

    def _open_settings_file(self) -> None:
        """Open the Settings.ini file."""
        self.open_file(SETTINGS_PATH)

    def _open_logging_folder(self) -> None:
        """Open the Logging directory."""
        self.open_directory(LOGGING_DIR_PATH)

    def _open_userip_log_file(self) -> None:
        """Open the UserIP_Logging.csv file."""
        self.open_file(USERIP_LOGGING_PATH)

    def _open_detection_log_file(self) -> None:
        """Open the Detection_Logging.csv file."""
        self.open_file(DETECTION_LOGGING_PATH)

    def _open_protection_log_file(self) -> None:
        """Open the Protection_Logging.csv file."""
        self.open_file(PROTECTION_LOGGING_PATH)

    def _open_debug_logs_folder(self) -> None:
        """Open the Debug logs directory."""
        self.open_directory(DEBUG_DIR_PATH)

    def _open_debug_log_file(self) -> None:
        """Open the debug.log file."""
        self.open_file(DEBUG_LOG_PATH)

    def _open_crash_log_file(self) -> None:
        """Open the crash.log file."""
        self.open_file(CRASH_LOG_PATH)

    def _build_data_menu(self, menu_bar: QMenuBar) -> None:
        """Build the Data & Files menu and attach folder, file, and log navigation actions."""
        data_menu = menu_bar.addMenu('Data && Files')
        if not data_menu:
            message = 'Failed to create Data & Files menu'
            raise RuntimeError(message)
        data_menu.setToolTipsVisible(True)

        open_local_appdata_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'Open Local AppData Folder', self)
        open_local_appdata_action.setToolTip('Open Local AppData\\Session Sniffer in Windows Explorer')
        open_local_appdata_action.triggered.connect(self._open_local_appdata_folder)
        data_menu.addAction(open_local_appdata_action)

        open_roaming_appdata_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'Open Roaming AppData Folder', self)
        open_roaming_appdata_action.setToolTip('Open Roaming AppData\\Session Sniffer in Windows Explorer')
        open_roaming_appdata_action.triggered.connect(self._open_roaming_appdata_folder)
        data_menu.addAction(open_roaming_appdata_action)

        data_menu.addSeparator()

        open_userip_databases_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'Open UserIP Databases Folder', self)
        open_userip_databases_action.setToolTip('Open Roaming AppData\\Session Sniffer\\UserIP Databases')
        open_userip_databases_action.triggered.connect(self._open_userip_databases_folder)
        data_menu.addAction(open_userip_databases_action)

        open_userip_databases_backups_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'Open UserIP Backups Folder', self)
        open_userip_databases_backups_action.setToolTip('Open Roaming AppData\\Session Sniffer\\UserIP Databases Backups')
        open_userip_databases_backups_action.triggered.connect(self._open_userip_databases_backups_folder)
        data_menu.addAction(open_userip_databases_backups_action)

        open_user_scripts_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'Open User Scripts Folder', self)
        open_user_scripts_action.setToolTip('Open Roaming AppData\\Session Sniffer\\scripts')
        open_user_scripts_action.triggered.connect(self._open_user_scripts_folder)
        data_menu.addAction(open_user_scripts_action)

        data_menu.addSeparator()

        app_logs_submenu = data_menu.addMenu(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'file-text.svg')), 'Application Logs')
        if not app_logs_submenu:
            message = 'Failed to create Application Logs submenu'
            raise RuntimeError(message)
        app_logs_submenu.setToolTipsVisible(True)
        app_logs_submenu.menuAction().setToolTip('Open or browse CSV application log files (detections, protection, UserIP)')

        open_logging_folder_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'Open Logging Folder', self)
        open_logging_folder_action.setToolTip('Open Local AppData\\Session Sniffer\\Logging')
        open_logging_folder_action.triggered.connect(self._open_logging_folder)
        app_logs_submenu.addAction(open_logging_folder_action)

        open_sessions_logs_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'Open Sessions Folder', self)
        open_sessions_logs_action.setToolTip('Open Local AppData\\Session Sniffer\\Logging\\Sessions')
        open_sessions_logs_action.triggered.connect(self._open_sessions_logging_folder)
        app_logs_submenu.addAction(open_sessions_logs_action)

        app_logs_submenu.addSeparator()

        open_detection_log_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'file-text.svg')), 'Detection_Logging.csv', self)
        open_detection_log_action.setToolTip('Open Local AppData\\Session Sniffer\\Logging\\Detection_Logging.csv')
        open_detection_log_action.triggered.connect(self._open_detection_log_file)
        app_logs_submenu.addAction(open_detection_log_action)

        open_protection_log_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'file-text.svg')), 'Protection_Logging.csv', self)
        open_protection_log_action.setToolTip('Open Local AppData\\Session Sniffer\\Logging\\Protection_Logging.csv')
        open_protection_log_action.triggered.connect(self._open_protection_log_file)
        app_logs_submenu.addAction(open_protection_log_action)

        open_userip_log_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'file-text.svg')), 'UserIP_Logging.csv', self)
        open_userip_log_action.setToolTip('Open Local AppData\\Session Sniffer\\Logging\\UserIP_Logging.csv')
        open_userip_log_action.triggered.connect(self._open_userip_log_file)
        app_logs_submenu.addAction(open_userip_log_action)

        debug_logs_submenu = data_menu.addMenu(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'bug.svg')), 'Debug Logs')
        if not debug_logs_submenu:
            message = 'Failed to create Debug Logs submenu'
            raise RuntimeError(message)
        debug_logs_submenu.setToolTipsVisible(True)
        debug_logs_submenu.menuAction().setToolTip('Open or browse the application debug log files')

        open_debug_logs_folder_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'Open Debug Logs Folder', self)
        open_debug_logs_folder_action.setToolTip('Open Local AppData\\Session Sniffer\\Debug')
        open_debug_logs_folder_action.triggered.connect(self._open_debug_logs_folder)
        debug_logs_submenu.addAction(open_debug_logs_folder_action)

        debug_logs_submenu.addSeparator()

        open_debug_log_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'file-text.svg')), 'debug.log', self)
        open_debug_log_action.setToolTip('Open Local AppData\\Session Sniffer\\Debug\\debug.log')
        open_debug_log_action.triggered.connect(self._open_debug_log_file)
        debug_logs_submenu.addAction(open_debug_log_action)

        open_crash_log_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'file-text.svg')), 'crash.log', self)
        open_crash_log_action.setToolTip('Open Local AppData\\Session Sniffer\\Debug\\crash.log')
        open_crash_log_action.triggered.connect(self._open_crash_log_file)
        debug_logs_submenu.addAction(open_crash_log_action)

        data_menu.addSeparator()

        open_settings_ini_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'file-cog.svg')), 'Open Settings.ini', self)
        open_settings_ini_action.setToolTip('Open Roaming AppData\\Session Sniffer\\Settings.ini')
        open_settings_ini_action.triggered.connect(self._open_settings_file)
        data_menu.addAction(open_settings_ini_action)

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
                f'PySide6 Version: {PYSIDE6_VERSION}',
                f'OS Info: {OS_INFO}',
            ],
        )

        dialog = QDialog(self)
        dialog.setWindowTitle(f'About {TITLE}')
        dialog.setMinimumWidth(440)

        layout = QVBoxLayout(dialog)
        layout.setSpacing(6)

        style = dialog.style()
        if style:
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
            f'<tr><td><b>PySide6 Version</b></td><td>&nbsp;&nbsp;{PYSIDE6_VERSION}</td></tr>'
            f'<tr><td><b>OS Info</b></td><td>&nbsp;&nbsp;{OS_INFO}</td></tr>'
            '</table>',
        )
        build_info.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(build_info)

        layout.addSpacing(8)

        button_box = QDialogButtonBox()
        copy_button = button_box.addButton('Copy Details', QDialogButtonBox.ButtonRole.ActionRole)
        button_box.addButton(QDialogButtonBox.StandardButton.Close)

        if copy_button:
            copy_button.setCursor(Qt.CursorShape.PointingHandCursor)

            def _on_copy_details() -> None:
                set_clipboard_text(copy_text)
                animate_button_feedback(copy_button)

            copy_button.clicked.connect(_on_copy_details)

        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)

        dialog.exec()

    def _build_help_menu(self, menu_bar: QMenuBar) -> None:
        """Build the Help menu and attach documentation, community, and about actions."""
        help_menu = menu_bar.addMenu('Help')
        if not help_menu:
            message = 'Failed to create Help menu'
            raise RuntimeError(message)
        help_menu.setToolTipsVisible(True)

        repo_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'github.svg')), 'Project Repository', self)
        repo_action.setToolTip('Open the Session Sniffer GitHub repository in your default web browser')
        repo_action.triggered.connect(self._open_project_repo)
        help_menu.addAction(repo_action)

        docs_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'book-text.svg')), 'Documentation', self)
        docs_action.setToolTip('View the complete documentation and user guide for Session Sniffer')
        docs_action.triggered.connect(self._open_documentation)
        help_menu.addAction(docs_action)

        tips_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'lightbulb.svg')), 'Tips and Tricks', self)
        tips_action.setToolTip('Learn optimization strategies, hidden features, and best practices')
        tips_action.triggered.connect(self._open_tips_and_tricks)
        help_menu.addAction(tips_action)

        release_notes_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'rotate-ccw-clock.svg')), 'Release Notes', self)
        release_notes_action.setToolTip('View the release history and notes on GitHub')
        release_notes_action.triggered.connect(self._open_release_notes)
        help_menu.addAction(release_notes_action)

        license_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'scale.svg')), 'View License', self)
        license_action.setToolTip('View the GNU General Public License (GPLv3) for Session Sniffer')
        license_action.triggered.connect(self._view_license)
        help_menu.addAction(license_action)

        help_menu.addSeparator()

        report_issue_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'bug.svg')), 'Report Issue', self)
        report_issue_action.setToolTip('Open a new issue on GitHub to report a bug or request a feature')
        report_issue_action.triggered.connect(self._report_issue)
        help_menu.addAction(report_issue_action)

        discord_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'discord.svg')), 'Discord Server', self)
        discord_action.setToolTip('Join the official Session Sniffer Discord community for support and updates')
        discord_action.triggered.connect(self._join_discord)
        help_menu.addAction(discord_action)

        help_menu.addSeparator()

        check_updates_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'cloud-download.svg')), 'Check for Updates', self)
        check_updates_action.setToolTip('Check GitHub for a newer version of Session Sniffer')
        check_updates_action.triggered.connect(self._check_for_updates)
        help_menu.addAction(check_updates_action)

        help_menu.addSeparator()

        about_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'info.svg')), 'About', self)
        about_action.setToolTip(f'About {TITLE}')
        about_action.triggered.connect(self._show_about_dialog)
        help_menu.addAction(about_action)
