"""File, folder, and URL open helpers mixin for `MainWindow`."""

import html
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
    QMenu,
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
from session_sniffer.guis.live_language import add_i18n_menu_actions
from session_sniffer.guis.loading_overlay import run_async_with_loading
from session_sniffer.guis.logs_manager import LogsManager
from session_sniffer.guis.theming import ICONS_DIR_PATH
from session_sniffer.guis.userip_manager import UserIPDatabasesManager
from session_sniffer.guis.utils import activate_window, animate_button_feedback, scale_by_ui, set_clipboard_text, show_or_focus_window
from session_sniffer.i18n import tr
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
    _checking_for_updates: bool = False
    _files_i18n_actions: list[tuple[QAction, str, str]] | None = None
    _files_i18n_menus: list[tuple[QMenu, str, str | None]] | None = None
    _files_about_action: QAction | None = None

    def _open_userip_manager(self) -> UserIPDatabasesManager:
        """Open the UserIP Databases Manager window, or focus the existing one."""
        return show_or_focus_window(self, '_userip_manager_window', lambda: UserIPDatabasesManager(None))

    def open_userip_manager_and_search(self, text: str) -> None:
        """Open the UserIP Databases Manager, activate global search, and populate the search field with `text`."""
        self._open_userip_manager().search_global(text)

    def open_userip_manager_and_navigate(self, db_path: Path, *, username: str = '', ip_or_range: str = '') -> None:
        """Open the UserIP Databases Manager on `db_path` and select the matching entry."""
        self._open_userip_manager().navigate_to_database(db_path, username=username, ip_or_range=ip_or_range)

    def _open_logs_manager(self) -> LogsManager:
        """Open the Logs Manager window, or focus the existing one."""
        return show_or_focus_window(self, '_logs_manager_window', lambda: LogsManager(None))

    def open_logs_manager_and_search_userip(self, text: str) -> None:
        """Open the Logs Manager on the UserIP Logging tab and filter by `text`."""
        self._open_logs_manager().search_in_userip_logging(text)

    def open_logs_manager_and_search_sessions(self, text: str) -> None:
        """Open the Logs Manager on the Sessions Logging tab and start a global search for `text`."""
        self._open_logs_manager().search_in_sessions_logging(text)

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
        """Manually trigger an asynchronous update check against GitHub."""
        if self._checking_for_updates:
            return
        self._checking_for_updates = True

        def _fetch() -> tuple[UpdateCheckOutcome, Callable[[], None] | None]:
            return check_for_updates(
                updater_channel=Settings.updater_channel,
                ignore_skipped=True,
            )

        def _on_done(result: tuple[UpdateCheckOutcome, Callable[[], None] | None]) -> None:
            self._checking_for_updates = False
            outcome, pending_download = result
            if pending_download is not None:
                pending_download()
            elif outcome is UpdateCheckOutcome.PROCEED:
                QMessageBox.information(
                    self,
                    TITLE,
                    tr('You are running the latest version.'),
                )

        run_async_with_loading(
            self,
            tr('Checking for Updates\u2026'),
            tr('Contacting GitHub releases\u2026'),
            _fetch,
            _on_done,
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
        """Open the settings.json file."""
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

    def _register_i18n_menu(self, menu: QMenu, title_key: str, tooltip_key: str | None = None) -> None:
        if self._files_i18n_menus is None:
            self._files_i18n_menus = []
        self._files_i18n_menus.append((menu, title_key, tooltip_key))

    def _add_i18n_menu_actions(self, menu: QMenu, specs: list[tuple[str, str, str, Callable[[], None]] | None]) -> None:
        if self._files_i18n_actions is None:
            self._files_i18n_actions = []
        add_i18n_menu_actions(self, menu, ICONS_DIR_PATH, specs, self._files_i18n_actions)

    def _refresh_files_menu_language_texts(self) -> None:
        """Re-translate Data & Files and Help menus, submenus, and actions on language change."""
        for menu, title_key, tooltip_key in self._files_i18n_menus or ():
            menu.setTitle(tr(title_key))
            if tooltip_key is not None:
                menu.menuAction().setToolTip(tr(tooltip_key))
        for action, text_key, tooltip_key in self._files_i18n_actions or ():
            action.setText(tr(text_key))
            action.setToolTip(tr(tooltip_key))
        if self._files_about_action is not None:
            self._files_about_action.setText(tr('About'))
            self._files_about_action.setToolTip(tr('About {title}', title=TITLE))

    def _build_data_menu(self, menu_bar: QMenuBar) -> None:
        """Build the Data & Files menu and attach folder, file, and log navigation actions."""
        data_menu = menu_bar.addMenu(tr('Data && Files'))
        if not data_menu:
            message = 'Failed to create Data & Files menu'
            raise RuntimeError(message)
        data_menu.setToolTipsVisible(True)
        self._register_i18n_menu(data_menu, 'Data && Files')

        self._add_i18n_menu_actions(
            data_menu,
            [
                ('folder.svg', 'Open Local AppData Folder', 'Open Local AppData\\Session Sniffer in your file manager', self._open_local_appdata_folder),
                ('folder.svg', 'Open Roaming AppData Folder', 'Open Roaming AppData\\Session Sniffer in your file manager', self._open_roaming_appdata_folder),
                None,
                ('folder.svg', 'Open UserIP Databases Folder', 'Open Roaming AppData\\Session Sniffer\\UserIP Databases', self._open_userip_databases_folder),
                ('folder.svg', 'Open UserIP Backups Folder', 'Open Roaming AppData\\Session Sniffer\\UserIP Databases Backups', self._open_userip_databases_backups_folder),
                ('folder.svg', 'Open User Scripts Folder', 'Open Roaming AppData\\Session Sniffer\\scripts', self._open_user_scripts_folder),
                None,
            ],
        )

        app_logs_submenu = data_menu.addMenu(QIcon(str(ICONS_DIR_PATH / 'file-text.svg')), tr('Application Logs'))
        if not app_logs_submenu:
            message = 'Failed to create Application Logs submenu'
            raise RuntimeError(message)
        app_logs_submenu.setToolTipsVisible(True)
        app_logs_tooltip = 'Open or browse CSV application log files (detections, protection, UserIP)'
        app_logs_submenu.menuAction().setToolTip(tr(app_logs_tooltip))
        self._register_i18n_menu(app_logs_submenu, 'Application Logs', app_logs_tooltip)

        self._add_i18n_menu_actions(
            app_logs_submenu,
            [
                ('folder.svg', 'Open Logging Folder', 'Open Local AppData\\Session Sniffer\\Logging', self._open_logging_folder),
                ('folder.svg', 'Open Sessions Folder', 'Open Local AppData\\Session Sniffer\\Logging\\Sessions', self._open_sessions_logging_folder),
                None,
                ('file-text.svg', 'Open Detection_Logging.csv', 'Open Local AppData\\Session Sniffer\\Logging\\Detection_Logging.csv', self._open_detection_log_file),
                ('file-text.svg', 'Open Protection_Logging.csv', 'Open Local AppData\\Session Sniffer\\Logging\\Protection_Logging.csv', self._open_protection_log_file),
                ('file-text.svg', 'Open UserIP_Logging.csv', 'Open Local AppData\\Session Sniffer\\Logging\\UserIP_Logging.csv', self._open_userip_log_file),
            ],
        )

        debug_logs_submenu = data_menu.addMenu(QIcon(str(ICONS_DIR_PATH / 'bug.svg')), tr('Debug Logs'))
        if not debug_logs_submenu:
            message = 'Failed to create Debug Logs submenu'
            raise RuntimeError(message)
        debug_logs_submenu.setToolTipsVisible(True)
        debug_logs_tooltip = 'Open or browse the application debug log files'
        debug_logs_submenu.menuAction().setToolTip(tr(debug_logs_tooltip))
        self._register_i18n_menu(debug_logs_submenu, 'Debug Logs', debug_logs_tooltip)

        self._add_i18n_menu_actions(
            debug_logs_submenu,
            [
                ('folder.svg', 'Open Debug Logs Folder', 'Open Local AppData\\Session Sniffer\\Debug', self._open_debug_logs_folder),
                None,
                ('file-text.svg', 'Open debug.log', 'Open Local AppData\\Session Sniffer\\Debug\\debug.log', self._open_debug_log_file),
                ('file-text.svg', 'Open crash.log', 'Open Local AppData\\Session Sniffer\\Debug\\crash.log', self._open_crash_log_file),
            ],
        )

        data_menu.addSeparator()

        self._add_i18n_menu_actions(
            data_menu,
            [
                ('file-cog.svg', 'Open settings.json', 'Open Roaming AppData\\Session Sniffer\\settings.json', self._open_settings_file),
            ],
        )

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
        dialog.setWindowTitle(tr('About {title}', title=TITLE))
        dialog.setMinimumWidth(scale_by_ui(440))

        layout = QVBoxLayout(dialog)
        layout.setSpacing(6)

        style = dialog.style()
        if style:
            icon_label = QLabel()
            icon_label.setPixmap(style.standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation).pixmap(32, 32))
            icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(icon_label)

        title_label = QLabel(f'<b style="font-size:13pt">{html.escape(TITLE)}</b>')
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)

        desc_label = QLabel(tr('A packet sniffer designed for Peer-To-Peer (P2P) video games on PC and consoles.'))
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)

        layout.addSpacing(6)

        build_header = QLabel(f'<b>{html.escape(tr("Build Information"))}</b>')
        layout.addWidget(build_header)
        build_sep = QFrame()
        build_sep.setFrameShape(QFrame.Shape.HLine)
        build_sep.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(build_sep)
        build_info = QLabel(
            '<table cellspacing="2">'
            f'<tr><td><b>{html.escape(tr("Version"))}</b></td><td>&nbsp;&nbsp;{html.escape(VERSION)}</td></tr>'
            '<tr><td style="padding-top:0px"></td></tr>'
            f'<tr><td><b>{html.escape(tr("Release Tag"))}</b></td><td>&nbsp;&nbsp;{html.escape(str(RELEASE_TAG))}</td></tr>'
            f'<tr><td><b>{html.escape(tr("Release Date"))}</b></td><td>&nbsp;&nbsp;{html.escape(str(RELEASE_DATE))}</td></tr>'
            f'<tr><td><b>{html.escape(tr("Commit Sha"))}</b></td><td>&nbsp;&nbsp;{html.escape(str(COMMIT_SHA))}</td></tr>'
            f'<tr><td><b>{html.escape(tr("Commit Date"))}</b></td><td>&nbsp;&nbsp;{html.escape(str(COMMIT_DATE))}</td></tr>'
            '<tr><td style="padding-top:0px"></td></tr>'
            f'<tr><td><b>{html.escape(tr("PySide6 Version"))}</b></td><td>&nbsp;&nbsp;{html.escape(PYSIDE6_VERSION)}</td></tr>'
            f'<tr><td><b>{html.escape(tr("OS Info"))}</b></td><td>&nbsp;&nbsp;{html.escape(OS_INFO)}</td></tr>'
            '</table>',
        )
        build_info.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(build_info)

        layout.addSpacing(8)

        button_box = QDialogButtonBox()
        copy_button = button_box.addButton(tr('Copy Details'), QDialogButtonBox.ButtonRole.ActionRole)
        close_button = button_box.addButton(QDialogButtonBox.StandardButton.Close)
        if close_button:
            close_button.setText(tr('Close'))

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
        help_menu = menu_bar.addMenu(tr('Help'))
        if not help_menu:
            message = 'Failed to create Help menu'
            raise RuntimeError(message)
        help_menu.setToolTipsVisible(True)
        self._register_i18n_menu(help_menu, 'Help')

        self._add_i18n_menu_actions(
            help_menu,
            [
                ('github.svg', 'Project Repository', 'Open the Session Sniffer GitHub repository in your default web browser', self._open_project_repo),
                ('book-text.svg', 'Documentation', 'View the complete documentation and user guide for Session Sniffer', self._open_documentation),
                ('lightbulb.svg', 'Tips and Tricks', 'Learn optimization strategies, hidden features, and best practices', self._open_tips_and_tricks),
                ('rotate-ccw-clock.svg', 'Release Notes', 'View the release history and notes on GitHub', self._open_release_notes),
                ('scale.svg', 'View License', 'View the GNU General Public License (GPLv3) for Session Sniffer', self._view_license),
                None,
                ('bug.svg', 'Report Issue', 'Open a new issue on GitHub to report a bug or request a feature', self._report_issue),
                ('discord.svg', 'Discord Server', 'Join the official Session Sniffer Discord community for support and updates', self._join_discord),
                None,
                ('cloud-download.svg', 'Check for Updates', 'Check GitHub for a newer version of Session Sniffer', self._check_for_updates),
                None,
            ],
        )

        about_action = QAction(QIcon(str(ICONS_DIR_PATH / 'info.svg')), tr('About'), self)
        about_action.setToolTip(tr('About {title}', title=TITLE))
        about_action.triggered.connect(self._show_about_dialog)
        help_menu.addAction(about_action)
        self._files_about_action = about_action
