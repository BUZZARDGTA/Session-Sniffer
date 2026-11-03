"""Dark-themed crash report dialog with embedded traceback, clipboard copy, and native fallback."""

import html
import logging
import traceback
import webbrowser
from collections import deque
from dataclasses import dataclass, field
from threading import Event
from typing import TYPE_CHECKING

from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot
from PySide6.QtGui import QColor, QFont, QIcon
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
)

from session_sniffer import msgbox
from session_sniffer.constants._build_info import COMMIT_DATE, COMMIT_SHA, OS_INFO, PYSIDE6_VERSION, RELEASE_DATE, RELEASE_TAG
from session_sniffer.constants.local import CRASH_LOG_PATH, DEBUG_DIR_PATH, DEBUG_LOG_PATH, VERSION
from session_sniffer.constants.standalone import DISCORD_INVITE_URL, GITHUB_ISSUES_URL, TITLE
from session_sniffer.guis._dialog_mixins import DraggableDialogMixin
from session_sniffer.guis.app import app
from session_sniffer.guis.fonts import get_monospace_font, get_ui_font
from session_sniffer.guis.stylesheets import (
    CRASH_DIALOG_BADGE_STYLESHEET,
    CRASH_DIALOG_EXIT_BUTTON_STYLESHEET,
    CRASH_DIALOG_FRAME_STYLESHEET,
    CRASH_DIALOG_ICON_CONTAINER_STYLESHEET,
    CRASH_DIALOG_INFO_CARD_STYLESHEET,
    CRASH_DIALOG_KICKER_LABEL_STYLESHEET,
    CRASH_DIALOG_PRIMARY_BUTTON_STYLESHEET,
    CRASH_DIALOG_SECONDARY_BUTTON_STYLESHEET,
    CRASH_DIALOG_SECTION_LABEL_STYLESHEET,
    CRASH_DIALOG_SUBTITLE_LABEL_STYLESHEET,
    CRASH_DIALOG_TRACEBACK_EDIT_STYLESHEET,
    DEPENDENCY_PROMPT_CLOSE_BUTTON_STYLESHEET,
    DEPENDENCY_PROMPT_DIALOG_STYLESHEET,
    DEPENDENCY_PROMPT_MESSAGE_LABEL_STYLESHEET,
    DEPENDENCY_PROMPT_TITLE_LABEL_STYLESHEET,
    UPDATE_DOWNLOAD_DIVIDER_STYLESHEET,
)
from session_sniffer.guis.utils import (
    animate_button_feedback,
    center_window_on_screen,
    open_file_location,
    render_svg_pixmap_from_resource,
    scale_by_ui,
    set_clipboard_text,
)
from session_sniffer.logging_setup import redact_text

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

logger = logging.getLogger(__name__)

_GUI_DISPATCH_TIMEOUT_SECONDS = 1.5
_DEBUG_LOG_TAIL_LINES = 40
_MAX_BADGE_TEXT_LEN = 48


def _format_exception_details(
    exc_info: tuple[type[BaseException], BaseException, TracebackType | None] | None,
) -> tuple[str, str, str]:
    """Return `(exc_type_name, exc_summary, formatted_traceback)` with secrets redacted."""
    if exc_info is not None:
        exc_type, exc_value, exc_tb = exc_info
        exc_type_name = exc_type.__name__
        value_text = str(exc_value).strip()
        raw_summary = f'{exc_type_name}: {value_text}' if value_text else exc_type_name
        raw_traceback = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb)).rstrip()
        return (
            exc_type_name,
            redact_text(raw_summary),
            redact_text(raw_traceback),
        )

    summary = 'Unhandled application crash'
    return 'Crash', summary, summary


def _read_debug_log_tail() -> str:
    """Return the last `_DEBUG_LOG_TAIL_LINES` lines from `debug.log` with secrets redacted."""
    try:
        if not DEBUG_LOG_PATH.is_file():
            return ''
        with DEBUG_LOG_PATH.open('r', encoding='utf-8', errors='replace') as debug_file:
            tail_lines = deque(debug_file, maxlen=_DEBUG_LOG_TAIL_LINES)
        return redact_text(''.join(tail_lines).rstrip())
    except OSError:
        return ''


def _build_display_traceback_text(
    thread_name: str,
    terminate_method: str,
    exc_summary: str,
    formatted_traceback: str,
) -> str:
    """Build the text displayed inside the dialog's read-only traceback box."""
    lines = [
        f'Version:   {VERSION} (Tag: {RELEASE_TAG} | Commit: {COMMIT_SHA})',
        f'System:    {OS_INFO} | PySide6: {PYSIDE6_VERSION}',
        f'Thread:    {thread_name} (Method: {terminate_method})',
        f'Exception: {exc_summary}',
        '─' * 64,
        formatted_traceback,
    ]
    return '\n'.join(lines)


def _build_clipboard_crash_report(
    thread_name: str,
    terminate_method: str,
    exc_summary: str,
    formatted_traceback: str,
) -> str:
    """Build a Markdown-formatted crash report suitable for pasting into GitHub Issues or Discord."""
    sections = [
        f'### {TITLE} Crash Report',
        '```',
        f'Version:         {VERSION}',
        f'Release Tag:     {RELEASE_TAG} ({RELEASE_DATE})',
        f'Commit SHA:      {COMMIT_SHA} ({COMMIT_DATE})',
        f'PySide6 Version: {PYSIDE6_VERSION}',
        f'OS Info:         {OS_INFO}',
        f'Thread:          {thread_name} (method={terminate_method})',
        f'Exception:       {exc_summary}',
        '',
        formatted_traceback,
    ]
    debug_tail = _read_debug_log_tail()
    if debug_tail:
        sections.extend(
            [
                '',
                '--- Recent debug.log tail ---',
                debug_tail,
            ],
        )
    sections.append('```')
    return '\n'.join(sections)


def _format_fallback_msgbox_text(
    thread_name: str,
    terminate_method: str,
    exc_summary: str,
    formatted_traceback: str,
) -> str:
    """Format the plain-text crash message used when falling back to a native OS message box."""
    return (
        'An unexpected (uncaught) error occurred.\n\n'
        f'Version: {VERSION} ({OS_INFO})\n'
        f'Thread: {thread_name} ({terminate_method})\n'
        f'Error: {exc_summary}\n\n'
        f'{formatted_traceback}\n\n'
        'Please kindly report it on GitHub Issues or our Discord server:\n'
        f'• GitHub Issues:\n  {GITHUB_ISSUES_URL}\n'
        f'• Discord Server:\n  {DISCORD_INVITE_URL}\n\n'
        'IMPORTANT: Please attach the following log files with your report so the issue can be diagnosed and fixed:\n'
        f'• {CRASH_LOG_PATH}\n'
        f'• {DEBUG_LOG_PATH}'
    )


@dataclass
class _CrashDialogRequest:
    """Thread-safe request payload for displaying the crash dialog on the main GUI thread."""

    thread_name: str
    exc_type_name: str
    display_traceback: str
    clipboard_report: str
    started_event: Event = field(default_factory=Event)
    finished_event: Event = field(default_factory=Event)
    aborted: bool = False
    failed: bool = False


class CrashDialog(DraggableDialogMixin, QDialog):
    """Frameless dark-themed dialog presenting crash diagnostics, traceback, and reporting actions."""

    def __init__(self, request: _CrashDialogRequest) -> None:
        """Initialize the crash report dialog."""
        super().__init__(None)
        self._request = request

        self.setWindowTitle(f'{TITLE} — Unhandled Exception')
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.Dialog
            | Qt.WindowType.WindowStaysOnTopHint,
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, on=True)
        self.setStyleSheet(DEPENDENCY_PROMPT_DIALOG_STYLESHEET)

        card_frame = QFrame(self)
        card_frame.setObjectName('crashDialogFrame')
        card_frame.setStyleSheet(CRASH_DIALOG_FRAME_STYLESHEET)

        drop_shadow = QGraphicsDropShadowEffect(card_frame)
        drop_shadow.setBlurRadius(36)
        drop_shadow.setOffset(0, 8)
        drop_shadow.setColor(QColor(0, 0, 0, 195))
        card_frame.setGraphicsEffect(drop_shadow)

        body_layout = QVBoxLayout(card_frame)
        pad_x = scale_by_ui(22)
        pad_y = scale_by_ui(18)
        body_layout.setContentsMargins(pad_x, pad_y, pad_x, pad_y)
        body_layout.setSpacing(scale_by_ui(12))

        body_layout.addLayout(self._create_header_row())
        body_layout.addWidget(self._create_separator())
        body_layout.addWidget(self._create_reporting_card())
        body_layout.addLayout(self._create_traceback_panel())
        body_layout.addWidget(self._create_separator())
        body_layout.addLayout(self._create_action_bar())

        root_layout = QVBoxLayout(self)
        margin = scale_by_ui(16)
        root_layout.setContentsMargins(margin, margin, margin, margin)
        root_layout.addWidget(card_frame)

        self.setFixedWidth(max(720, scale_by_ui(840)))
        self.adjustSize()
        self.setFixedSize(self.size())
        center_window_on_screen(self)

    @staticmethod
    def _create_separator() -> QFrame:
        """Create a horizontal separator line widget."""
        sep = QFrame()
        sep.setStyleSheet(UPDATE_DOWNLOAD_DIVIDER_STYLESHEET)
        return sep

    def _create_header_row(self) -> QHBoxLayout:
        """Build the top header with danger icon badge, kicker, title, build subtitle, and close button."""
        badge_box = QFrame()
        badge_box.setObjectName('crashDialogIconContainer')
        badge_box.setStyleSheet(CRASH_DIALOG_ICON_CONTAINER_STYLESHEET)
        badge_size = scale_by_ui(40)
        badge_box.setFixedSize(badge_size, badge_size)

        glyph_size = scale_by_ui(22)
        bug_label = QLabel(badge_box)
        bug_label.setPixmap(render_svg_pixmap_from_resource('bug.svg', glyph_size, glyph_size, tint_color='#f87171'))
        bug_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bug_label.setStyleSheet('background: transparent;')

        badge_layout = QVBoxLayout(badge_box)
        badge_layout.setContentsMargins(0, 0, 0, 0)
        badge_layout.addWidget(bug_label, 0, Qt.AlignmentFlag.AlignCenter)

        kicker_label = QLabel('UNHANDLED EXCEPTION')
        kicker_label.setFont(get_ui_font(scale_by_ui(8), QFont.Weight.Bold))
        kicker_label.setStyleSheet(CRASH_DIALOG_KICKER_LABEL_STYLESHEET)

        heading_label = QLabel('An Unexpected Error Occurred')
        heading_label.setFont(get_ui_font(scale_by_ui(13), QFont.Weight.Bold))
        heading_label.setStyleSheet(DEPENDENCY_PROMPT_TITLE_LABEL_STYLESHEET)

        meta_label = QLabel(f'{VERSION}  •  {OS_INFO}  •  Thread: {self._request.thread_name}')
        meta_label.setFont(get_ui_font(scale_by_ui(8)))
        meta_label.setStyleSheet(CRASH_DIALOG_SUBTITLE_LABEL_STYLESHEET)

        text_stack = QVBoxLayout()
        text_stack.setSpacing(scale_by_ui(2))
        text_stack.setContentsMargins(0, 0, 0, 0)
        text_stack.addWidget(kicker_label)
        text_stack.addWidget(heading_label)
        text_stack.addWidget(meta_label)

        dismiss_btn = QPushButton('\u00d7')
        dismiss_btn.setObjectName('dependencyPromptCloseButton')
        dismiss_btn.setStyleSheet(DEPENDENCY_PROMPT_CLOSE_BUTTON_STYLESHEET)
        dismiss_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        dismiss_btn.setToolTip('Close and exit')
        dismiss_btn.clicked.connect(self.reject)

        row = QHBoxLayout()
        row.setSpacing(scale_by_ui(12))
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(badge_box, 0, Qt.AlignmentFlag.AlignVCenter)
        row.addLayout(text_stack, 1)
        row.addWidget(dismiss_btn, 0, Qt.AlignmentFlag.AlignTop)
        return row

    @staticmethod
    def _create_reporting_card() -> QFrame:
        """Build the structured reporting instructions card with separate lines for links and log paths."""
        card = QFrame()
        card.setObjectName('crashDialogInfoCard')
        card.setStyleSheet(CRASH_DIALOG_INFO_CARD_STYLESHEET)

        escaped_github = html.escape(GITHUB_ISSUES_URL)
        escaped_discord = html.escape(DISCORD_INVITE_URL)
        escaped_crash_log = html.escape(str(CRASH_LOG_PATH))
        escaped_debug_log = html.escape(str(DEBUG_LOG_PATH))

        info_html = (
            '<div style="line-height: 1.45;">'
            'Please kindly report this error on <b>GitHub Issues</b> or our <b>Discord server</b>:<br>'
            f'&bull; <b>GitHub Issues:</b><br>&nbsp;&nbsp;&nbsp;<a href="{escaped_github}" style="color: #5fb4f5; text-decoration: none;">{escaped_github}</a><br>'
            f'&bull; <b>Discord Server:</b><br>&nbsp;&nbsp;&nbsp;<a href="{escaped_discord}" style="color: #5fb4f5; text-decoration: none;">{escaped_discord}</a>'
            '<br><br>'
            '<b>IMPORTANT:</b> Click <b>Copy Crash Report</b> below to include the full traceback in your report, '
            'or attach these log files:<br>'
            f'&bull; <span style="color: #93c5fd; font-family: Consolas, Menlo, monospace;">{escaped_crash_log}</span><br>'
            f'&bull; <span style="color: #93c5fd; font-family: Consolas, Menlo, monospace;">{escaped_debug_log}</span>'
            '</div>'
        )

        msg_label = QLabel(info_html, card)
        msg_label.setTextFormat(Qt.TextFormat.RichText)
        msg_label.setWordWrap(True)
        msg_label.setOpenExternalLinks(True)
        msg_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        msg_label.setFont(get_ui_font(scale_by_ui(9)))
        msg_label.setStyleSheet(DEPENDENCY_PROMPT_MESSAGE_LABEL_STYLESHEET)

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(scale_by_ui(14), scale_by_ui(11), scale_by_ui(14), scale_by_ui(11))
        card_layout.setSpacing(scale_by_ui(4))
        card_layout.addWidget(msg_label)
        return card

    def _create_traceback_panel(self) -> QVBoxLayout:
        """Build the embedded exception traceback viewer section."""
        section_label = QLabel('EXCEPTION TRACEBACK & DIAGNOSTICS')
        section_label.setFont(get_ui_font(scale_by_ui(8), QFont.Weight.Bold))
        section_label.setStyleSheet(CRASH_DIALOG_SECTION_LABEL_STYLESHEET)

        badge_text = self._request.exc_type_name
        if len(badge_text) > _MAX_BADGE_TEXT_LEN:
            badge_text = f'{badge_text[: _MAX_BADGE_TEXT_LEN - 1]}…'
        badge_label = QLabel(badge_text)
        badge_label.setFont(get_monospace_font(scale_by_ui(8), QFont.Weight.Bold))
        badge_label.setStyleSheet(CRASH_DIALOG_BADGE_STYLESHEET)
        badge_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        header_row = QHBoxLayout()
        header_row.setContentsMargins(0, 0, 0, 0)
        header_row.setSpacing(scale_by_ui(8))
        header_row.addWidget(section_label)
        header_row.addStretch(1)
        header_row.addWidget(badge_label)

        traceback_edit = QPlainTextEdit()
        traceback_edit.setObjectName('crashDialogTracebackEdit')
        traceback_edit.setReadOnly(True)
        traceback_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        traceback_edit.setFont(get_monospace_font(scale_by_ui(9)))
        traceback_edit.setStyleSheet(CRASH_DIALOG_TRACEBACK_EDIT_STYLESHEET)
        traceback_edit.setPlainText(self._request.display_traceback)
        traceback_edit.setFixedHeight(scale_by_ui(240))

        panel = QVBoxLayout()
        panel.setContentsMargins(0, 0, 0, 0)
        panel.setSpacing(scale_by_ui(6))
        panel.addLayout(header_row)
        panel.addWidget(traceback_edit)
        return panel

    @staticmethod
    def _make_action_button(
        label: str,
        stylesheet: str,
        tooltip: str,
        callback: Callable[[], None],
        *,
        icon_file: str | None = None,
    ) -> QPushButton:
        """Create a styled footer action button with optional SVG icon."""
        btn = QPushButton(label)
        btn.setStyleSheet(stylesheet)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setFixedHeight(scale_by_ui(34))
        btn.setToolTip(tooltip)
        if icon_file is not None:
            icon_px = scale_by_ui(15)
            tint = '#ffffff' if icon_file == 'copy.svg' else None
            btn.setIcon(QIcon(render_svg_pixmap_from_resource(icon_file, icon_px, icon_px, tint_color=tint)))
        btn.clicked.connect(callback)
        return btn

    def _create_action_bar(self) -> QHBoxLayout:
        """Build the footer action bar with Copy Report, Open Debug Folder, GitHub, Discord, and Exit buttons."""
        self._copy_button = self._make_action_button(
            '  Copy Crash Report',
            CRASH_DIALOG_PRIMARY_BUTTON_STYLESHEET,
            'Copy version info, exception traceback, and recent debug log lines to the clipboard',
            self._on_copy_crash_report,
            icon_file='copy.svg',
        )
        open_folder_btn = self._make_action_button(
            '  Open Debug Folder',
            CRASH_DIALOG_SECONDARY_BUTTON_STYLESHEET,
            f'Open {DEBUG_DIR_PATH} in your file manager to attach crash.log and debug.log',
            self._on_open_debug_folder,
            icon_file='folder.svg',
        )
        github_btn = self._make_action_button(
            '  GitHub Issues',
            CRASH_DIALOG_SECONDARY_BUTTON_STYLESHEET,
            'Open GitHub Issues in your default browser',
            self._on_open_github,
            icon_file='github.svg',
        )
        discord_btn = self._make_action_button(
            '  Discord',
            CRASH_DIALOG_SECONDARY_BUTTON_STYLESHEET,
            'Open the Session Sniffer Discord server in your default browser',
            self._on_open_discord,
            icon_file='discord.svg',
        )
        exit_btn = self._make_action_button(
            'Exit',
            CRASH_DIALOG_EXIT_BUTTON_STYLESHEET,
            'Close this dialog and terminate the application',
            self.reject,
        )

        footer = QHBoxLayout()
        footer.setContentsMargins(0, 0, 0, 0)
        footer.setSpacing(scale_by_ui(8))
        footer.addWidget(self._copy_button)
        footer.addWidget(open_folder_btn)
        footer.addWidget(github_btn)
        footer.addWidget(discord_btn)
        footer.addStretch(1)
        footer.addWidget(exit_btn)
        return footer

    def _on_copy_crash_report(self) -> None:
        """Copy the formatted crash report to the system clipboard and animate button feedback."""
        set_clipboard_text(self._request.clipboard_report)
        animate_button_feedback(
            self._copy_button,
            feedback_text='  Copied!',
            feedback_tooltip='Crash report copied to clipboard!',
        )

    @staticmethod
    def _on_open_debug_folder() -> None:
        """Open the Debug logs folder and select crash.log if present."""
        DEBUG_DIR_PATH.mkdir(parents=True, exist_ok=True)
        target_path = CRASH_LOG_PATH if CRASH_LOG_PATH.is_file() else DEBUG_DIR_PATH
        open_file_location(target_path)

    @staticmethod
    def _on_open_github() -> None:
        """Open the GitHub Issues page in the default web browser."""
        webbrowser.open(GITHUB_ISSUES_URL)

    @staticmethod
    def _on_open_discord() -> None:
        """Open the Discord server invite in the default web browser."""
        webbrowser.open(DISCORD_INVITE_URL)


def _execute_crash_dialog_on_gui_thread(request: _CrashDialogRequest) -> None:
    """Instantiate and run `CrashDialog` modally on the main Qt GUI thread."""
    dialog = CrashDialog(request)
    dialog.show()
    dialog.raise_()
    dialog.activateWindow()
    dialog.exec()


class _CrashDialogDispatcher(QObject):
    """Thread-safe dispatcher that runs `CrashDialog` on the main Qt thread with a non-blocking handshake."""

    request_dialog: Signal = Signal(object)

    def __init__(self) -> None:
        """Initialize the dispatcher and bind it to the main Qt application thread."""
        super().__init__()
        self.moveToThread(app.thread())
        self.request_dialog.connect(self._handle_request, Qt.ConnectionType.QueuedConnection)

    @Slot(object)
    def _handle_request(self, request: _CrashDialogRequest) -> None:
        """Execute the crash dialog on the main GUI thread if the request has not timed out."""
        if request.aborted:
            request.finished_event.set()
            return
        request.started_event.set()
        try:
            _execute_crash_dialog_on_gui_thread(request)
        except (RuntimeError, OSError, ValueError, TypeError):
            logger.exception('Failed to display Qt crash dialog on GUI thread')
            request.failed = True
        finally:
            request.finished_event.set()


_dispatcher = _CrashDialogDispatcher()


def show_crash_dialog(
    *,
    thread_name: str,
    terminate_method: str,
    exc_info: tuple[type[BaseException], BaseException, TracebackType | None] | None = None,
) -> None:
    """Display the dark-themed `CrashDialog` on the GUI thread, or fall back to a native message box.

    When called from a background thread, dispatches to the main Qt thread via a non-blocking
    queued signal and waits up to `_GUI_DISPATCH_TIMEOUT_SECONDS` for the main thread to accept
    and display the dialog. If the main thread is unresponsive or deadlocked, immediately falls
    back to `msgbox.show` on the calling thread so the crash notification is never lost.
    """
    exc_type_name, exc_summary, formatted_traceback = _format_exception_details(exc_info)
    display_traceback = _build_display_traceback_text(thread_name, terminate_method, exc_summary, formatted_traceback)
    clipboard_report = _build_clipboard_crash_report(thread_name, terminate_method, exc_summary, formatted_traceback)

    request = _CrashDialogRequest(
        thread_name=thread_name,
        exc_type_name=exc_type_name,
        display_traceback=display_traceback,
        clipboard_report=clipboard_report,
    )

    if QThread.currentThread() == app.thread():
        try:
            _execute_crash_dialog_on_gui_thread(request)
        except (RuntimeError, OSError, ValueError, TypeError):
            logger.exception('Failed to display Qt crash dialog on main thread; falling back to native message box')
        else:
            return
    else:
        _dispatcher.request_dialog.emit(request)
        if request.started_event.wait(timeout=_GUI_DISPATCH_TIMEOUT_SECONDS):
            request.finished_event.wait()
            if not request.failed:
                return
        else:
            request.aborted = True
            logger.warning(
                'Main GUI thread did not respond within %.1fs; falling back to native message box for crash report',
                _GUI_DISPATCH_TIMEOUT_SECONDS,
            )

    fallback_text = _format_fallback_msgbox_text(thread_name, terminate_method, exc_summary, formatted_traceback)
    msgbox_style = msgbox.Style.MB_OK | msgbox.Style.MB_ICONERROR | msgbox.Style.MB_SYSTEMMODAL
    msgbox.show(TITLE, fallback_text, msgbox_style)
