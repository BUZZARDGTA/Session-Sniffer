"""Qt dialog for prompting the user to install a missing dependency or capture driver."""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QIcon
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from session_sniffer.guis._dialog_mixins import DraggableDialogMixin
from session_sniffer.guis.app import app
from session_sniffer.guis.stylesheets import (
    DEPENDENCY_PROMPT_ACTION_BUTTON_STYLESHEET,
    DEPENDENCY_PROMPT_CLOSE_BUTTON_STYLESHEET,
    DEPENDENCY_PROMPT_DIALOG_STYLESHEET,
    DEPENDENCY_PROMPT_EXIT_BUTTON_STYLESHEET,
    DEPENDENCY_PROMPT_FOOTER_HINT_STYLESHEET,
    DEPENDENCY_PROMPT_FRAME_STYLESHEET,
    DEPENDENCY_PROMPT_ICON_CONTAINER_STYLESHEET,
    DEPENDENCY_PROMPT_INFO_CARD_STYLESHEET,
    DEPENDENCY_PROMPT_KICKER_LABEL_STYLESHEET,
    DEPENDENCY_PROMPT_MESSAGE_LABEL_STYLESHEET,
    DEPENDENCY_PROMPT_STATUS_BADGE_STYLESHEET,
    DEPENDENCY_PROMPT_STATUS_CARD_STYLESHEET,
    DEPENDENCY_PROMPT_STATUS_SUBTITLE_STYLESHEET,
    DEPENDENCY_PROMPT_STATUS_TITLE_STYLESHEET,
    DEPENDENCY_PROMPT_TITLE_LABEL_STYLESHEET,
    UPDATE_DOWNLOAD_DIVIDER_STYLESHEET,
)
from session_sniffer.guis.utils import (
    SPINNER_FRAMES,
    center_window_on_screen,
    render_svg_pixmap_from_resource,
    scale_by_ui,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_SPINNER_COLOR = '#38bdf8'


class DependencyPromptDialog(DraggableDialogMixin, QDialog):
    """Frameless dark-themed dialog that informs the user of a missing dependency and polls until it is installed."""

    def __init__(
        self,
        title: str,
        message: str,
        condition: Callable[[], bool],
        *,
        status_callback: Callable[[], tuple[str, str]] | None = None,
        action: tuple[str, Callable[[], None]] | None = None,
    ) -> None:
        """Initialize the dependency prompt dialog."""
        super().__init__(None)
        self._condition = condition
        self._status_callback = status_callback
        self._action = action
        self._spinner_index = 0

        self.setWindowTitle(title)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Dialog)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, on=True)
        self.setStyleSheet(DEPENDENCY_PROMPT_DIALOG_STYLESHEET)

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(scale_by_ui(16), scale_by_ui(16), scale_by_ui(16), scale_by_ui(16))

        container_frame = QFrame()
        container_frame.setObjectName('dependencyPromptFrame')
        container_frame.setStyleSheet(DEPENDENCY_PROMPT_FRAME_STYLESHEET)

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(32)
        shadow.setOffset(0, 8)
        shadow.setColor(QColor(0, 0, 0, 180))
        container_frame.setGraphicsEffect(shadow)

        frame_layout = QVBoxLayout(container_frame)
        frame_layout.setContentsMargins(scale_by_ui(22), scale_by_ui(18), scale_by_ui(22), scale_by_ui(18))
        frame_layout.setSpacing(scale_by_ui(12))

        frame_layout.addLayout(self._build_header(title))
        frame_layout.addWidget(self._build_divider())
        frame_layout.addWidget(self._build_info_card(message))

        if action:
            frame_layout.addLayout(self._build_action_row(action[0]))

        frame_layout.addWidget(self._build_status_card())
        frame_layout.addWidget(self._build_divider())
        frame_layout.addLayout(self._build_footer())

        outer_layout.addWidget(container_frame)
        self.setFixedWidth(scale_by_ui(560))
        self.adjustSize()
        self.setFixedSize(self.size())
        center_window_on_screen(self)

        self._spinner_timer = QTimer(self)
        self._spinner_timer.timeout.connect(self._animate_spinner)
        self._spinner_timer.start(80)

        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._check_condition)
        self._poll_timer.start(500)

    @staticmethod
    def _build_divider() -> QFrame:
        """Build a subtle horizontal divider line."""
        divider = QFrame()
        divider.setStyleSheet(UPDATE_DOWNLOAD_DIVIDER_STYLESHEET)
        return divider

    def _build_header(self, title: str) -> QHBoxLayout:
        """Build the top header with icon badge, category kicker, title, and close button."""
        header_layout = QHBoxLayout()
        header_layout.setSpacing(scale_by_ui(12))
        header_layout.setContentsMargins(0, 0, 0, 0)

        icon_frame = QFrame()
        icon_frame.setObjectName('dependencyPromptIconContainer')
        icon_frame.setStyleSheet(DEPENDENCY_PROMPT_ICON_CONTAINER_STYLESHEET)
        icon_frame.setFixedSize(scale_by_ui(38), scale_by_ui(38))

        icon_inner_layout = QVBoxLayout(icon_frame)
        icon_inner_layout.setContentsMargins(0, 0, 0, 0)
        icon_inner_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        icon_pixmap = render_svg_pixmap_from_resource('ethernet.svg', scale_by_ui(22), scale_by_ui(22))
        icon_label = QLabel()
        icon_label.setPixmap(icon_pixmap)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setStyleSheet('background: transparent;')
        icon_inner_layout.addWidget(icon_label)

        header_layout.addWidget(icon_frame, 0, Qt.AlignmentFlag.AlignVCenter)

        title_column = QVBoxLayout()
        title_column.setSpacing(scale_by_ui(1))
        title_column.setContentsMargins(0, 0, 0, 0)

        kicker_label = QLabel('NETWORK DRIVER')
        kicker_label.setFont(QFont('Segoe UI', scale_by_ui(8), QFont.Weight.Bold))
        kicker_label.setStyleSheet(DEPENDENCY_PROMPT_KICKER_LABEL_STYLESHEET)
        title_column.addWidget(kicker_label)

        title_label = QLabel(title)
        title_label.setFont(QFont('Segoe UI', scale_by_ui(13), QFont.Weight.Bold))
        title_label.setStyleSheet(DEPENDENCY_PROMPT_TITLE_LABEL_STYLESHEET)
        title_column.addWidget(title_label)

        header_layout.addLayout(title_column, 1)

        close_button = QPushButton('✕')
        close_button.setObjectName('dependencyPromptCloseButton')
        close_button.setStyleSheet(DEPENDENCY_PROMPT_CLOSE_BUTTON_STYLESHEET)
        close_button.setCursor(Qt.CursorShape.PointingHandCursor)
        close_button.clicked.connect(self.reject)
        header_layout.addWidget(close_button, 0, Qt.AlignmentFlag.AlignTop)

        return header_layout

    @staticmethod
    def _build_info_card(message: str) -> QFrame:
        """Build the structured informational card with description."""
        card = QFrame()
        card.setObjectName('dependencyPromptInfoCard')
        card.setStyleSheet(DEPENDENCY_PROMPT_INFO_CARD_STYLESHEET)

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(scale_by_ui(14), scale_by_ui(12), scale_by_ui(14), scale_by_ui(12))

        msg_label = QLabel(message)
        msg_label.setWordWrap(True)
        msg_label.setFont(QFont('Segoe UI', scale_by_ui(9)))
        msg_label.setStyleSheet(DEPENDENCY_PROMPT_MESSAGE_LABEL_STYLESHEET)
        card_layout.addWidget(msg_label)

        return card

    def _build_action_row(self, action_text: str) -> QHBoxLayout:
        """Build the primary action button row."""
        button_row = QHBoxLayout()
        button_row.setContentsMargins(0, 0, 0, 0)
        button_row.setSpacing(0)

        action_button = QPushButton(f'  {action_text}')
        action_button.setStyleSheet(DEPENDENCY_PROMPT_ACTION_BUTTON_STYLESHEET)
        action_button.setFont(QFont('Segoe UI', scale_by_ui(9), QFont.Weight.Bold))
        action_button.setCursor(Qt.CursorShape.PointingHandCursor)
        action_icon = render_svg_pixmap_from_resource('website.svg', scale_by_ui(16), scale_by_ui(16))
        action_button.setIcon(QIcon(action_icon))
        action_button.setFixedHeight(scale_by_ui(34))
        action_button.clicked.connect(self._handle_action_clicked)

        button_row.addWidget(action_button)
        return button_row

    def _build_status_card(self) -> QFrame:
        """Build the live auto-detection radar card with animated spinner and listening badge."""
        card = QFrame()
        card.setObjectName('dependencyPromptStatusCard')
        card.setStyleSheet(DEPENDENCY_PROMPT_STATUS_CARD_STYLESHEET)

        layout = QHBoxLayout(card)
        layout.setContentsMargins(scale_by_ui(14), scale_by_ui(8), scale_by_ui(14), scale_by_ui(8))
        layout.setSpacing(scale_by_ui(12))

        self._spinner_label = QLabel(SPINNER_FRAMES[0])
        self._spinner_label.setFont(QFont('Consolas', scale_by_ui(13), QFont.Weight.Bold))
        self._spinner_label.setStyleSheet(f'color: {_SPINNER_COLOR}; background: transparent;')
        self._spinner_label.setFixedWidth(scale_by_ui(22))
        self._spinner_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._spinner_label)

        text_column = QVBoxLayout()
        text_column.setSpacing(scale_by_ui(1))
        text_column.setContentsMargins(0, 0, 0, 0)

        initial_title = 'Listening for installation…'
        initial_subtitle = 'The application will resume automatically once detected.'
        if self._status_callback:
            initial_title, initial_subtitle = self._status_callback()

        self._status_title_label = QLabel(initial_title)
        self._status_title_label.setFont(QFont('Segoe UI', scale_by_ui(9), QFont.Weight.Bold))
        self._status_title_label.setStyleSheet(DEPENDENCY_PROMPT_STATUS_TITLE_STYLESHEET)
        text_column.addWidget(self._status_title_label)

        self._status_subtitle_label = QLabel(initial_subtitle)
        self._status_subtitle_label.setFont(QFont('Segoe UI', scale_by_ui(8)))
        self._status_subtitle_label.setStyleSheet(DEPENDENCY_PROMPT_STATUS_SUBTITLE_STYLESHEET)
        text_column.addWidget(self._status_subtitle_label)

        layout.addLayout(text_column, 1)

        badge_label = QLabel('AUTO-DETECT')
        badge_label.setFont(QFont('Segoe UI', scale_by_ui(7), QFont.Weight.Bold))
        badge_label.setStyleSheet(DEPENDENCY_PROMPT_STATUS_BADGE_STYLESHEET)
        badge_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(badge_label, 0, Qt.AlignmentFlag.AlignVCenter)

        return card

    def _build_footer(self) -> QHBoxLayout:
        """Build the bottom footer row with an informational hint and exit button."""
        footer_layout = QHBoxLayout()
        footer_layout.setContentsMargins(0, 0, 0, 0)
        footer_layout.setSpacing(scale_by_ui(10))

        hint_layout = QHBoxLayout()
        hint_layout.setSpacing(scale_by_ui(6))
        hint_layout.setContentsMargins(0, 0, 0, 0)

        info_icon = render_svg_pixmap_from_resource('info.svg', scale_by_ui(13), scale_by_ui(13))
        info_label = QLabel()
        info_label.setPixmap(info_icon)
        info_label.setStyleSheet('background: transparent;')
        hint_layout.addWidget(info_label, 0, Qt.AlignmentFlag.AlignVCenter)

        hint_label = QLabel('Administrator permissions may be requested during setup')
        hint_label.setFont(QFont('Segoe UI', scale_by_ui(8)))
        hint_label.setStyleSheet(DEPENDENCY_PROMPT_FOOTER_HINT_STYLESHEET)
        hint_layout.addWidget(hint_label, 0, Qt.AlignmentFlag.AlignVCenter)

        footer_layout.addLayout(hint_layout)
        footer_layout.addStretch(1)

        exit_button = QPushButton('Exit Application')
        exit_button.setStyleSheet(DEPENDENCY_PROMPT_EXIT_BUTTON_STYLESHEET)
        exit_button.setFont(QFont('Segoe UI', scale_by_ui(8), QFont.Weight.Bold))
        exit_button.setCursor(Qt.CursorShape.PointingHandCursor)
        exit_button.setFixedHeight(scale_by_ui(28))
        exit_button.clicked.connect(self.reject)
        footer_layout.addWidget(exit_button)

        return footer_layout

    def _handle_action_clicked(self) -> None:
        """Invoke the optional action callback."""
        if self._action:
            self._action[1]()

    def _animate_spinner(self) -> None:
        """Advance the animated spinner frame."""
        self._spinner_index = (self._spinner_index + 1) % len(SPINNER_FRAMES)
        self._spinner_label.setText(SPINNER_FRAMES[self._spinner_index])

    def _check_condition(self) -> None:
        """Check dynamic status, evaluate condition, and auto-close the dialog when satisfied."""
        if self._status_callback:
            status_title, status_subtitle = self._status_callback()
            self._status_title_label.setText(status_title)
            self._status_subtitle_label.setText(status_subtitle)

        if self._condition():
            self._poll_timer.stop()
            self._spinner_timer.stop()
            self.accept()


@dataclass(frozen=True)
class _PromptRequest:
    """Request payload for displaying a dependency prompt on the GUI thread."""

    title: str
    message: str
    condition: Callable[[], bool]
    status_callback: Callable[[], tuple[str, str]] | None = None
    action: tuple[str, Callable[[], None]] | None = None


class _PromptDispatcher(QObject):
    """Thread-safe dispatcher that displays DependencyPromptDialog on the main Qt thread."""

    request_dialog = Signal(_PromptRequest)

    def __init__(self) -> None:
        """Initialize the prompt dispatcher with a blocking queued connection."""
        super().__init__()
        self._result: bool = False
        self.request_dialog.connect(self._handle_request, Qt.ConnectionType.BlockingQueuedConnection)

    def _handle_request(self, request: _PromptRequest) -> None:
        """Instantiate and execute the dialog on the main GUI thread."""
        dialog = DependencyPromptDialog(
            title=request.title,
            message=request.message,
            condition=request.condition,
            status_callback=request.status_callback,
            action=request.action,
        )
        self._result = dialog.exec() == QDialog.DialogCode.Accepted or request.condition()

    @property
    def result(self) -> bool:
        """Get the result of the last dialog execution."""
        return self._result


_dispatcher = _PromptDispatcher()


def show_dependency_prompt(
    title: str,
    message: str,
    condition: Callable[[], bool],
    *,
    status_callback: Callable[[], tuple[str, str]] | None = None,
    action: tuple[str, Callable[[], None]] | None = None,
) -> bool:
    """Display a dependency prompt dialog and wait until condition is satisfied or cancelled.

    Safe to call from either the main GUI thread or background worker threads.

    Args:
        title: Title of the prompt dialog.
        message: Informational message explaining the missing dependency and next steps.
        condition: Callable that returns True once the dependency is satisfied.
        status_callback: Optional callable returning (title, subtitle) for dynamic step reporting.
        action: Optional tuple of (button_text, callback) for the primary action button.

    Returns:
        True if the condition became satisfied, or False if the user cancelled.
    """
    if condition():
        return True

    # If already running on the main GUI thread:
    if QThread.currentThread() == app.thread():
        dialog = DependencyPromptDialog(
            title=title,
            message=message,
            condition=condition,
            status_callback=status_callback,
            action=action,
        )
        return dialog.exec() == QDialog.DialogCode.Accepted or condition()

    request = _PromptRequest(
        title=title,
        message=message,
        condition=condition,
        status_callback=status_callback,
        action=action,
    )
    _dispatcher.request_dialog.emit(request)
    return _dispatcher.result or condition()
