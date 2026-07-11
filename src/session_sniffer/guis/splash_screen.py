"""Frameless splash screen shown during application startup."""

import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, ParamSpec, TypeVar

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QTextCursor
from PySide6.QtWidgets import QApplication, QLabel, QTextEdit, QVBoxLayout, QWidget

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.stylesheets import (
    SPLASH_LOG_AREA_STYLESHEET,
    SPLASH_SCREEN_STYLESHEET,
    SPLASH_SUBTITLE_LABEL_STYLESHEET,
    SPLASH_SUBTITLE_READY_STYLESHEET,
    SPLASH_TITLE_LABEL_STYLESHEET,
)
from session_sniffer.guis.utils import SPINNER_FRAMES, center_window_on_screen

_P = ParamSpec('_P')
_T = TypeVar('_T')

if TYPE_CHECKING:
    from collections.abc import Callable
_SPINNER_COLOR = '#5599dd'
_CHECK_ICON = '✓'
_CHECK_COLOR = '#44cc66'
_READY_COLOR = '#44cc66'
_TEXT_COLOR = '#8899aa'


class SplashScreen(QWidget):
    """Frameless dark splash window that accumulates startup status messages."""

    def __init__(self) -> None:
        """Initialize the startup splash screen."""
        super().__init__()
        self.setWindowTitle(TITLE)
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint,
        )
        self.setFixedSize(560, 340)
        self.setStyleSheet(SPLASH_SCREEN_STYLESHEET)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        title_label = QLabel(TITLE)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setFont(QFont('Segoe UI', 42, QFont.Weight.Bold))
        title_label.setStyleSheet(SPLASH_TITLE_LABEL_STYLESHEET)
        layout.addWidget(title_label)

        self._subtitle = QLabel('Initializing sniffing engine…')
        self._subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._subtitle.setFont(QFont('Segoe UI', 18))
        self._subtitle.setStyleSheet(SPLASH_SUBTITLE_LABEL_STYLESHEET)
        layout.addWidget(self._subtitle)

        self._log_area = QTextEdit()
        self._log_area.setReadOnly(True)
        self._log_area.setFont(QFont('Consolas', 10))
        self._log_area.setStyleSheet(SPLASH_LOG_AREA_STYLESHEET)
        layout.addWidget(self._log_area)

        self._current_message: str | None = None
        self._spinner_index = 0

        self._spinner_timer = QTimer(self)
        self._spinner_timer.setInterval(80)
        self._spinner_timer.timeout.connect(self._animate_spinner)

        self._executor = ThreadPoolExecutor(max_workers=1)

        self._center_on_screen()

    def _center_on_screen(self) -> None:
        """Center the splash window on the primary screen."""
        center_window_on_screen(self)

    @staticmethod
    def _build_line_html(icon: str, icon_color: str, text: str) -> str:
        """Build an HTML line with a colored icon prefix."""
        return f'<span style="color:{icon_color}; font-weight:bold;">{icon}</span>&nbsp;&nbsp;<span style="color:{_TEXT_COLOR};">{text}</span>'

    def _replace_last_line(self, html: str) -> None:
        """Replace the last line in the log area with new HTML content."""
        cursor = self._log_area.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.movePosition(QTextCursor.MoveOperation.StartOfBlock, QTextCursor.MoveMode.KeepAnchor)
        cursor.removeSelectedText()
        cursor.insertHtml(html)

    def _mark_current_done(self) -> None:
        """Replace the spinner on the current line with a checkmark."""
        if self._current_message is not None:
            self._spinner_timer.stop()
            self._replace_last_line(self._build_line_html(_CHECK_ICON, _CHECK_COLOR, self._current_message))

    def _animate_spinner(self) -> None:
        """Advance the spinner animation on the current line."""
        if self._current_message is None:
            return
        self._spinner_index = (self._spinner_index + 1) % len(SPINNER_FRAMES)
        frame = SPINNER_FRAMES[self._spinner_index]
        self._replace_last_line(self._build_line_html(frame, _SPINNER_COLOR, self._current_message))

    def update_status(self, message: str) -> None:
        """Append a status line with an animated spinner, marking the previous line done."""
        self._mark_current_done()

        self._current_message = message
        self._spinner_index = 0
        self._log_area.append(self._build_line_html(SPINNER_FRAMES[0], _SPINNER_COLOR, message))
        self._spinner_timer.start()

        scrollbar = self._log_area.verticalScrollBar()
        if scrollbar:
            scrollbar.setValue(scrollbar.maximum())
        QApplication.processEvents()

    def run_with_spinner(self, fn: Callable[_P, _T], /, *args: _P.args, **kwargs: _P.kwargs) -> _T:
        """Run a callable in a background thread while keeping the spinner animated.

        The Qt event loop is pumped continuously so the spinner QTimer fires.
        Exceptions from the callable are re-raised in the calling thread.
        """
        future = self._executor.submit(fn, *args, **kwargs)
        while not future.done():
            QApplication.processEvents()
            time.sleep(0.016)
        return future.result()

    def finish_loading(self) -> None:
        """Mark the last step done and show a ready message."""
        self._mark_current_done()
        self._current_message = None
        self._subtitle.setText('Ready!')
        self._subtitle.setStyleSheet(SPLASH_SUBTITLE_READY_STYLESHEET)

        ready_html = f'<br><span style="color:{_READY_COLOR}; font-weight:bold;">&#x2714;&nbsp;&nbsp;All systems go &mdash; launching!</span>'
        self._log_area.append(ready_html)

        scrollbar = self._log_area.verticalScrollBar()
        if scrollbar:
            scrollbar.setValue(scrollbar.maximum())
        QApplication.processEvents()

    def close_splash(self) -> None:
        """Close the splash screen."""
        self._spinner_timer.stop()
        self._executor.shutdown(wait=False)
        self.close()

    def lower_to_back(self) -> None:
        """Ensure the splash is not marked always-on-top before continuing startup."""
        if self.windowFlags() & Qt.WindowType.WindowStaysOnTopHint:
            self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, on=False)
            self.show()
