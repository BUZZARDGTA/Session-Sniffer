"""Frameless splash screen shown during application startup."""

import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, ParamSpec, TypeVar

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QTextCursor
from PyQt6.QtWidgets import QApplication, QLabel, QTextEdit, QVBoxLayout, QWidget

from session_sniffer.constants.standalone import TITLE

_P = ParamSpec('_P')
_T = TypeVar('_T')

if TYPE_CHECKING:
    from collections.abc import Callable

_SPINNER_FRAMES = ('⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏')
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
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint,
        )
        self.setFixedSize(560, 340)
        self.setStyleSheet('background-color: #19232d;')

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        title_label = QLabel(TITLE)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setFont(QFont('Segoe UI', 20, QFont.Weight.Bold))
        title_label.setStyleSheet('color: #e0e6ee; background: transparent;')
        layout.addWidget(title_label)

        self._subtitle = QLabel('Initializing sniffing engine\u2009\u2026')
        self._subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._subtitle.setFont(QFont('Segoe UI', 10))
        self._subtitle.setStyleSheet('color: #667788; background: transparent;')
        layout.addWidget(self._subtitle)

        self._log_area = QTextEdit()
        self._log_area.setReadOnly(True)
        self._log_area.setFont(QFont('Consolas', 9))
        self._log_area.setStyleSheet(
            'QTextEdit {'
            '  background-color: #141922;'
            '  color: #8899aa;'
            '  border: 1px solid #2a3544;'
            '  border-radius: 6px;'
            '  padding: 8px;'
            '}',
        )
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
        screen = self.screen()
        if screen is not None:
            geo = screen.availableGeometry()
            x = geo.x() + (geo.width() - self.width()) // 2
            y = geo.y() + (geo.height() - self.height()) // 2
            self.move(x, y)

    @staticmethod
    def _build_line_html(icon: str, icon_color: str, text: str) -> str:
        """Build an HTML line with a colored icon prefix."""
        return (
            f'<span style="color:{icon_color}; font-weight:bold;">{icon}</span>'
            f'&nbsp;&nbsp;<span style="color:{_TEXT_COLOR};">{text}</span>'
        )

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
        self._spinner_index = (self._spinner_index + 1) % len(_SPINNER_FRAMES)
        frame = _SPINNER_FRAMES[self._spinner_index]
        self._replace_last_line(self._build_line_html(frame, _SPINNER_COLOR, self._current_message))

    def update_status(self, message: str) -> None:
        """Append a status line with an animated spinner, marking the previous line done."""
        self._mark_current_done()

        self._current_message = message
        self._spinner_index = 0
        self._log_area.append(self._build_line_html(_SPINNER_FRAMES[0], _SPINNER_COLOR, message))
        self._spinner_timer.start()

        scrollbar = self._log_area.verticalScrollBar()
        if scrollbar is not None:
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
        self._subtitle.setStyleSheet(f'color: {_READY_COLOR}; background: transparent;')

        ready_html = (
            f'<br><span style="color:{_READY_COLOR}; font-weight:bold;">'
            f'&#x2714;&nbsp;&nbsp;All systems go &mdash; launching!</span>'
        )
        self._log_area.append(ready_html)

        scrollbar = self._log_area.verticalScrollBar()
        if scrollbar is not None:
            scrollbar.setValue(scrollbar.maximum())
        QApplication.processEvents()

    def close_splash(self) -> None:
        """Close the splash screen."""
        self._spinner_timer.stop()
        self._executor.shutdown(wait=False)
        self.close()

    def lower_to_back(self) -> None:
        """Remove the always-on-top hint so other windows (e.g. dialogs) can appear above the splash."""
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowStaysOnTopHint)
        self.show()
