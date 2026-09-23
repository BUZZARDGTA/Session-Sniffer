"""Central QApplication instance for the entire application.

This module ensures there's only one QApplication instance throughout the application.
"""

import os
import sys
from typing import TYPE_CHECKING, cast, override

from PySide6.QtCore import QEvent, QMessageLogContext, QObject, Qt, QtMsgType, qInstallMessageHandler
from PySide6.QtWidgets import (
    QAbstractScrollArea,
    QAbstractSpinBox,
    QApplication,
    QComboBox,
    QDial,
    QSlider,
    QWidget,
)

from session_sniffer.guis.theme import get_dark_palette

if TYPE_CHECKING:
    from PySide6.QtGui import QWheelEvent


def _qt_message_handler(message_type: QtMsgType, _context: QMessageLogContext, message: str) -> None:
    if 'Portal operation not allowed' in message or 'QFileSystemWatcher: FindNextChangeNotification failed' in message:
        return
    if message_type in (QtMsgType.QtWarningMsg, QtMsgType.QtCriticalMsg, QtMsgType.QtFatalMsg):
        sys.stderr.write(f'{message}\n')
    else:
        sys.stdout.write(f'{message}\n')


def _configure_platform_qt_environment() -> None:
    if sys.platform != 'win32':
        existing_logging_rules: str = os.environ.get('QT_LOGGING_RULES', '')
        suppression_rule: str = 'qt.qpa.theme.gnome=false'
        os.environ['QT_LOGGING_RULES'] = f'{existing_logging_rules};{suppression_rule}' if existing_logging_rules else suppression_rule
        # On Wayland, use bradient decorations so window controls (minimize, maximize, close)
        # and dark title bars render reliably without relying on desktop portal D-Bus queries.
        os.environ.setdefault('QT_WAYLAND_DECORATION', 'bradient')

    qInstallMessageHandler(_qt_message_handler)


_FOCUS_POLICY_CHECK_EVENT_TYPES = (
    QEvent.Type.Show,
    QEvent.Type.Polish,
    QEvent.Type.Enter,
    QEvent.Type.HoverEnter,
    QEvent.Type.ChildAdded,
    QEvent.Type.Wheel,
)


class _DisableScrollValueChangeFilter(QObject):
    """Filter out mouse wheel events on input widgets so scrolling does not change values or focus."""

    @override
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if event.type() in _FOCUS_POLICY_CHECK_EVENT_TYPES and isinstance(watched, QWidget):
            if watched.focusPolicy() == Qt.FocusPolicy.WheelFocus:
                watched.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
            if (parent := watched.parentWidget()) is not None and parent.focusPolicy() == Qt.FocusPolicy.WheelFocus:
                parent.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

        if event.type() == QEvent.Type.Wheel:
            is_target, target = self._is_scroll_value_change_widget(watched)
            if is_target and target is not None:
                if target.focusPolicy() == Qt.FocusPolicy.WheelFocus:
                    target.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
                event.ignore()
                ancestor = target.parentWidget()
                while ancestor is not None:
                    ancestor.wheelEvent(cast('QWheelEvent', event))
                    if event.isAccepted():
                        return True
                    ancestor = ancestor.parentWidget()
                return True
        return super().eventFilter(watched, event)

    @staticmethod
    def _is_scroll_value_change_widget(watched: QObject) -> tuple[bool, QWidget | None]:
        if not isinstance(watched, QWidget):
            return False, None
        if isinstance(watched, QAbstractScrollArea):
            return False, None
        parent_widget = watched.parentWidget()
        if isinstance(parent_widget, QAbstractScrollArea):
            return False, None
        if isinstance(watched, (QComboBox, QAbstractSpinBox, QSlider, QDial)):
            return True, watched
        if isinstance(parent_widget, (QComboBox, QAbstractSpinBox, QSlider, QDial)):
            return True, parent_widget
        return False, None


_configure_platform_qt_environment()

# Create the single QApplication instance for the entire application.
# The stylesheet is applied later in main() after the screen size and UI scale
# factor are resolved, so fonts and sizes are correct for every display tier.
app = QApplication([])  # Passing an empty list for application arguments
app.setPalette(get_dark_palette())

_wheel_filter = _DisableScrollValueChangeFilter(app)
app.installEventFilter(_wheel_filter)
