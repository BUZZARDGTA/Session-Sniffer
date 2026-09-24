"""Central QApplication instance for the entire application.

This module ensures there's only one QApplication instance throughout the application.
"""

import os
import sys
from typing import override

from PySide6.QtCore import QCoreApplication, QEvent, QMessageLogContext, QObject, Qt, QtMsgType, qInstallMessageHandler
from PySide6.QtGui import QWheelEvent
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

        if event.type() == QEvent.Type.Wheel and isinstance(event, QWheelEvent):
            is_target, target = self._is_scroll_value_change_widget(watched)
            if is_target and target is not None:
                if target.focusPolicy() == Qt.FocusPolicy.WheelFocus:
                    target.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
                # If a combo box popup view is open and active, let the user scroll through the popup list
                if isinstance(target, QComboBox) and target.view().isVisible():
                    return super().eventFilter(watched, event)

                event.ignore()
                ancestor = target.parentWidget()
                while ancestor is not None:
                    if isinstance(ancestor, QAbstractScrollArea):
                        QCoreApplication.sendEvent(ancestor.viewport(), event)
                        return True
                    ancestor = ancestor.parentWidget()
                return True
        return super().eventFilter(watched, event)

    @staticmethod
    def _is_scroll_value_change_widget(watched: QObject) -> tuple[bool, QWidget | None]:
        if not isinstance(watched, QWidget):
            return False, None
        current_widget: QWidget | None = watched
        while current_widget is not None:
            if isinstance(current_widget, QAbstractScrollArea):
                return False, None
            if isinstance(current_widget, (QComboBox, QAbstractSpinBox, QSlider, QDial)):
                return True, current_widget
            current_widget = current_widget.parentWidget()
        return False, None


_configure_platform_qt_environment()

# Create the single QApplication instance for the entire application.
# The stylesheet is applied later in main() after the screen size and UI scale
# factor are resolved, so fonts and sizes are correct for every display tier.
app = QApplication([])  # Passing an empty list for application arguments
app.setPalette(get_dark_palette())

_wheel_filter = _DisableScrollValueChangeFilter(app)
app.installEventFilter(_wheel_filter)
