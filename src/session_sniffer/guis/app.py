"""Central QApplication instance for the entire application.

This module ensures there's only one QApplication instance throughout the application.
"""

import ctypes
import gc
import logging
import os
import sys
from typing import Final, cast, override

from PySide6.QtCore import (
    QAbstractEventDispatcher,
    QCoreApplication,
    QEvent,
    QFileSystemWatcher,
    QMessageLogContext,
    QObject,
    Qt,
    QTimer,
    QtMsgType,
    qInstallMessageHandler,
)
from PySide6.QtGui import QIcon, QWheelEvent
from PySide6.QtWidgets import (
    QAbstractScrollArea,
    QAbstractSpinBox,
    QApplication,
    QComboBox,
    QDial,
    QSlider,
    QWidget,
)
from shiboken6 import getCppPointer, isValid

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.guis.theme import get_dark_palette
from session_sniffer.logging_setup import dump_crash_diagnostics, flush_all_loggers

logger = logging.getLogger(__name__)

if sys.platform == 'win32':
    _kernel32 = ctypes.windll.kernel32  # pyright: ignore[reportAttributeAccessIssue]
    _kernel32.IsBadReadPtr.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    _kernel32.IsBadReadPtr.restype = ctypes.c_bool


def _get_purecall_target() -> int | None:
    if sys.platform != 'win32':
        return None
    try:
        vcruntime = ctypes.CDLL('vcruntime140.dll')
        purecall_func = vcruntime['_purecall']
        return ctypes.cast(purecall_func, ctypes.c_void_p).value
    except (AttributeError, KeyError, OSError, ValueError):
        return None


_PURECALL_TARGET: Final[int | None] = _get_purecall_target()
_X64_JMP_OPCODE_0: Final[int] = 0xFF
_X64_JMP_OPCODE_1: Final[int] = 0x25


def _resolves_to_purecall(function_pointer: int) -> bool:
    """Check whether a function pointer points to or jumps to the MSVC CRT _purecall handler."""
    if _PURECALL_TARGET is not None and function_pointer == _PURECALL_TARGET:
        return True
    if sys.platform != 'win32':
        return False
    if _kernel32.IsBadReadPtr(function_pointer, 6):
        return True
    try:
        opcode_0 = ctypes.c_uint8.from_address(function_pointer).value
        opcode_1 = ctypes.c_uint8.from_address(function_pointer + 1).value
        if opcode_0 == _X64_JMP_OPCODE_0 and opcode_1 == _X64_JMP_OPCODE_1:  # jmp qword ptr [rip + displacement]
            displacement = ctypes.c_int32.from_address(function_pointer + 2).value
            iat_entry = function_pointer + 6 + displacement
            if not _kernel32.IsBadReadPtr(iat_entry, 8):
                resolved_target = ctypes.c_uint64.from_address(iat_entry).value
                return _PURECALL_TARGET is not None and resolved_target == _PURECALL_TARGET
    except (OSError, ValueError):
        return False
    return False


def sanitize_native_event_filters() -> None:
    """Sanitize QAbstractEventDispatcher native event filters to eliminate dangling purecall filters."""
    if sys.platform != 'win32':
        return
    dispatcher = cast('QAbstractEventDispatcher | None', QAbstractEventDispatcher.instance())
    if dispatcher is None:
        return
    cpp_pointers = getCppPointer(dispatcher)
    if not cpp_pointers or not cpp_pointers[0]:
        return
    try:
        d_pointer = ctypes.c_uint64.from_address(cpp_pointers[0] + 8).value
        if not d_pointer or _kernel32.IsBadReadPtr(d_pointer + 0x80, 16):
            return
        filter_count = ctypes.c_uint64.from_address(d_pointer + 0x88).value
        filters_array = ctypes.c_uint64.from_address(d_pointer + 0x80).value
        if not filters_array or not filter_count or _kernel32.IsBadReadPtr(filters_array, filter_count * 8):
            return
        for index in range(filter_count):
            slot_address = filters_array + index * 8
            object_pointer = ctypes.c_uint64.from_address(slot_address).value
            if not object_pointer:
                continue
            if _kernel32.IsBadReadPtr(object_pointer, 8):
                ctypes.c_uint64.from_address(slot_address).value = 0
                continue
            vtable = ctypes.c_uint64.from_address(object_pointer).value
            if not vtable or _kernel32.IsBadReadPtr(vtable + 8, 8):
                ctypes.c_uint64.from_address(slot_address).value = 0
                continue
            slot1 = ctypes.c_uint64.from_address(vtable + 8).value
            if _resolves_to_purecall(slot1):
                logger.debug('Zeroed out dead native event filter at slot index %d', index)
                ctypes.c_uint64.from_address(slot_address).value = 0
    except (OSError, ValueError) as e:
        logger.debug('Native event filter sanitization skipped: %s', e)


def _qt_message_handler(message_type: QtMsgType, context: QMessageLogContext, message: str) -> None:
    if message_type != QtMsgType.QtFatalMsg and (
        'Portal operation not allowed' in message
        or 'QFileSystemWatcher: FindNextChangeNotification failed' in message
        or 'QThreadStorage: entry' in message
        or 'QWaitCondition: Destroyed while threads are still waiting' in message
    ):
        return
    type_name = {
        QtMsgType.QtDebugMsg: 'DEBUG',
        QtMsgType.QtInfoMsg: 'INFO',
        QtMsgType.QtWarningMsg: 'WARNING',
        QtMsgType.QtCriticalMsg: 'CRITICAL',
        QtMsgType.QtFatalMsg: 'FATAL',
    }.get(message_type, 'UNKNOWN')
    ctx_info = f' ({context.file}:{context.line}, {context.function})' if context.file else ''
    full_message = f'Qt {type_name}: {message}{ctx_info}'
    if message_type == QtMsgType.QtFatalMsg:
        logger.critical('%s', full_message)
        dump_crash_diagnostics(full_message)
        flush_all_loggers()
    elif message_type == QtMsgType.QtCriticalMsg:
        logger.error('%s', full_message)
    elif message_type == QtMsgType.QtWarningMsg:
        logger.warning('%s', full_message)
    if message_type in (QtMsgType.QtWarningMsg, QtMsgType.QtCriticalMsg, QtMsgType.QtFatalMsg):
        if sys.stderr is not None:
            sys.stderr.write(f'{full_message}\n')
            sys.stderr.flush()
    elif sys.stdout is not None:
        sys.stdout.write(f'{full_message}\n')
        sys.stdout.flush()


def _configure_platform_qt_environment() -> None:
    if sys.platform != 'win32':
        existing_logging_rules: str = os.environ.get('QT_LOGGING_RULES', '')
        suppression_rule: str = 'qt.qpa.theme.gnome=false'
        os.environ['QT_LOGGING_RULES'] = f'{existing_logging_rules};{suppression_rule}' if existing_logging_rules else suppression_rule
        # On Wayland, use bradient decorations so window controls (minimize, maximize, close)
        # and dark title bars render reliably without relying on desktop portal D-Bus queries.
        os.environ.setdefault('QT_WAYLAND_DECORATION', 'bradient')

    qInstallMessageHandler(_qt_message_handler)


class _DisableScrollValueChangeFilter(QObject):
    """Filter out mouse wheel events on input widgets so scrolling does not change values or focus."""

    @override
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if not isValid(watched):
            return False
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
                while ancestor is not None and isValid(ancestor):
                    if isinstance(ancestor, QAbstractScrollArea):
                        QCoreApplication.sendEvent(ancestor.viewport(), event)
                        return True
                    ancestor = ancestor.parentWidget()
                return True
        return super().eventFilter(watched, event)

    @staticmethod
    def _is_scroll_value_change_widget(watched: QObject) -> tuple[bool, QWidget | None]:
        if not isValid(watched) or not isinstance(watched, QWidget):
            return False, None
        current_widget: QWidget | None = watched
        while current_widget is not None and isValid(current_widget):
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

_icon_path = RESOURCES_DIR_PATH / 'icons' / ('sonar.ico' if sys.platform == 'win32' else 'sonar.svg')
if not _icon_path.is_file():
    _icon_path = RESOURCES_DIR_PATH / 'icons' / 'sonar.svg'
app.setWindowIcon(QIcon(str(_icon_path)))

_wheel_filter = _DisableScrollValueChangeFilter(app)
app.installEventFilter(_wheel_filter)

# Permanent file watcher keeps the Windows removable drive listener alive for the
# application lifetime, preventing internal Qt drive notification filter churn.
_permanent_file_watcher: QFileSystemWatcher | None = QFileSystemWatcher(app) if sys.platform == 'win32' else None

# In multi-threaded PySide applications with high-frequency worker threads allocating memory,
# automatic cyclic GC running on worker threads causes C++ Qt objects to be destructed on non-GUI
# threads, leading to race conditions and CRT pure virtual function call crashes.
# Disabling multi-threaded automatic GC and running cyclic collection periodically on the GUI thread
# ensures all Qt object destructions occur safely on the thread to which they belong.
gc.disable()


def _perform_gui_maintenance() -> None:
    gc.collect()
    sanitize_native_event_filters()


_gui_maintenance_timer = QTimer(app)
_gui_maintenance_timer.setInterval(5000)
_gui_maintenance_timer.timeout.connect(_perform_gui_maintenance)
_gui_maintenance_timer.start()
