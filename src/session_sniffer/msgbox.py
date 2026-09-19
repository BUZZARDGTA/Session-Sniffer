"""Message box utilities using native Windows MessageBox API or Qt QMessageBox fallback on Linux.

It defines two main components:
- msgbox.ReturnValues: Enum class representing the possible return values from a MessageBox.
- msgbox.Style: IntFlag class representing the different styles and options available for the MessageBox.

The msgbox.show() method can be used to display a message box with custom buttons, and behavior.
"""
# pylint: disable=implicit-flag-alias

import ctypes
import enum
import sys
import threading
import time
from typing import TYPE_CHECKING

from PySide6.QtCore import QMetaObject, Qt
from PySide6.QtWidgets import QMessageBox

from session_sniffer.error_messages import ensure_instance
from session_sniffer.guis.app import app

if TYPE_CHECKING:
    from collections.abc import Callable


# https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw#parameters
class Style(enum.IntFlag):
    """IntFlag class representing the different styles and options available for the MessageBox.

    This class defines the various button and icon configurations that can be used when displaying a message box.
    """

    MB_ABORTRETRYIGNORE = 0x00000002  # Contains Abort, Retry, and Ignore buttons.
    MB_CANCELTRYCONTINUE = 0x00000006  # Contains Cancel, Try Again, Continue buttons.
    MB_HELP = 0x00004000  # Adds a Help button to the message box.
    MB_OK = 0x00000000  # Contains only the OK button (default).
    MB_OKCANCEL = 0x00000001  # Contains OK and Cancel buttons.
    MB_RETRYCANCEL = 0x00000005  # Contains Retry and Cancel buttons.
    MB_YESNO = 0x00000004  # Contains Yes and No buttons.
    MB_YESNOCANCEL = 0x00000003  # Contains Yes, No, and Cancel buttons.
    MB_ICONEXCLAMATION = 0x00000030  # Displays an Exclamation icon (Warning).
    MB_ICONWARNING = 0x00000030  # Displays a Warning icon.
    MB_ICONINFORMATION = 0x00000040  # Displays an Information icon.
    MB_ICONASTERISK = 0x00000040  # Displays an Asterisk icon (Info).
    MB_ICONQUESTION = 0x00000020  # Displays a Question icon.
    MB_ICONSTOP = 0x00000010  # Displays a Stop icon (Error).
    MB_ICONERROR = 0x00000010  # Displays an Error icon.
    MB_ICONHAND = 0x00000010  # Displays a Hand icon (Error).
    MB_DEFBUTTON1 = 0x00000000  # First button is the default button.
    MB_DEFBUTTON2 = 0x00000100  # Second button is the default button.
    MB_DEFBUTTON3 = 0x00000200  # Third button is the default button.
    MB_DEFBUTTON4 = 0x00000300  # Fourth button is the default button.
    MB_APPLMODAL = 0x00000000  # Application modal; the user must respond before continuing.
    MB_SYSTEMMODAL = 0x00001000  # System modal; all applications are suspended until the user responds.
    MB_TASKMODAL = 0x00002000  # Task modal; blocks input to other windows in the same task.
    MB_DEFAULT_DESKTOP_ONLY = 0x00020000  # Restricts the message box to the default desktop only.
    MB_RIGHT = 0x00080000  # Text in the message box is right-aligned.
    MB_RTLREADING = 0x00100000  # Specifies text should appear right-to-left (for languages like Arabic).
    MB_SETFOREGROUND = 0x00010000  # Brings the message box to the foreground.
    MB_TOPMOST = 0x00040000  # Makes the message box topmost.
    MB_SERVICE_NOTIFICATION = 0x00200000  # For service notification (typically used by background services).


# https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw#return-value
class ReturnValues(enum.IntEnum):
    """Enum class representing the possible return values from a MessageBox.

    These values correspond to the button choices made by the user when interacting with a MessageBox dialog.
    """

    IDABORT = 3  # The Abort     button was selected.
    IDCANCEL = 2  # The Cancel    button was selected.
    IDCONTINUE = 11  # The Continue  button was selected.
    IDIGNORE = 5  # The Ignore    button was selected.
    IDNO = 7  # The No        button was selected.
    IDOK = 1  # The OK        button was selected.
    IDRETRY = 4  # The Retry     button was selected.
    IDTRY_AGAIN = 10  # The Try Again button was selected.
    IDYES = 6  # The Yes       button was selected.


_state: dict[str, int] = {'owner_hwnd': 0}


def set_owner_hwnd(hwnd: int) -> None:
    """Set the owner window handle used by `show()`.

    When set to a non-zero value, the message box becomes an owned window of
    that HWND and Windows always renders owned windows above their owner.
    Pass 0 to restore the default (no owner, standard z-order).
    """
    _state['owner_hwnd'] = hwnd


_QT_BUTTON_TO_RETURN_VALUE: dict[QMessageBox.StandardButton, ReturnValues] = {
    QMessageBox.StandardButton.Ok: ReturnValues.IDOK,
    QMessageBox.StandardButton.Cancel: ReturnValues.IDCANCEL,
    QMessageBox.StandardButton.Yes: ReturnValues.IDYES,
    QMessageBox.StandardButton.No: ReturnValues.IDNO,
    QMessageBox.StandardButton.Retry: ReturnValues.IDRETRY,
    QMessageBox.StandardButton.Abort: ReturnValues.IDABORT,
    QMessageBox.StandardButton.Ignore: ReturnValues.IDIGNORE,
}


def _show_qt(title: str, text: str, style: Style) -> ReturnValues:
    """Display a Qt QMessageBox for non-Windows platforms."""
    _ = app

    box = QMessageBox()
    box.setWindowTitle(title)
    box.setText(text)

    if style & Style.MB_ICONSTOP:
        box.setIcon(QMessageBox.Icon.Critical)
    elif style & Style.MB_ICONEXCLAMATION:
        box.setIcon(QMessageBox.Icon.Warning)
    elif style & Style.MB_ICONQUESTION:
        box.setIcon(QMessageBox.Icon.Question)
    elif style & Style.MB_ICONINFORMATION:
        box.setIcon(QMessageBox.Icon.Information)

    button_flags = style & 0x0000000F
    if button_flags == Style.MB_OKCANCEL:
        box.setStandardButtons(QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
    elif button_flags == Style.MB_YESNO:
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    elif button_flags == Style.MB_YESNOCANCEL:
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel)
    elif button_flags == Style.MB_RETRYCANCEL:
        box.setStandardButtons(QMessageBox.StandardButton.Retry | QMessageBox.StandardButton.Cancel)
    elif button_flags == Style.MB_ABORTRETRYIGNORE:
        box.setStandardButtons(QMessageBox.StandardButton.Abort | QMessageBox.StandardButton.Retry | QMessageBox.StandardButton.Ignore)
    else:
        box.setStandardButtons(QMessageBox.StandardButton.Ok)

    result = box.exec()
    return _QT_BUTTON_TO_RETURN_VALUE.get(QMessageBox.StandardButton(result), ReturnValues.IDOK)


def show(title: str, text: str, style: Style) -> ReturnValues:
    """Display a message box with the specified title, text, and style.

    Args:
        title: The title of the message box.
        text: The text to display in the message box.
        style: The style for the message box, defined by the Style class.

    Returns:
        The return value from the message box, indicating which button was pressed.

    Raises:
        TypeError: If the return value from the MessageBox is not an integer.
    """
    if sys.platform != 'win32':
        return _show_qt(title, text, style)

    result = ctypes.windll.user32.MessageBoxW(_state['owner_hwnd'], text, title, style)
    return ReturnValues(ensure_instance(result, int))


def _show_until_windows(
    title: str,
    text: str,
    condition: Callable[[], bool],
    poll_interval: float,
    style: Style,
) -> bool:
    """Display a Windows message box and poll until condition returns True or user cancels."""
    if condition():
        return True

    success_event = threading.Event()
    stop_event = threading.Event()

    def poller() -> None:
        while not stop_event.wait(poll_interval):
            if condition():
                success_event.set()
                for _ in range(20):
                    hwnd = ctypes.windll.user32.FindWindowW('#32770', title)
                    if hwnd:
                        ctypes.windll.user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE
                        break
                    time.sleep(0.1)
                break

    while not success_event.is_set():
        stop_event.clear()
        poll_thread = threading.Thread(target=poller, name='MsgboxPoller', daemon=True)
        poll_thread.start()

        result = ctypes.windll.user32.MessageBoxW(_state['owner_hwnd'], text, title, style)
        stop_event.set()
        poll_thread.join()

        if success_event.is_set():
            return True

        if result == ReturnValues.IDCANCEL:
            return False

        if condition():
            return True

    return True


def _show_until_qt(
    title: str,
    text: str,
    condition: Callable[[], bool],
    poll_interval: float,
    style: Style,
) -> bool:
    """Display a Qt QMessageBox and poll until condition returns True or user cancels."""
    if condition():
        return True

    _ = app

    box = QMessageBox()
    box.setWindowTitle(title)
    box.setText(text)

    if style & Style.MB_ICONSTOP:
        box.setIcon(QMessageBox.Icon.Critical)
    elif style & Style.MB_ICONEXCLAMATION:
        box.setIcon(QMessageBox.Icon.Warning)
    elif style & Style.MB_ICONQUESTION:
        box.setIcon(QMessageBox.Icon.Question)
    elif style & Style.MB_ICONINFORMATION:
        box.setIcon(QMessageBox.Icon.Information)

    box.setStandardButtons(QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)

    success_event = threading.Event()
    stop_event = threading.Event()

    def poller() -> None:
        while not stop_event.wait(poll_interval):
            if condition():
                success_event.set()
                QMetaObject.invokeMethod(box, 'accept', Qt.ConnectionType.QueuedConnection)
                break

    while not success_event.is_set():
        stop_event.clear()
        poll_thread = threading.Thread(target=poller, name='MsgboxPoller', daemon=True)
        poll_thread.start()

        result = box.exec()
        stop_event.set()
        poll_thread.join()

        if success_event.is_set():
            return True

        if result == QMessageBox.StandardButton.Cancel:
            return False

        if condition():
            return True

    return True


def show_until(
    title: str,
    text: str,
    condition: Callable[[], bool],
    poll_interval: float = 0.5,
    style: Style = Style.MB_OKCANCEL | Style.MB_ICONINFORMATION | Style.MB_SETFOREGROUND,
) -> bool:
    """Display a message box and poll in a loop until condition returns True or user cancels.

    If condition returns True at any point, the dialog is closed automatically and True is returned.
    If the user cancels or closes the dialog, False is returned.

    Args:
        title: The title of the message box.
        text: The text to display in the message box.
        condition: A callable returning a boolean indicating if the requirement is satisfied.
        poll_interval: The polling interval in seconds.
        style: The message box style flags.

    Returns:
        True if condition was satisfied, False if the user cancelled.
    """
    if sys.platform != 'win32':
        return _show_until_qt(title, text, condition, poll_interval, style)

    return _show_until_windows(title, text, condition, poll_interval, style)
