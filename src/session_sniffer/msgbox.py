"""Message box utilities using native Windows MessageBox API or Qt QMessageBox fallback on Linux.

It defines two main components:
- msgbox.ReturnValues: Enum class representing the possible return values from a MessageBox.
- msgbox.Style: IntFlag class representing the different styles and options available for the MessageBox.

The msgbox.show() method can be used to display a message box with custom buttons, and behavior.
"""

import ctypes
import enum
import sys

from PySide6.QtWidgets import QMessageBox

from session_sniffer.error_messages import ensure_instance
from session_sniffer.guis.app import app


# https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw#parameters
class Style(enum.IntFlag):
    """IntFlag class representing the different styles and options available for the MessageBox.

    This class defines the various button and icon configurations that can be used when displaying a message box.
    """

    MB_OK = 0x00000000  # Contains only the OK button (default).
    MB_OKCANCEL = 0x00000001  # Contains OK and Cancel buttons.
    MB_ABORTRETRYIGNORE = 0x00000002  # Contains Abort, Retry, and Ignore buttons.
    MB_YESNO = 0x00000004  # Contains Yes and No buttons.
    MB_YESNOCANCEL = MB_OKCANCEL | MB_ABORTRETRYIGNORE  # Contains Yes, No, and Cancel buttons.
    MB_RETRYCANCEL = MB_OKCANCEL | MB_YESNO  # Contains Retry and Cancel buttons.
    MB_ICONSTOP = 0x00000010  # Displays a Stop icon (Error).
    MB_ICONERROR = MB_ICONSTOP  # Displays an Error icon.
    MB_ICONQUESTION = 0x00000020  # Displays a Question icon.
    MB_ICONEXCLAMATION = MB_ICONSTOP | MB_ICONQUESTION  # Displays an Exclamation icon (Warning).
    MB_ICONWARNING = MB_ICONEXCLAMATION  # Displays a Warning icon.
    MB_ICONINFORMATION = 0x00000040  # Displays an Information icon.
    MB_SYSTEMMODAL = 0x00001000  # System modal; all applications are suspended until the user responds.
    MB_SETFOREGROUND = 0x00010000  # Brings the message box to the foreground.
    MB_TOPMOST = 0x00040000  # Makes the message box topmost.


# https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw#return-value
class ReturnValues(enum.IntEnum):
    """Enum class representing the possible return values from a MessageBox.

    These values correspond to the button choices made by the user when interacting with a MessageBox dialog.
    """

    IDABORT = 3  # The Abort     button was selected.
    IDCANCEL = 2  # The Cancel    button was selected.
    IDIGNORE = 5  # The Ignore    button was selected.
    IDNO = 7  # The No        button was selected.
    IDOK = 1  # The OK        button was selected.
    IDRETRY = 4  # The Retry     button was selected.
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

    icon_flags = style & 0x000000F0
    if icon_flags == Style.MB_ICONSTOP:
        box.setIcon(QMessageBox.Icon.Critical)
    elif icon_flags == Style.MB_ICONEXCLAMATION:
        box.setIcon(QMessageBox.Icon.Warning)
    elif icon_flags == Style.MB_ICONQUESTION:
        box.setIcon(QMessageBox.Icon.Question)
    elif icon_flags == Style.MB_ICONINFORMATION:
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
