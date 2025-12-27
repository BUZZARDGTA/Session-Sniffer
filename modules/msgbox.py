"""The module provides a wrapper for the Windows MessageBox API using ctypes.

It defines two main components:
- MsgBox.ReturnValues: Enum class representing the possible return values from a MessageBox.
- MsgBox.Style: IntFlag class representing the different styles and options available for the MessageBox.

The MsgBox.show() method can be used to display a message box with custom buttons, and behavior.
"""
import ctypes
import enum

from modules.error_messages import format_type_error


class MsgBox:
    """A class to interact with the Windows MessageBox API.

    Provides functionality to display a message box with various button options, and behaviors.
    """

    # https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw#parameters
    class Style(enum.IntFlag):
        """IntFlag class representing the different styles and options available for the MessageBox.

        This class defines the various button and icon configurations that can be used when displaying a message box.
        """
        # pylint: disable=implicit-flag-alias
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
        # pylint: enable=implicit-flag-alias

    # https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw#return-value
    class ReturnValues(enum.IntEnum):
        """Enum class representing the possible return values from a MessageBox.

        These values correspond to the button choices made by the user when interacting with a MessageBox dialog.
        """
        IDABORT = 3   # The Abort     button was selected.
        IDCANCEL = 2   # The Cancel    button was selected.
        IDCONTINUE = 11  # The Continue  button was selected.
        IDIGNORE = 5   # The Ignore    button was selected.
        IDNO = 7   # The No        button was selected.
        IDOK = 1   # The OK        button was selected.
        IDRETRY = 4   # The Retry     button was selected.
        IDTRY_AGAIN = 10  # The Try Again button was selected.
        IDYES = 6   # The Yes       button was selected.

    @staticmethod
    def show(title: str, text: str, style: Style) -> int:
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
        msgbox_result = ctypes.windll.user32.MessageBoxW(0, text, title, style)
        if not isinstance(msgbox_result, int):
            raise TypeError(format_type_error(msgbox_result, int))

        return msgbox_result
