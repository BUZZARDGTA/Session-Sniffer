"""Discord intro popup dialog and clickable label widgets."""

import webbrowser

from PyQt6.QtCore import QEasingCurve, QPoint, QPropertyAnimation, Qt, pyqtSignal
from PyQt6.QtGui import QMouseEvent
from PyQt6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QSpacerItem, QVBoxLayout

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.app import app
from session_sniffer.guis.exceptions import PrimaryScreenNotFoundError
from session_sniffer.guis.stylesheets import (
    DISCORD_POPUP_EXIT_BUTTON_STYLESHEET,
    DISCORD_POPUP_JOIN_BUTTON_STYLESHEET,
    DISCORD_POPUP_MAIN_STYLESHEET,
)
from session_sniffer.settings import Settings

DISCORD_INVITE_URL = 'https://discord.gg/hMZ7MsPX7G'


class ClickableLabel(QLabel):
    """Emit a signal when the label is clicked."""

    clicked = pyqtSignal()

    def mousePressEvent(self, event: QMouseEvent | None) -> None:  # pyright: ignore[reportIncompatibleMethodOverride]  # pylint: disable=invalid-name  # noqa: N802
        """Emit `clicked` when left mouse button is pressed."""
        if event is not None and event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()


class DiscordIntro(QDialog):
    """Show a modal dialog inviting the user to join the Discord server."""

    def __init__(self) -> None:
        """Initialize the Discord community intro dialog."""
        super().__init__()

        window_title = '🏆 Join our Discord Community! 🤝'

        # Ensure the dialog is modal, blocking interaction with the main window
        self.setModal(True)

        # Set up the window
        self.setWindowTitle(window_title)
        self.setMinimumSize(460, 160)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool | Qt.WindowType.Dialog)  # | Qt.WindowType.WindowStaysOnTopHint

        # Set window opacity to 0 for fade-in animation
        self.setWindowOpacity(0)

        # Styling for the main container window
        self.setStyleSheet(DISCORD_POPUP_MAIN_STYLESHEET)

        self.fade_out = QPropertyAnimation(self, b'windowOpacity')

        # Exit button in the top right corner
        self.exit_button = QPushButton('x', self)
        self.exit_button.setFixedSize(16, 16)  # Make the width and height equal
        self.exit_button.setToolTip('Close this popup')
        self.exit_button.setStyleSheet(DISCORD_POPUP_EXIT_BUTTON_STYLESHEET)
        self.exit_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.exit_button.clicked.connect(self.close_popup)  # pyright: ignore[reportUnknownMemberType]

        # Layout for the window content
        layout = QVBoxLayout()

        # Add the exit button to the top right
        exit_layout = QHBoxLayout()
        exit_layout.addStretch(1)  # Spacer
        exit_layout.addWidget(self.exit_button)
        layout.addLayout(exit_layout)

        # Label for the Discord message
        self.title_label = QLabel(
            f"<font size='6' color='#5865F2'><b>{window_title}</b></font>",
            self)
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(self.title_label)

        layout.addItem(QSpacerItem(0, 4, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))  # Spacer

        # Join button container
        self.join_button = QPushButton(f'🔥 Join Now - {TITLE} Discord! 🔥', self)
        self.join_button.setToolTip('Open Discord and join the Session Sniffer community server')
        self.join_button.setStyleSheet(DISCORD_POPUP_JOIN_BUTTON_STYLESHEET)
        self.join_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.join_button.clicked.connect(self.open_discord)  # pyright: ignore[reportUnknownMemberType]

        # Set button width to 75% of the window width
        self.join_button.setMaximumWidth(int(self.width() * 0.75))

        # Center the button horizontally using a layout
        button_layout = QHBoxLayout()
        button_layout.addStretch(1)  # Spacer before the button
        button_layout.addWidget(self.join_button)
        button_layout.addStretch(1)  # Spacer after the button

        layout.addLayout(button_layout)  # Add the button layout to the main layout

        # Clickable text "Don't remind me again"
        self.dont_remind_me_label = ClickableLabel("<font size='3' color='#B0B0B0'><u>Don't remind me again</u></font>", self)
        self.dont_remind_me_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.dont_remind_me_label.setToolTip('Disable Discord popup notifications permanently')
        self.dont_remind_me_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self.dont_remind_me_label.clicked.connect(self.dont_remind_me)  # pyright: ignore[reportUnknownMemberType]

        layout.addItem(QSpacerItem(0, 10, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))  # Spacer
        layout.addWidget(self.dont_remind_me_label)

        # Apply margin here to adjust widget spacing
        layout.setContentsMargins(10, 10, 10, 10)  # Add margin to the layout

        # Set the main layout of the window
        self.setLayout(layout)

        # Show the window to allow size calculations
        self.show()

        # After the window is shown, center it
        self.center_window()

        # Fade-in animation
        self.fade_in = QPropertyAnimation(self, b'windowOpacity')
        self.fade_in.setDuration(1000)
        self.fade_in.setStartValue(0)
        self.fade_in.setEndValue(1)
        self.fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.fade_in.start()

        # Raise and activate window to ensure it gets focus
        self.raise_()
        self.activateWindow()

        # Initialize variables to track mouse position
        self._drag_pos: QPoint | None = None

    # pylint: disable=invalid-name
    def mousePressEvent(self, event: QMouseEvent | None) -> None:  # pyright: ignore[reportIncompatibleMethodOverride]  # noqa: N802
        """Begin drag when clicking the dialog background."""
        if (
            event is not None
            and event.button() == Qt.MouseButton.LeftButton
            and not self.exit_button.underMouse()
            and not self.join_button.underMouse()
            and not self.dont_remind_me_label.underMouse()  # Only allow dragging if the click is not on a button
        ):
            self._drag_pos = event.globalPosition().toPoint()

        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent | None) -> None:  # pyright: ignore[reportIncompatibleMethodOverride]  # noqa: N802
        """Move the dialog while dragging."""
        if (
            event is not None
            and self._drag_pos is not None  # If mouse is pressed, move the window
        ):
            delta = event.globalPosition().toPoint() - self._drag_pos
            self.move(self.pos() + delta)
            self._drag_pos = event.globalPosition().toPoint()

        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent | None) -> None:  # pyright: ignore[reportIncompatibleMethodOverride]  # noqa: N802
        """Stop dragging the dialog on mouse release."""
        self._drag_pos = None  # Reset drag position when mouse is released

        super().mouseReleaseEvent(event)
    # pylint: enable=invalid-name

    def center_window(self) -> None:
        """Center the dialog on the primary screen."""
        screen = app.primaryScreen()
        if screen is None:
            raise PrimaryScreenNotFoundError

        screen_geometry = screen.geometry()
        x = (screen_geometry.width() - self.width()) // 2
        y = (screen_geometry.height() - self.height()) // 2
        self.move(x, y)

    def open_discord(self) -> None:
        """Open the Discord invite URL and disable future popup reminders."""
        webbrowser.open(DISCORD_INVITE_URL)

        if Settings.SHOW_DISCORD_POPUP:
            Settings.SHOW_DISCORD_POPUP = False
            Settings.rewrite_settings_file()

        self.close_popup()

    def dont_remind_me(self) -> None:
        """Disable future Discord popup reminders and close the dialog."""
        if Settings.SHOW_DISCORD_POPUP:
            Settings.SHOW_DISCORD_POPUP = False
            Settings.rewrite_settings_file()

        self.close_popup()

    def close_popup(self) -> None:
        """Fade out and close the Discord popup dialog."""
        # Smooth fade-out before closing
        self.fade_out.setDuration(500)
        self.fade_out.setStartValue(1)  # Start from fully opaque
        self.fade_out.setEndValue(0)    # Fade to fully transparent
        self.fade_out.setEasingCurve(QEasingCurve.Type.InCubic)
        self.fade_out.finished.connect(self.close)  # pyright: ignore[reportUnknownMemberType]  # Close the window after the fade-out finishes
        self.fade_out.start()
