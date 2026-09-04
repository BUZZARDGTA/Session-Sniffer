"""Custom `QLineEdit` that renders a fixed-length mask when hidden to prevent character-count guessing."""

from typing import Final, override

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication, QKeyEvent, QKeySequence, QMouseEvent, QResizeEvent
from PySide6.QtWidgets import QLineEdit, QMenu, QStyle, QStyleOptionFrame, QToolButton, QWidget

_MASK_CHARACTER: Final[str] = '•'


class SecretLineEdit(QLineEdit):
    """A `QLineEdit` that displays a fixed-length mask when unrevealed to prevent character-count guessing.

    The underlying text is preserved and returned by `text()`, so external validation,
    saving, and verification operate on the real value without leakage.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the secret line-edit with default masked state."""
        super().__init__(parent)
        self._real_text = ''
        self._revealed = False
        self.setEchoMode(QLineEdit.EchoMode.Password)

    @override
    def text(self) -> str:
        """Return the real underlying secret text."""
        if self._revealed:
            return super().text()
        return self._real_text

    @override
    def setText(self, text: str | None) -> None:
        """Set the underlying secret text and update the display."""
        self._real_text = text or ''
        self._update_display()
        self.textChanged.emit(self._real_text)

    @property
    def is_revealed(self) -> bool:
        """Whether the secret is currently displayed in plain text."""
        return self._revealed

    def set_revealed(self, *, revealed: bool) -> None:
        """Toggle between plain-text revealed mode and fixed-mask hidden mode."""
        if self._revealed != revealed:
            if self._revealed:
                self._real_text = super().text()
            self._revealed = revealed
            self._update_display()

    def _get_mask_text(self) -> str:
        """Return a mask string dynamically calculated to fill the visible text area."""
        trailing_buttons = self.findChildren(QToolButton)
        if trailing_buttons:
            trailing_button = trailing_buttons[0]
            available_width = max(trailing_button.geometry().x() - self.contentsMargins().left(), 0)
        else:
            style_option = QStyleOptionFrame()
            style_option.initFrom(self)
            contents_rect = self.style().subElementRect(QStyle.SubElement.SE_LineEditContents, style_option, self)
            available_width = max(contents_rect.width(), self.width(), 0)

        bullet_width = max(self.fontMetrics().horizontalAdvance(_MASK_CHARACTER), 1)
        count = max(available_width // bullet_width, 1)
        return _MASK_CHARACTER * count

    def _update_display(self) -> None:
        """Update the displayed characters without re-emitting external textChanged signals."""
        self.blockSignals(True)  # noqa: FBT003
        if self._revealed:
            self.setEchoMode(QLineEdit.EchoMode.Normal)
            super().setText(self._real_text)
        else:
            self.setEchoMode(QLineEdit.EchoMode.Password)
            super().setText(self._get_mask_text() if self._real_text else '')
            self.setCursorPosition(0)
        self.blockSignals(False)  # noqa: FBT003

    def _paste_from_clipboard(self) -> None:
        """Paste stripped text from the clipboard into the underlying secret value."""
        clipboard = QGuiApplication.clipboard()
        self.setText(clipboard.text().strip())

    @override
    def keyPressEvent(self, event: QKeyEvent) -> None:
        """Handle key events in masked mode to safely update the underlying secret text."""
        if not self._revealed:
            if event.matches(QKeySequence.StandardKey.Paste):
                self._paste_from_clipboard()
                event.accept()
                return

            if event.key() in (Qt.Key.Key_Backspace, Qt.Key.Key_Delete):
                if self.hasSelectedText() or not self._real_text:
                    self.setText('')
                else:
                    self.setText(self._real_text[:-1])
                event.accept()
                return

            if event.text() and event.text().isprintable():
                if self.hasSelectedText():
                    self.setText(event.text())
                else:
                    self.setText(self._real_text + event.text())
                event.accept()
                return

        super().keyPressEvent(event)

    @override
    def mousePressEvent(self, event: QMouseEvent) -> None:
        """Select all text on click when masked to allow immediate replacement or clearing."""
        super().mousePressEvent(event)
        if not self._revealed and self._real_text:
            self.selectAll()

    @override
    def resizeEvent(self, event: QResizeEvent) -> None:
        """Update mask fill length when the widget is resized so it fills the container."""
        super().resizeEvent(event)
        if not self._revealed and self._real_text:
            self._update_display()

    @override
    def createStandardContextMenu(self) -> QMenu:
        """Provide standard context menu with masked-safe paste and delete actions."""
        menu = super().createStandardContextMenu()
        if not self._revealed:
            for action in menu.actions():
                if action.objectName() == 'edit-paste':
                    action.triggered.disconnect()
                    action.triggered.connect(self._paste_from_clipboard)
                elif action.objectName() == 'edit-delete':
                    action.triggered.disconnect()
                    action.triggered.connect(self._clear_secret)
        return menu

    def _clear_secret(self) -> None:
        """Clear the secret value."""
        self.setText('')
