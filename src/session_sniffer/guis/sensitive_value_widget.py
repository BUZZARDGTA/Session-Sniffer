"""Sleek, polished container that renders sensitive data blurred until revealed."""

from typing import TYPE_CHECKING, Final, override

if TYPE_CHECKING:
    from collections.abc import Callable

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QMouseEvent
from PySide6.QtWidgets import (
    QApplication,
    QGraphicsBlurEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QWidget,
)

_SENSITIVE_BLUR_RADIUS: Final[float] = 10.0

_REDACTED_PILL_STYLESHEET_BLURRED: Final[str] = (
    'QWidget#sensitive_container {'
    '    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
    '        stop:0 rgba(26, 15, 46, 0.85), stop:1 rgba(42, 18, 72, 0.85));'
    '    border: 1px solid rgba(167, 139, 250, 0.35);'
    '    border-radius: 6px;'
    '}'
    'QWidget#sensitive_container:hover {'
    '    border-color: rgba(192, 132, 252, 0.75);'
    '    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
    '        stop:0 rgba(36, 20, 64, 0.95), stop:1 rgba(58, 26, 98, 0.95));'
    '}'
)

_REDACTED_PILL_STYLESHEET_REVEALED: Final[str] = (
    'QWidget#sensitive_container {'
    '    background-color: rgba(20, 12, 36, 0.6);'
    '    border: 1px solid rgba(167, 139, 250, 0.25);'
    '    border-radius: 6px;'
    '}'
)

_SENSITIVE_ACTION_BUTTON_STYLESHEET: Final[str] = (
    'QPushButton {'
    '    background-color: rgba(124, 58, 237, 0.3);'
    '    color: #d8b4fe;'
    '    border: 1px solid rgba(167, 139, 250, 0.45);'
    '    border-radius: 4px;'
    '    padding: 3px 12px;'
    '    font-size: 13px;'
    '    font-weight: 700;'
    '    letter-spacing: 0.5px;'
    '}'
    'QPushButton:hover {'
    '    background-color: rgba(139, 92, 246, 0.55);'
    '    border-color: rgba(216, 180, 254, 0.8);'
    '    color: #ffffff;'
    '}'
    'QPushButton:pressed {'
    '    background-color: #7c3aed;'
    '}'
)


class SensitiveValueWidget(QWidget):
    """A sleek, polished container that renders sensitive data blurred until revealed."""

    def __init__(
        self,
        text: str,
        *,
        on_toggled: Callable[[bool], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the sensitive value widget with blurred default state."""
        super().__init__(parent)
        self._text = text
        self._revealed = False
        self._on_toggled = on_toggled

        outer_layout = QHBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(6)

        self._container = QWidget(self)
        self._container.setObjectName('sensitive_container')
        self._container.setCursor(Qt.CursorShape.PointingHandCursor)

        container_layout = QHBoxLayout(self._container)
        container_layout.setContentsMargins(10, 4, 8, 4)
        container_layout.setSpacing(10)

        self._label = QLabel(text, self._container)
        font = QFont('Consolas', 13)
        font.setBold(True)
        self._label.setFont(font)
        self._label.setStyleSheet('color: #f3e8ff; background: transparent; padding: 0 2px;')

        self._blur_effect = QGraphicsBlurEffect(self._label)
        self._blur_effect.setBlurRadius(_SENSITIVE_BLUR_RADIUS)
        self._label.setGraphicsEffect(self._blur_effect)

        self._copy_button = QPushButton('Copy', self._container)
        self._copy_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._copy_button.setStyleSheet(_SENSITIVE_ACTION_BUTTON_STYLESHEET)
        self._copy_button.setToolTip('Copy to clipboard')
        self._copy_button.clicked.connect(self._copy_to_clipboard)

        self._toggle_button = QPushButton('Reveal', self._container)
        self._toggle_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._toggle_button.setStyleSheet(_SENSITIVE_ACTION_BUTTON_STYLESHEET)
        self._toggle_button.clicked.connect(self.toggle)

        container_layout.addWidget(self._label)
        container_layout.addWidget(self._copy_button)
        container_layout.addWidget(self._toggle_button)

        outer_layout.addWidget(self._container)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)

        self._apply_state()

    def _copy_to_clipboard(self) -> None:
        """Copy the underlying text to clipboard and briefly acknowledge."""
        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(self._text)
        self._copy_button.setText('Copied')
        QTimer.singleShot(1200, lambda: self._copy_button.setText('Copy'))

    @property
    def is_revealed(self) -> bool:
        """Whether the sensitive value is currently unblurred."""
        return self._revealed

    def set_revealed(self, *, revealed: bool) -> None:
        """Set revealed state explicitly."""
        if self._revealed != revealed:
            self._revealed = revealed
            self._apply_state()
            if self._on_toggled is not None:
                self._on_toggled(self._revealed)

    def toggle(self) -> None:
        """Toggle revealed state between blurred and clear."""
        self.set_revealed(revealed=not self._revealed)

    def _apply_state(self) -> None:
        self._blur_effect.setEnabled(not self._revealed)
        if self._revealed:
            self._container.setStyleSheet(_REDACTED_PILL_STYLESHEET_REVEALED)
            self._container.setCursor(Qt.CursorShape.ArrowCursor)
            self._label.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard
            )
            self._label.setCursor(Qt.CursorShape.IBeamCursor)
            self._label.setToolTip('Select text to copy, or click Copy')
            self._toggle_button.setText('Hide')
            self._copy_button.show()
        else:
            self._container.setStyleSheet(_REDACTED_PILL_STYLESHEET_BLURRED)
            self._container.setCursor(Qt.CursorShape.PointingHandCursor)
            self._label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
            self._label.setCursor(Qt.CursorShape.PointingHandCursor)
            self._label.setToolTip('Click anywhere to reveal')
            self._toggle_button.setText('Reveal')
            self._copy_button.hide()

    @override
    def mousePressEvent(self, event: QMouseEvent) -> None:
        """Clicking on the container when blurred automatically unblurs it."""
        if event.button() == Qt.MouseButton.LeftButton and not self._revealed:
            self.toggle()
            event.accept()
            return
        super().mousePressEvent(event)
