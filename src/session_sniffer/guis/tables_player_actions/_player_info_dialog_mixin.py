"""Shared base mixin for player-info dialogs (group boxes, form rows, layout helpers)."""

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QCloseEvent, QFont
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.guis.utils import get_screen_size, resize_window_for_screen


class PlayerInfoDialogMixin(QDialog):
    """Base class providing shared layout helpers for player-info dialogs.

    Concrete subclasses call `_apply_standard_dialog_size`, `_add_header_label`,
    `_init_scroll_area`, and `_add_close_button_box` from their `__init__`, and use
    `_make_group` / `_add_row` when building content sections.
    """

    @staticmethod
    def _make_group(title: str, *, accent: str) -> tuple[QGroupBox, QFormLayout]:
        """Create a styled group box with an attached QFormLayout and return both."""
        group = QGroupBox(title)
        group.setStyleSheet(
            'QGroupBox {'
            f' border: 1px solid {accent};'
            ' border-radius: 6px;'
            ' margin-top: 14px;'
            ' padding-top: 10px;'
            ' background: rgba(255, 255, 255, 8);'
            ' font-weight: bold;'
            '}'
            'QGroupBox::title {'
            ' subcontrol-origin: margin;'
            ' subcontrol-position: top left;'
            ' left: 10px; padding: 2px 8px;'
            f' background: {accent};'
            ' color: #ffffff;'
            ' border-radius: 4px;'
            '}',
        )
        form = QFormLayout(group)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        form.setFormAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(5)
        form.setContentsMargins(10, 8, 10, 10)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        return group, form

    @staticmethod
    def _add_row(form: QFormLayout, label_text: str, value: str) -> None:
        """Append a copyable label/value row to *form*."""
        label_widget = QLabel(f'{label_text}:')
        label_widget.setStyleSheet('color: #cbd5e0; font-weight: 600; background: transparent;')
        form.addRow(label_widget, PlayerInfoDialogMixin._make_value_label(value))

    @staticmethod
    def _make_value_label(text: str = '') -> QLabel:
        """Create and style a copyable value `QLabel`."""
        value_widget = QLabel(text)
        value_widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        value_widget.setCursor(Qt.CursorShape.IBeamCursor)
        value_widget.setWordWrap(True)
        value_widget.setFont(QFont('Consolas'))
        value_widget.setStyleSheet('color: #ffffff; font-weight: bold; padding: 3px 6px; border-radius: 3px; background: rgba(255, 255, 255, 12);')
        value_widget.setToolTip('Click and drag to select; Ctrl+C to copy.')
        return value_widget

    def _init_scroll_area(self, outer_layout: QVBoxLayout) -> QVBoxLayout:
        """Add a frameless scroll area to *outer_layout* and return its inner `QVBoxLayout`."""
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer_layout.addWidget(scroll, stretch=1)

        scroll_content = QWidget()
        scroll.setWidget(scroll_content)
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(2, 2, 2, 2)
        scroll_layout.setSpacing(10)
        return scroll_layout

    def _add_close_button_box(self, outer_layout: QVBoxLayout) -> None:
        """Append a Close button box to *outer_layout*."""
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, parent=self)
        button_box.rejected.connect(self.reject)
        button_box.accepted.connect(self.accept)
        outer_layout.addWidget(button_box)

    def _apply_standard_dialog_size(self) -> None:
        """Apply the standard 560x460 minimum size and an adaptive resize based on screen resolution."""
        self.setMinimumSize(560, 460)
        screen_size = get_screen_size()
        if screen_size >= (1920, 1080):
            self.resize(700, 580)
        elif screen_size >= (1280, 720):
            self.resize(620, 520)
        else:
            resize_window_for_screen(self, screen_size)
            self.resize(min(self.width(), max(560, screen_size[0] - 80)), min(self.height(), max(460, screen_size[1] - 80)))

    def _add_header_label(self, outer_layout: QVBoxLayout, text: str, grad_stop0: str, grad_stop1: str) -> QLabel:
        """Create a gradient header label, add it to *outer_layout*, and return it."""
        header = QLabel(text)
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet(
            'font-size: 14pt; font-weight: bold; padding: 8px 6px;'
            'color: #ffffff; background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
            f' stop:0 {grad_stop0}, stop:1 {grad_stop1}); border-radius: 6px;',
        )
        header.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        outer_layout.addWidget(header)
        return header

    def closeEvent(self, a0: QCloseEvent | None) -> None:  # noqa: N802
        """Handle the close event."""
        super().closeEvent(a0)
