"""Shared dialog mixins and helpers for unsaved-changes close handling and tabbed button rows."""

from typing import TYPE_CHECKING, override

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QDialog, QHBoxLayout, QMessageBox, QPushButton

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.stylesheets import DIALOG_DANGER_BUTTON_STYLESHEET, DIALOG_PRIMARY_BUTTON_STYLESHEET

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtGui import QCloseEvent


class UnsavedChangesMixin(QDialog):
    """Mixin providing a `closeEvent` that prompts to save unsaved changes.

    Concrete subclasses must implement `_has_unsaved_changes_for_close` and `_save_on_close`.
    """

    def _has_unsaved_changes_for_close(self) -> bool:
        """Return `True` if there are unsaved changes that should be saved before closing."""
        raise NotImplementedError

    def _save_on_close(self) -> bool:
        """Perform the save action on close. Return `True` if save succeeded and the dialog may close."""
        raise NotImplementedError

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Prompt to save if there are unsaved changes before closing."""
        if not self._has_unsaved_changes_for_close():
            event.accept()
            return
        result = QMessageBox.warning(
            self,
            TITLE,
            'You have unsaved changes. Save before closing?',
            QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Save,
        )
        if result == QMessageBox.StandardButton.Save:
            if not self._save_on_close():
                event.ignore()
                return
        elif result == QMessageBox.StandardButton.Cancel:
            event.ignore()
            return
        event.accept()


def setup_tab_dialog_buttons(
    button_row: QHBoxLayout,
    reset_button: QPushButton,
    reset_to_defaults: Callable[[], None],
    reset_current_tab: Callable[[], None],
) -> QPushButton:
    """Finalize *reset_button*, add a stretch, add the per-tab reset button, and return a new Save button.

    The caller is responsible for setting the Save button's tooltip, connecting its clicked signal,
    and adding it (plus any Cancel button) to *button_row*.
    """
    button_row.addStretch()

    reset_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
    reset_button.clicked.connect(reset_to_defaults)
    button_row.addWidget(reset_button)

    reset_tab_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh.svg')), ' Reset')
    reset_tab_button.setToolTip('Reset current tab settings to their default values (review before saving)')
    reset_tab_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
    reset_tab_button.clicked.connect(reset_current_tab)
    button_row.addWidget(reset_tab_button)

    save_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'save.svg')), ' Save')
    save_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
    save_button.setDefault(True)
    return save_button


def equalize_button_sizes(button_row: QHBoxLayout) -> None:
    """Ensure all QPushButton widgets in *button_row* share the same minimum width and height based on the largest button."""
    buttons: list[QPushButton] = []
    for index in range(button_row.count()):
        item = button_row.itemAt(index)
        widget = item.widget() if item is not None else None
        if isinstance(widget, QPushButton):
            buttons.append(widget)
    if not buttons:
        return
    max_width = max(button.sizeHint().width() for button in buttons)
    max_height = max(button.sizeHint().height() for button in buttons)
    for button in buttons:
        button.setMinimumWidth(max_width)
        button.setMinimumHeight(max_height)
