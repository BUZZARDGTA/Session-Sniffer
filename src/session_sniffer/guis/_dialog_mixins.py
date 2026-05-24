"""Shared dialog mixins and helpers for unsaved-changes close handling and tabbed button rows."""

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QDialog, QHBoxLayout, QMessageBox, QPushButton

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_PRIMARY_BUTTON_STYLESHEET

if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtGui import QCloseEvent

_MixinBase = QDialog


class UnsavedChangesMixin(_MixinBase):
    """Mixin providing a `closeEvent` that prompts to save unsaved changes.

    Concrete subclasses must implement `_has_unsaved_changes_for_close` and `_save_on_close`.
    """

    def _has_unsaved_changes_for_close(self) -> bool:
        """Return `True` if there are unsaved changes that should be saved before closing."""
        raise NotImplementedError

    def _save_on_close(self) -> bool:
        """Perform the save action on close. Return `True` if save succeeded and the dialog may close."""
        raise NotImplementedError

    def closeEvent(self, a0: QCloseEvent | None) -> None:  # noqa: N802
        """Prompt to save if there are unsaved changes before closing."""
        if not self._has_unsaved_changes_for_close():
            if a0 is not None:
                a0.accept()
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
                if a0 is not None:
                    a0.ignore()
                return
        elif result == QMessageBox.StandardButton.Cancel:
            if a0 is not None:
                a0.ignore()
            return
        if a0 is not None:
            a0.accept()


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
    reset_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    reset_button.clicked.connect(reset_to_defaults)
    button_row.addWidget(reset_button)

    button_row.addStretch()

    reset_tab_button = QPushButton('\U0001f504 Reset')
    reset_tab_button.setToolTip('Reset current tab settings to default values (review before saving)')
    reset_tab_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    reset_tab_button.clicked.connect(reset_current_tab)
    button_row.addWidget(reset_tab_button)

    save_button = QPushButton('\U0001f4be Save')
    save_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
    save_button.setDefault(True)
    return save_button
