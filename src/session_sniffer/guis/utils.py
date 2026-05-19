"""Utility functions for GUI-related operations.

This module provides helper functions to interact with GUI elements.
"""


from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QHeaderView,
    QMainWindow,
    QMenu,
    QMessageBox,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.standalone import TITLE

from .app import app
from .exceptions import PrimaryScreenNotFoundError, UnsupportedScreenResolutionError

if TYPE_CHECKING:
    from PyQt6.QtGui import QMouseEvent


class PersistentMenu(QMenu):
    """QMenu that stays open when a checkable action is clicked."""

    def mouseReleaseEvent(self, a0: QMouseEvent | None) -> None:  # noqa: N802
        """Prevent auto-closing when a checkable action is triggered."""
        if a0 is None:
            super().mouseReleaseEvent(a0)
            return
        action = self.actionAt(a0.pos())
        if action and action.isCheckable():
            action.trigger()
            a0.accept()
            return
        super().mouseReleaseEvent(a0)


# ---------------------------------------------------------------------------
# Suspend-mode tooltip strings — shared between detections_manager and
# userip_manager_settings_mixin so they stay in sync.
# ---------------------------------------------------------------------------

SUSPEND_TOOLTIP_AUTO = (
    'Resume when the hostile player fully disconnects.\n'
    '\u2022 Robustness: High \u2013 game stays frozen until the threat is gone.\n'
    '\u2022 Freeze time: Moderate \u2013 depends on how long the player stays.'
)
SUSPEND_TOOLTIP_MANUAL = (
    'Remain suspended indefinitely (must be resumed manually).\n'
    '\u2022 Robustness: Maximum \u2013 nothing resumes automatically.\n'
    '\u2022 Freeze time: Longest \u2013 game stays frozen until you intervene.'
)
SUSPEND_TOOLTIP_ADAPTIVE = (
    'PPS-based smart suspend/resume.\n'
    'Temporarily resumes while the hostile player is idle (0 packets/sec)\n'
    'and re-suspends as soon as activity is detected.\n'
    '\u2022 Robustness: Moderate \u2013 idle players may still be connected.\n'
    '\u2022 Freeze time: Shortest \u2013 game is only frozen during active traffic.'
)
SUSPEND_TOOLTIP_CUSTOM = (
    'Resume after a fixed number of seconds.\n'
    '\u2022 Robustness: Low \u2013 timer may expire while the threat is still active.\n'
    '\u2022 Freeze time: Fixed \u2013 exactly the duration you specify.'
)


def format_player_display(ip: str, usernames: list[str]) -> str:
    """Return a human-readable player identifier combining usernames and IP.

    Returns `'username1, username2 (ip)'` when usernames are known,
    or just `'ip'` when no usernames are available.
    """
    if usernames:
        names = ', '.join(usernames)
        return f'{names} ({ip})'
    return ip


def get_screen_size() -> tuple[int, int]:
    """Get the current screen size and validate minimum resolution requirements.

    Returns:
        Screen width and height in pixels.

    Raises:
        PrimaryScreenNotFoundError: If no primary screen is detected.
        UnsupportedScreenResolutionError: If screen resolution is below minimum requirements.
    """
    min_screen_width = 800
    min_screen_height = 600

    screen = app.primaryScreen()
    if screen is None:
        raise PrimaryScreenNotFoundError

    size = screen.size()
    screen_width = size.width()
    screen_height = size.height()

    if screen_width < min_screen_width or screen_height < min_screen_height:
        raise UnsupportedScreenResolutionError(screen_width, screen_height, min_screen_width, min_screen_height)

    return screen_width, screen_height


def resize_window_for_screen(window: QDialog | QMainWindow, screen_width: int, screen_height: int) -> None:
    """Resize a window based on the screen resolution.

    Args:
        window: The window to resize.
        screen_width: The width of the screen.
        screen_height: The height of the screen.
    """
    if (screen_width, screen_height) >= (2560, 1440):
        window.resize(1400, 900)
    elif (screen_width, screen_height) >= (1920, 1080):
        window.resize(1200, 720)
    elif (screen_width, screen_height) >= (1024, 768):
        window.resize(940, 680)


# ---------------------------------------------------------------------------
# Shared GUI helpers
# ---------------------------------------------------------------------------

class NumericTableWidgetItem(QTableWidgetItem):  # pylint: disable=too-few-public-methods
    """QTableWidgetItem that sorts numerically."""

    def __lt__(self, other: QTableWidgetItem) -> bool:
        """Compare numerically using UserRole data if available, falling back to text then string comparison."""
        self_val = self.data(Qt.ItemDataRole.UserRole)
        other_val = other.data(Qt.ItemDataRole.UserRole)
        if isinstance(self_val, (int, float)) and isinstance(other_val, (int, float)):
            return float(self_val) < float(other_val)
        try:
            return float(self.text()) < float(other.text())
        except ValueError:
            return super().__lt__(other)


class ToggleAlwaysOnTopMixin(QWidget):  # pylint: disable=too-few-public-methods
    """Mixin providing an always-on-top toggle and window-layout helpers for QWidget subclasses."""

    def _setup_window_layout(
        self,
        *,
        always_on_top: bool,
        margins: tuple[int, int, int, int] = (8, 8, 8, 8),
        spacing: int = 4,
    ) -> QVBoxLayout:
        """Set always-on-top flag, WA_DeleteOnClose, and return a configured QVBoxLayout."""
        if always_on_top:
            self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(*margins)
        layout.setSpacing(spacing)
        return layout

    def _add_always_on_top_checkbox(self, layout: QVBoxLayout, *, always_on_top: bool) -> None:
        """Create and add the standard 'Always on Top' checkbox to *layout*."""
        checkbox = QCheckBox('Always on Top')
        checkbox.setToolTip('Keep this window above all other windows.\nThis toggle does not change the saved default.')
        checkbox.setChecked(always_on_top)
        checkbox.toggled.connect(self._toggle_always_on_top)
        layout.addWidget(checkbox)

    def _toggle_always_on_top(self, checked: bool) -> None:  # noqa: FBT001
        if checked:
            self.setWindowFlags(self.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
        else:
            self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowStaysOnTopHint)
        self.show()


def set_dialog_window_flags(dialog: QDialog) -> None:
    """Apply the standard non-modal resizable window flags to *dialog*."""
    dialog.setWindowModality(Qt.WindowModality.NonModal)
    dialog.setWindowFlags(
        Qt.WindowType.Window
        | Qt.WindowType.WindowStaysOnTopHint
        | Qt.WindowType.WindowCloseButtonHint
        | Qt.WindowType.WindowMinimizeButtonHint
        | Qt.WindowType.WindowMaximizeButtonHint,
    )


def setup_table_view_headers(table: QTableView) -> QHeaderView:
    """Hide the vertical header of *table* and return the horizontal header.

    Raises:
        RuntimeError: If either header is None.
    """
    v_header = table.verticalHeader()
    if v_header is None:
        msg = 'Failed to get vertical header'
        raise RuntimeError(msg)
    v_header.setVisible(False)
    h_header = table.horizontalHeader()
    if h_header is None:
        msg = 'Failed to get horizontal header'
        raise RuntimeError(msg)
    return h_header


def find_main_window() -> QMainWindow | None:
    """Return the first visible top-level QMainWindow, or None."""
    return next(
        (w for w in QApplication.topLevelWidgets() if isinstance(w, QMainWindow) and w.isVisible()),
        None,
    )


def create_nonmodal_warning(parent: QWidget | None, text: str) -> QMessageBox:
    """Create a pre-configured non-modal warning QMessageBox without showing it."""
    dlg = QMessageBox(parent)
    dlg.setWindowModality(Qt.WindowModality.NonModal)
    dlg.setWindowTitle(TITLE)
    dlg.setText(text)
    dlg.setIcon(QMessageBox.Icon.Warning)
    dlg.setStandardButtons(QMessageBox.StandardButton.Ok)
    return dlg


def setup_stat_table(table: QTableWidget, layout: QVBoxLayout, *, sorting: bool = True) -> None:
    """Configure *table* with standard stat-window settings and add it to *layout*.

    Raises:
        RuntimeError: If either header is None.
    """
    h_header = table.horizontalHeader()
    if h_header is None:
        msg = 'Failed to get horizontal header'
        raise RuntimeError(msg)
    h_header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    h_header.setStretchLastSection(True)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.setSortingEnabled(sorting)
    v_header = table.verticalHeader()
    if v_header is None:
        msg = 'Failed to get vertical header'
        raise RuntimeError(msg)
    v_header.setVisible(False)
    layout.addWidget(table)


def setup_stat_table_with_header(table: QTableWidget, layout: QVBoxLayout, *, sorting: bool = True) -> QHeaderView:
    """Configure *table* and return its horizontal header for further customisation.

    Calls `setup_stat_table` then retrieves the header; raises `RuntimeError` if unavailable.
    """
    setup_stat_table(table, layout, sorting=sorting)
    h_header = table.horizontalHeader()
    if h_header is None:
        msg = 'Failed to get horizontal header'
        raise RuntimeError(msg)
    return h_header
