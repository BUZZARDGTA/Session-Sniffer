"""Player Resolver — tabbed container for High Rate Monitor and Player Identifier."""

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.guis.high_pps_monitor import HighRateMonitorWidget
from session_sniffer.guis.player_identifier import PlayerIdentifierWidget
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable


class PlayerResolverWindow(QWidget):  # pylint: disable=too-few-public-methods
    """Tabbed window hosting the High Rate Monitor and Player Identifier tools."""

    def __init__(self, highlight_ips_callback: Callable[[list[str]], None], parent: QWidget | None = None) -> None:
        """Initialize the Player Resolver window."""
        super().__init__(parent)

        self.setWindowTitle('Player Resolver')
        self.setMinimumSize(700, 400)
        _base_flags = Qt.WindowType.Window | Qt.WindowType.WindowCloseButtonHint
        if Settings.gui_rate_graph_always_on_top:
            _base_flags |= Qt.WindowType.WindowStaysOnTopHint
        self.setWindowFlags(_base_flags)

        layout = QVBoxLayout(self)

        # Tabs
        self._tabs = QTabWidget()
        layout.addWidget(self._tabs)

        # Tab 1: High Rate Monitor
        self.high_rate_monitor = HighRateMonitorWidget(self)
        self._tabs.addTab(self.high_rate_monitor, '\U0001f4c8 High Rate Monitor')

        # Tab 2: Player Identifier
        self.player_identifier = PlayerIdentifierWidget(highlight_ips_callback, self)
        self._tabs.addTab(self.player_identifier, '\U0001f3af Player Identifier')

        # Always on top checkbox (shared across tabs)
        always_on_top_checkbox = QCheckBox('Always on Top')
        always_on_top_checkbox.setToolTip('Keep this window above all other windows.')
        always_on_top_checkbox.setChecked(Settings.gui_rate_graph_always_on_top)
        always_on_top_checkbox.toggled.connect(self._toggle_always_on_top)
        layout.addWidget(always_on_top_checkbox, alignment=Qt.AlignmentFlag.AlignHCenter)

    def _toggle_always_on_top(self, checked: bool) -> None:  # noqa: FBT001
        if checked:
            self.setWindowFlags(self.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
        else:
            self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowStaysOnTopHint)
        self.show()
