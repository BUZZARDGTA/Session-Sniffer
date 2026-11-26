"""Player Resolver — tabbed container for High Rate Monitor and Player Identifier."""

from typing import TYPE_CHECKING, override

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent, QIcon, QShowEvent
from PySide6.QtWidgets import (
    QTabWidget,
    QVBoxLayout,
)

from session_sniffer.guis.app import activate_window
from session_sniffer.guis.high_rate_monitor import HighRateMonitorWidget
from session_sniffer.guis.live_language import register_language_refresh
from session_sniffer.guis.player_identifier import PlayerIdentifierWidget
from session_sniffer.guis.theming import ICONS_DIR_PATH
from session_sniffer.guis.utils import ToggleAlwaysOnTopMixin, scale_by_ui
from session_sniffer.guis.window_layout import apply_maximize_on_show, restore_window_layout, save_window_layout_with_always_on_top
from session_sniffer.i18n import tr
from session_sniffer.models import GUIState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtWidgets import QWidget


class PlayerResolverWindow(ToggleAlwaysOnTopMixin):
    """Tabbed window hosting the High Rate Monitor and Player Identifier tools."""

    def __init__(
        self,
        select_ips_callback: Callable[[list[str]], None],
        deselect_ips_callback: Callable[[list[str] | None], None],
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the Player Resolver window."""
        super().__init__(parent)
        self._has_been_shown = False

        self.setMinimumSize(scale_by_ui(600), scale_by_ui(390))
        win_state = restore_window_layout(self, 'player_resolver')
        always_on_top = win_state.always_on_top if win_state is not None and win_state.always_on_top is not None else False
        flags = (
            Qt.WindowType.Window
            | Qt.WindowType.WindowCloseButtonHint
            | Qt.WindowType.WindowMinimizeButtonHint
            | Qt.WindowType.WindowMaximizeButtonHint
        )
        if always_on_top:
            flags |= Qt.WindowType.WindowStaysOnTopHint
        self.setWindowFlags(flags)

        layout = QVBoxLayout(self)

        # Tabs
        self._tabs = QTabWidget()
        layout.addWidget(self._tabs)

        # Tab 1: Player High Rate Monitor
        self.high_rate_monitor = HighRateMonitorWidget(select_ips_callback, deselect_ips_callback, self)
        self._tabs.addTab(self.high_rate_monitor, QIcon(str(ICONS_DIR_PATH / 'gauge.svg')), '')

        # Tab 2: Player Identifier
        self.player_identifier = PlayerIdentifierWidget(select_ips_callback, deselect_ips_callback, self)
        self._tabs.addTab(self.player_identifier, QIcon(str(ICONS_DIR_PATH / 'user-round-search.svg')), '')

        if win_state is not None and win_state.active_tab is not None and 0 <= win_state.active_tab < self._tabs.count():
            self._tabs.setCurrentIndex(win_state.active_tab)

        self._apply_translations()
        register_language_refresh(self, self._apply_translations)

        # Always on top checkbox (shared across tabs)
        self.add_always_on_top_checkbox(layout, always_on_top=always_on_top, alignment=Qt.AlignmentFlag.AlignHCenter)

    def _apply_translations(self) -> None:
        """Apply translated text to the window title and tab labels."""
        self.setWindowTitle(tr('Player Resolver'))
        self._tabs.setTabText(0, tr('Player High Rate Monitor'))
        self._tabs.setTabText(1, tr('Player Identifier'))

    def show_and_focus(self, tab_index: int | None = None) -> None:
        """Show the window, bring it to the front, and optionally switch to *tab_index*."""
        if tab_index is not None and 0 <= tab_index < self._tabs.count():
            self._tabs.setCurrentIndex(tab_index)
        activate_window(self)

    @override
    def showEvent(self, event: QShowEvent) -> None:
        """Handle window show event to maximize if required and start monitoring when background running is disabled."""
        self._has_been_shown = True
        super().showEvent(event)
        apply_maximize_on_show(self)
        if not Settings.high_rate_monitor_run_in_background:
            self.high_rate_monitor.start_monitoring()

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Persist window layout when shown and stop monitoring when background running is disabled."""
        if self._has_been_shown and Settings.gui_remember_window_layout:
            gui_state = GUIState.load()
            if (win_state := save_window_layout_with_always_on_top(self, 'player_resolver', gui_state=gui_state)) is not None:
                win_state.active_tab = self._tabs.currentIndex()
            gui_state.save()
        if not Settings.high_rate_monitor_run_in_background and not self.high_rate_monitor.has_open_graphs():
            self.high_rate_monitor.stop_monitoring()
        super().closeEvent(event)
