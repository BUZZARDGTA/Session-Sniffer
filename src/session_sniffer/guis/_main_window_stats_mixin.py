"""Statistics windows and player-display mixin for `MainWindow`."""

from typing import TYPE_CHECKING

from PySide6.QtCore import QItemSelection, QItemSelectionModel
from PySide6.QtWidgets import QMainWindow

from session_sniffer.gta5.suspend_manager import GTASuspendManager
from session_sniffer.guis.capture_statistics_window import CaptureStatisticsWindow
from session_sniffer.guis.country_breakdown import CountryBreakdownWindow
from session_sniffer.guis.packets_latency_graph import PacketsLatencyGraphWindow
from session_sniffer.guis.player_leaderboard import PlayerLeaderboardWindow
from session_sniffer.guis.port_heatmap import PortHeatmapWindow
from session_sniffer.guis.reconnect_frequency import ReconnectFrequencyWindow
from session_sniffer.guis.session_bps_graph import SessionBpsGraphWindow
from session_sniffer.guis.session_duration import SessionDurationWindow
from session_sniffer.guis.session_pps_graph import SessionPpsGraphWindow
from session_sniffer.guis.session_rate_graph import SessionRateGraphWindow
from session_sniffer.guis.session_timeline import SessionTimelineWindow
from session_sniffer.guis.utils import activate_window
from session_sniffer.player.registry import PlayersRegistry, SessionHost
from session_sniffer.rdr2.suspend_manager import RDR2SuspendManager
from session_sniffer.rendering_core.types import CaptureStats
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from session_sniffer.guis._session_table_section import SessionTableSection
    from session_sniffer.models.player import Player


class StatsMixin(QMainWindow):
    """Statistics windows and player-display mixin for `MainWindow`.

    Expects these attributes on the concrete class (set in `__init__`):
        `_connected`, `_disconnected`, `_leaderboard_window`,
        `_session_rate_graph_window`, `_session_pps_graph_window`,
        `_session_bps_graph_window`, `_packets_latency_graph_window`,
        `_country_breakdown_window`, `_reconnect_frequency_window`,
        `_session_timeline_window`, `_port_heatmap_window`,
        `_session_duration_window`, `_capture_statistics_window`
    """

    # -- Attribute stubs for type checkers --
    _connected: SessionTableSection
    _disconnected: SessionTableSection
    _leaderboard_window: PlayerLeaderboardWindow | None
    _session_rate_graph_window: SessionRateGraphWindow | None
    _session_pps_graph_window: SessionPpsGraphWindow | None
    _session_bps_graph_window: SessionBpsGraphWindow | None
    _packets_latency_graph_window: PacketsLatencyGraphWindow | None
    _country_breakdown_window: CountryBreakdownWindow | None
    _reconnect_frequency_window: ReconnectFrequencyWindow | None
    _session_timeline_window: SessionTimelineWindow | None
    _port_heatmap_window: PortHeatmapWindow | None
    _session_duration_window: SessionDurationWindow | None
    _capture_statistics_window: CaptureStatisticsWindow | None

    def _sync_game_process_button(self) -> None: ...  # Provided by GameMixin

    def _select_connected_ips(self, ip_addresses: list[str]) -> None:
        """Select and scroll to player rows by IP in the connected table."""
        selection = QItemSelection()
        first_index = None
        for ip in ip_addresses:
            row = self._connected.table_model.get_row_index_by_ip(ip)
            if row is None:
                continue
            top_left = self._connected.table_model.index(row, 0)
            bottom_right = self._connected.table_model.index(row, self._connected.table_model.columnCount() - 1)
            selection.select(top_left, bottom_right)
            if first_index is None:
                first_index = top_left
        if first_index is None:
            return
        if not self._connected.is_expanded:
            self._connected.expand()
        self._connected.table_view.selectionModel().select(selection, QItemSelectionModel.SelectionFlag.ClearAndSelect)
        self._connected.table_view.scrollTo(first_index)

    def _deselect_connected_ips(self, ip_addresses: list[str] | None = None) -> None:
        """Deselect player rows by IP in the connected table, or clear selection if None or empty."""
        if not ip_addresses:
            self._connected.table_view.selectionModel().clearSelection()
            return
        selection = QItemSelection()
        for ip in ip_addresses:
            row = self._connected.table_model.get_row_index_by_ip(ip)
            if row is None:
                continue
            top_left = self._connected.table_model.index(row, 0)
            bottom_right = self._connected.table_model.index(row, self._connected.table_model.columnCount() - 1)
            selection.select(top_left, bottom_right)
        if not selection.isEmpty():
            self._connected.table_view.selectionModel().select(selection, QItemSelectionModel.SelectionFlag.Deselect)

    def _select_ips(self, ip_addresses: list[str]) -> None:
        """Select and scroll to player rows by IP, checking connected first then disconnected."""
        connected_selection = QItemSelection()
        disconnected_selection = QItemSelection()
        connected_first_index = None
        disconnected_first_index = None
        for ip in ip_addresses:
            row = self._connected.table_model.get_row_index_by_ip(ip)
            if row is not None:
                top_left = self._connected.table_model.index(row, 0)
                bottom_right = self._connected.table_model.index(row, self._connected.table_model.columnCount() - 1)
                connected_selection.select(top_left, bottom_right)
                if connected_first_index is None:
                    connected_first_index = top_left
            else:
                row = self._disconnected.table_model.get_row_index_by_ip(ip)
                if row is not None:
                    top_left = self._disconnected.table_model.index(row, 0)
                    bottom_right = self._disconnected.table_model.index(row, self._disconnected.table_model.columnCount() - 1)
                    disconnected_selection.select(top_left, bottom_right)
                    if disconnected_first_index is None:
                        disconnected_first_index = top_left
        if connected_first_index is not None:
            if not self._connected.is_expanded:
                self._connected.expand()
            self._connected.table_view.selectionModel().select(connected_selection, QItemSelectionModel.SelectionFlag.ClearAndSelect)
            self._connected.table_view.scrollTo(connected_first_index)
        if disconnected_first_index is not None:
            if not self._disconnected.is_expanded:
                self._disconnected.expand()
            self._disconnected.table_view.selectionModel().select(disconnected_selection, QItemSelectionModel.SelectionFlag.ClearAndSelect)
            self._disconnected.table_view.scrollTo(disconnected_first_index)

    def _open_player_leaderboard(self) -> None:
        """Open the Most Seen Players leaderboard, or focus the existing one."""
        if self._leaderboard_window is not None:
            activate_window(self._leaderboard_window)
            return
        window = PlayerLeaderboardWindow()
        window.destroyed.connect(lambda: setattr(self, '_leaderboard_window', None) if self._leaderboard_window is window else None)
        self._leaderboard_window = window
        self._leaderboard_window.load_and_show()

    def reset_session_graph(self) -> None:
        """Reset graph history for all open statistics windows (called on capture restart)."""
        if self._session_rate_graph_window is not None:
            self._session_rate_graph_window.reset()
        if self._session_pps_graph_window is not None:
            self._session_pps_graph_window.reset()
        if self._session_bps_graph_window is not None:
            self._session_bps_graph_window.reset()
        if self._packets_latency_graph_window is not None:
            self._packets_latency_graph_window.reset()
        if self._capture_statistics_window is not None:
            self._capture_statistics_window.reset()

    def _open_session_rate_graph(self) -> None:
        """Open or focus the session-wide rate graph window."""
        if self._session_rate_graph_window is not None:
            activate_window(self._session_rate_graph_window)
            return

        window = SessionRateGraphWindow()
        window.destroyed.connect(lambda: setattr(self, '_session_rate_graph_window', None) if self._session_rate_graph_window is window else None)
        self._session_rate_graph_window = window
        self._session_rate_graph_window.show()

    def _tick_stats(self) -> None:
        """Tick all open statistics windows with the latest data."""
        CaptureStats.capture_health_samples.append(
            (
                CaptureStats.global_avg_latency_ms,
                CaptureStats.global_pps_rate,
                CaptureStats.global_bps_rate,
            ),
        )
        if self._session_rate_graph_window is not None:
            self._session_rate_graph_window.update_rates(
                pps=CaptureStats.global_pps_rate,
                bps=CaptureStats.global_bps_rate,
            )
        if self._session_pps_graph_window is not None:
            self._session_pps_graph_window.update_pps(CaptureStats.global_pps_rate)
        if self._session_bps_graph_window is not None:
            self._session_bps_graph_window.update_bps(CaptureStats.global_bps_rate)
        if self._packets_latency_graph_window is not None:
            self._packets_latency_graph_window.update_latency(CaptureStats.global_avg_latency_ms)
        if self._country_breakdown_window is not None:
            self._country_breakdown_window.refresh()
        if self._reconnect_frequency_window is not None:
            self._reconnect_frequency_window.refresh()
        if self._session_timeline_window is not None:
            self._session_timeline_window.refresh()
        if self._port_heatmap_window is not None:
            self._port_heatmap_window.refresh()
        if self._session_duration_window is not None:
            self._session_duration_window.refresh()

        # Sync game process control state every tick
        if Settings.is_gta5_feature_set() or Settings.is_rdr2_feature_set():
            self._sync_game_process_button()

    def _open_session_pps_graph(self) -> None:
        """Open or focus the session-wide PPS graph window."""
        if self._session_pps_graph_window is not None:
            activate_window(self._session_pps_graph_window)
            return

        window = SessionPpsGraphWindow()
        window.destroyed.connect(lambda: setattr(self, '_session_pps_graph_window', None) if self._session_pps_graph_window is window else None)
        self._session_pps_graph_window = window
        self._session_pps_graph_window.show()

    def _open_session_bps_graph(self) -> None:
        """Open or focus the session-wide BPS graph window."""
        if self._session_bps_graph_window is not None:
            activate_window(self._session_bps_graph_window)
            return

        window = SessionBpsGraphWindow()
        window.destroyed.connect(lambda: setattr(self, '_session_bps_graph_window', None) if self._session_bps_graph_window is window else None)
        self._session_bps_graph_window = window
        self._session_bps_graph_window.show()

    def _open_packets_latency_graph(self) -> None:
        """Open or focus the packets latency graph window."""
        if self._packets_latency_graph_window is not None:
            activate_window(self._packets_latency_graph_window)
            return

        window = PacketsLatencyGraphWindow()
        window.destroyed.connect(lambda: setattr(self, '_packets_latency_graph_window', None) if self._packets_latency_graph_window is window else None)
        self._packets_latency_graph_window = window
        self._packets_latency_graph_window.show()

    def _open_country_breakdown(self) -> None:
        """Open or focus the country breakdown window."""
        if self._country_breakdown_window is not None:
            activate_window(self._country_breakdown_window)
            return

        window = CountryBreakdownWindow(always_on_top=True)
        window.destroyed.connect(lambda: setattr(self, '_country_breakdown_window', None) if self._country_breakdown_window is window else None)
        self._country_breakdown_window = window
        self._country_breakdown_window.show()

    def _open_reconnect_frequency(self) -> None:
        """Open or focus the reconnect frequency window."""
        if self._reconnect_frequency_window is not None:
            activate_window(self._reconnect_frequency_window)
            return

        window = ReconnectFrequencyWindow(always_on_top=True)
        window.destroyed.connect(lambda: setattr(self, '_reconnect_frequency_window', None) if self._reconnect_frequency_window is window else None)
        self._reconnect_frequency_window = window
        self._reconnect_frequency_window.show()

    def _open_session_timeline(self) -> None:
        """Open or focus the session timeline window."""
        if self._session_timeline_window is not None:
            activate_window(self._session_timeline_window)
            return

        window = SessionTimelineWindow(always_on_top=True)
        window.destroyed.connect(lambda: setattr(self, '_session_timeline_window', None) if self._session_timeline_window is window else None)
        self._session_timeline_window = window
        self._session_timeline_window.show()

    def _open_port_heatmap(self) -> None:
        """Open or focus the port heatmap window."""
        if self._port_heatmap_window is not None:
            activate_window(self._port_heatmap_window)
            return

        window = PortHeatmapWindow(always_on_top=True)
        window.destroyed.connect(lambda: setattr(self, '_port_heatmap_window', None) if self._port_heatmap_window is window else None)
        self._port_heatmap_window = window
        self._port_heatmap_window.show()

    def _open_session_duration(self) -> None:
        """Open or focus the session duration window."""
        if self._session_duration_window is not None:
            activate_window(self._session_duration_window)
            return

        window = SessionDurationWindow(always_on_top=True)
        window.destroyed.connect(lambda: setattr(self, '_session_duration_window', None) if self._session_duration_window is window else None)
        self._session_duration_window = window
        self._session_duration_window.show()

    def _open_capture_health(self) -> None:
        """Open or focus the capture statistics window."""
        if self._capture_statistics_window is not None:
            activate_window(self._capture_statistics_window)
            return

        window = CaptureStatisticsWindow()
        window.open_session_pps_graph_requested.connect(self._open_session_pps_graph)
        window.open_session_bps_graph_requested.connect(self._open_session_bps_graph)
        window.open_packets_latency_graph_requested.connect(self._open_packets_latency_graph)
        window.destroyed.connect(lambda: setattr(self, '_capture_statistics_window', None) if self._capture_statistics_window is window else None)
        self._capture_statistics_window = window
        self._capture_statistics_window.show()

    def remove_player_from_connected(self, ip: str) -> None:
        """Remove a single player from connected table and registry by IP address."""
        removed_player: Player | None = PlayersRegistry.remove_connected_player(ip)
        if removed_player is None:
            return

        SessionHost.players_pending_for_disconnection = [player for player in SessionHost.players_pending_for_disconnection if player.ip != ip]

        self._connected.table_model.remove_player_by_ip(ip)

        GTASuspendManager.release_reasons_for_ip(ip)
        RDR2SuspendManager.release_reasons_for_ip(ip)

    def remove_player_from_disconnected(self, ip: str) -> None:
        """Remove a single player from disconnected table and registry by IP address."""
        removed_player: Player | None = PlayersRegistry.remove_disconnected_player(ip)
        if removed_player is None:
            return

        self._disconnected.table_model.remove_player_by_ip(ip)

        GTASuspendManager.release_reasons_for_ip(ip)
        RDR2SuspendManager.release_reasons_for_ip(ip)
