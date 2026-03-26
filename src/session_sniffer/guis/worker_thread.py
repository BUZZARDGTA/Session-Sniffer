"""Background QThread that polls rendering snapshots and emits GUI update payloads."""

from typing import TYPE_CHECKING

from PyQt6.QtCore import QThread, pyqtSignal

from session_sniffer.background.tasks import gui_closed__event
from session_sniffer.rendering_core.types import CellColor, GUIRenderingState, GUIUpdatePayload

if TYPE_CHECKING:
    from session_sniffer.guis.tables import SessionTableView


class GUIWorkerThread(QThread):
    """Emit GUI update payloads compiled by the rendering core."""

    update_signal = pyqtSignal(GUIUpdatePayload)

    def __init__(
        self,
        connected_table_view: SessionTableView,
        disconnected_table_view: SessionTableView,
    ) -> None:
        """Initialize the GUI worker thread.

        Args:
            connected_table_view: The connected players table view.
            disconnected_table_view: The disconnected players table view.
        """
        super().__init__()

        self.connected_table_view = connected_table_view
        self.disconnected_table_view = disconnected_table_view

    def run(self) -> None:
        """Continuously emit GUI payloads while the app is running."""
        last_snapshot_version = 0

        while not gui_closed__event.is_set():
            snapshot, last_snapshot_version = GUIRenderingState.wait_rendering_snapshot(
                timeout=0.1,
                last_seen_version=last_snapshot_version,
            )
            if snapshot is None:
                continue

            header_text = snapshot.header_text
            status_capture_text = snapshot.status_capture_text
            status_config_text = snapshot.status_config_text
            status_issues_text = snapshot.status_issues_text
            status_performance_text = snapshot.status_performance_text
            connected_num = snapshot.connected_num_rows
            disconnected_num = snapshot.disconnected_num_rows

            # Preprocess rows with colors
            connected_rows_with_colors: list[tuple[list[str], list[CellColor]]] = [
                (list(row), list(colors))
                for row, colors in zip(snapshot.connected_rows, snapshot.connected_colors, strict=True)
            ]
            disconnected_rows_with_colors: list[tuple[list[str], list[CellColor]]] = [
                (list(row), list(colors))
                for row, colors in zip(snapshot.disconnected_rows, snapshot.disconnected_colors, strict=True)
            ]

            self.update_signal.emit(GUIUpdatePayload(
                snapshot_version=last_snapshot_version,
                header_text=header_text,
                status_capture_text=status_capture_text,
                status_config_text=status_config_text,
                status_issues_text=status_issues_text,
                status_performance_text=status_performance_text,
                connected_rows_with_colors=connected_rows_with_colors,
                disconnected_rows_with_colors=disconnected_rows_with_colors,
                connected_num=connected_num,
                disconnected_num=disconnected_num,
            ))
