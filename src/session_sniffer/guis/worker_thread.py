"""Background QThread that polls rendering snapshots and emits GUI update payloads."""

import time

from PyQt6.QtCore import QThread, pyqtSignal

from session_sniffer.background.tasks import gui_closed__event
from session_sniffer.diagnostics import SlowdownDetector
from session_sniffer.logging_setup import get_logger
from session_sniffer.rendering_core.types import CellColor, GUIRenderingState, GUIUpdatePayload, PaginationState

logger = get_logger(__name__)


def _paginate(
    rows: list[tuple[list[str], list[CellColor]]],
    total_rows: int,
    rows_per_page: int,
    requested_page: int,
) -> tuple[list[tuple[list[str], list[CellColor]]], int, int]:
    """Slice rows into a single page.

    Returns:
        (page_rows, clamped_page, total_pages)
    """
    if rows_per_page <= 0:
        return rows, 1, 1

    total_pages = max(1, (total_rows + rows_per_page - 1) // rows_per_page)
    page = min(max(1, requested_page), total_pages)
    start_index = (page - 1) * rows_per_page
    return rows[start_index:start_index + rows_per_page], page, total_pages


class GUIWorkerThread(QThread):
    """Emit GUI update payloads compiled by the rendering core."""

    update_signal = pyqtSignal(GUIUpdatePayload)

    def run(self) -> None:
        """Continuously emit GUI payloads while the app is running."""
        last_snapshot_version = 0
        _preprocessing_slowdown = SlowdownDetector.get('gui_worker_preprocessing')

        while not gui_closed__event.is_set():
            try:
                snapshot, last_snapshot_version = GUIRenderingState.wait_rendering_snapshot(
                    timeout=0.1,
                    last_seen_version=last_snapshot_version,
                )
            except RuntimeError:
                logger.exception('Error waiting for rendering snapshot')
                continue

            if snapshot is None:
                continue

            status = snapshot.status
            connected_num = snapshot.connected.num_rows
            disconnected_num = snapshot.disconnected.num_rows

            # Preprocess rows with colors
            try:
                _preprocess_start = time.monotonic()
                connected_rows_with_colors: list[tuple[list[str], list[CellColor]]] = [
                    (list(row), list(colors))
                    for row, colors in zip(snapshot.connected.rows, snapshot.connected.colors, strict=True)
                ]
                disconnected_rows_with_colors: list[tuple[list[str], list[CellColor]]] = [
                    (list(row), list(colors))
                    for row, colors in zip(snapshot.disconnected.rows, snapshot.disconnected.colors, strict=True)
                ]

                # Apply pagination
                c_rpp, c_page, d_rpp, d_page = PaginationState.get()

                connected_rows_with_colors, connected_page, connected_total_pages = _paginate(
                    connected_rows_with_colors, connected_num, c_rpp, c_page,
                )
                disconnected_rows_with_colors, disconnected_page, disconnected_total_pages = _paginate(
                    disconnected_rows_with_colors, disconnected_num, d_rpp, d_page,
                )

                _preprocessing_slowdown.check(time.monotonic() - _preprocess_start, 'gui_worker_preprocessing')
                self.update_signal.emit(GUIUpdatePayload(
                    snapshot_version=last_snapshot_version,
                    column_config=snapshot.column_config,
                    header_text=status.header_text,
                    status_capture_text=status.status_capture_text,
                    status_config_text=status.status_config_text,
                    status_issues_text=status.status_issues_text,
                    status_performance_text=status.status_performance_text,
                    connected_rows_with_colors=connected_rows_with_colors,
                    disconnected_rows_with_colors=disconnected_rows_with_colors,
                    connected_num=connected_num,
                    disconnected_num=disconnected_num,
                    connected_rows_per_page=c_rpp,
                    disconnected_rows_per_page=d_rpp,
                    connected_page=connected_page,
                    disconnected_page=disconnected_page,
                    connected_total_pages=connected_total_pages,
                    disconnected_total_pages=disconnected_total_pages,
                ))
            except (ValueError, RuntimeError):
                logger.exception('Error processing or emitting GUI update payload')
