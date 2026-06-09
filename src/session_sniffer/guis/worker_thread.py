"""Background QThread that polls rendering snapshots and emits GUI update payloads."""

from typing import override

from PyQt6.QtCore import pyqtSignal

from session_sniffer.background.events import gui_closed__event
from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.rendering_core.types import CellColor, GUIRenderingSnapshot, GUIRenderingState, GUIUpdatePayload, PaginationState, SearchState


def _search_filter(
    rows: list[tuple[list[str], list[CellColor]]],
    text: str,
    column: int,
) -> list[tuple[list[str], list[CellColor]]]:
    """Return only rows whose target cell(s) contain `text` (case-insensitive).

    When `column` is -1, all cells are checked. Otherwise only the cell at `column` is checked.
    """
    lowered = text.lower()
    if column < 0:
        return [(row, colors) for row, colors in rows if any(lowered in cell.lower() for cell in row)]
    return [(row, colors) for row, colors in rows if column < len(row) and lowered in row[column].lower()]


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


class GUIWorkerThread(CrashingQThread):
    """Emit GUI update payloads compiled by the rendering core."""

    update_signal = pyqtSignal(GUIUpdatePayload)

    @override
    def _run(self) -> None:
        """Continuously emit GUI payloads while the app is running."""
        last_seen_version = 0
        last_snapshot: GUIRenderingSnapshot | None = None
        last_search_version: int = -1

        while not gui_closed__event.is_set():
            snapshot, last_seen_version = GUIRenderingState.wait_rendering_snapshot(
                timeout=0.1,
                last_seen_version=last_seen_version,
            )

            c_text, c_col, d_text, d_col, search_version = SearchState.get()

            if snapshot is not None:
                last_snapshot = snapshot
            elif search_version == last_search_version or last_snapshot is None:
                continue

            last_search_version = search_version

            status = last_snapshot.status
            connected_num = last_snapshot.connected.num_rows
            disconnected_num = last_snapshot.disconnected.num_rows

            # Preprocess rows with colors
            connected_rows_with_colors: list[tuple[list[str], list[CellColor]]] = [
                (list(row), list(colors))
                for row, colors in zip(last_snapshot.connected.rows, last_snapshot.connected.colors, strict=True)
            ]
            disconnected_rows_with_colors: list[tuple[list[str], list[CellColor]]] = [
                (list(row), list(colors))
                for row, colors in zip(last_snapshot.disconnected.rows, last_snapshot.disconnected.colors, strict=True)
            ]

            # Apply search filter (before pagination so counts and pages stay accurate)
            if c_text:
                connected_rows_with_colors = _search_filter(connected_rows_with_colors, c_text, c_col)
                connected_num = len(connected_rows_with_colors)
            if d_text:
                disconnected_rows_with_colors = _search_filter(disconnected_rows_with_colors, d_text, d_col)
                disconnected_num = len(disconnected_rows_with_colors)

            # Apply pagination
            c_rpp, c_page, d_rpp, d_page = PaginationState.get()

            connected_rows_with_colors, connected_page, connected_total_pages = _paginate(
                connected_rows_with_colors, connected_num, c_rpp, c_page,
            )
            disconnected_rows_with_colors, disconnected_page, disconnected_total_pages = _paginate(
                disconnected_rows_with_colors, disconnected_num, d_rpp, d_page,
            )

            self.update_signal.emit(GUIUpdatePayload(
                snapshot_version=last_seen_version,
                column_config=last_snapshot.column_config,
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
