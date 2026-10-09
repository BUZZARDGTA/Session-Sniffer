"""Background QThread that polls rendering snapshots and emits GUI update payloads."""

import logging
from collections.abc import Sequence
from typing import override

from PySide6.QtCore import Signal

from session_sniffer.background.events import gui_closed__event
from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.table_model import sort_table_rows
from session_sniffer.player.registry import PlayersRegistry, SessionTracker
from session_sniffer.rendering_core.types import (
    CellColor,
    GUIRenderingSnapshot,
    GUIRenderingState,
    GUIUpdatePayload,
    PaginationState,
    SearchState,
    SessionFilterState,
    SortState,
    TableMergeState,
)

logger = logging.getLogger(__name__)

_COLUMN_ALL = -1
_COLUMN_NOT_FOUND = -2


def _search_filter[T: Sequence[str], C: Sequence[CellColor]](
    rows: Sequence[tuple[T, C]],
    text: str,
    column: int,
) -> list[tuple[T, C]]:
    """Return only rows whose target cell(s) contain `text` (case-insensitive).

    When `column` is -1, all cells are checked. Otherwise only the cell at `column` is checked.
    """
    lowered = text.lower()
    if column < 0:
        return [entry for entry in rows if any(lowered in cell.lower() for cell in entry[0])]
    return [entry for entry in rows if column < len(entry[0]) and lowered in entry[0][column].lower()]


def _paginate[T](
    rows: Sequence[T],
    total_rows: int,
    rows_per_page: int,
    requested_page: int,
) -> tuple[Sequence[T], int, int]:
    """Slice rows into a single page.

    Returns:
        (page_rows, clamped_page, total_pages)
    """
    if rows_per_page <= 0:
        return rows, 1, 1

    total_pages = max(1, (total_rows + rows_per_page - 1) // rows_per_page)
    page = min(max(1, requested_page), total_pages)
    start_index = (page - 1) * rows_per_page
    return rows[start_index : start_index + rows_per_page], page, total_pages


class GUIWorkerThread(CrashingQThread):
    """Emit GUI update payloads compiled by the rendering core."""

    update_signal: Signal = Signal(object)

    @override
    def requestInterruption(self) -> None:
        """Request thread interruption and wake the rendering snapshot condition."""
        super().requestInterruption()
        GUIRenderingState.wake()

    @override
    def cancel(self, timeout_ms: int = 2000) -> bool:
        """Cancel worker thread, waking the rendering snapshot condition immediately."""
        GUIRenderingState.wake()
        return super().cancel(timeout_ms)

    @override
    def _run(self) -> None:
        """Continuously emit GUI payloads while the app is running."""
        last_seen_version = 0
        last_snapshot: GUIRenderingSnapshot | None = None
        last_search_version: int = -1
        last_pagination_version: int = -1
        last_sort_version: int = -1
        last_session_filter_version: int = -1
        last_table_merge_version: int = -1
        last_session_id: int = -1

        cached_connected_zipped: list[tuple[tuple[str, ...], tuple[CellColor, ...]]] = []
        cached_disconnected_zipped: list[tuple[tuple[str, ...], tuple[CellColor, ...]]] = []
        cached_connected_sorted: Sequence[tuple[tuple[str, ...], tuple[CellColor, ...]]] = ()
        cached_disconnected_sorted: Sequence[tuple[tuple[str, ...], tuple[CellColor, ...]]] = ()
        cached_connected_count: int = 0
        cached_disconnected_count: int = 0

        logger.debug('GUIWorkerThread _run loop entered')
        while not gui_closed__event.is_set() and not self.isInterruptionRequested():
            snapshot, last_seen_version = GUIRenderingState.wait_rendering_snapshot(
                timeout=0.1,
                last_seen_version=last_seen_version,
            )
            if self.isInterruptionRequested() or gui_closed__event.is_set():
                logger.debug('GUIWorkerThread _run loop terminating (gui_closed=%s, interruption=%s)', gui_closed__event.is_set(), self.isInterruptionRequested())
                return

            search_text, search_column_name, search_version = SearchState.get()
            connected_rows_per_page, connected_page, disconnected_rows_per_page, disconnected_page, pagination_version = PaginationState.get()
            connected_sort_col, connected_sort_order, disconnected_sort_col, disconnected_sort_order, sort_version = SortState.get()
            selected_session, session_filter_version = SessionFilterState.get()
            table_merge_version = TableMergeState.get_version()
            current_session_id = SessionTracker.get_current_session_id()

            current_session_changed = (
                selected_session == SessionFilterState.FILTER_CURRENT
                and current_session_id != last_session_id
            )
            needs_filter_and_sort = (
                snapshot is not None
                or search_version != last_search_version
                or sort_version != last_sort_version
                or session_filter_version != last_session_filter_version
                or table_merge_version != last_table_merge_version
                or current_session_changed
            )
            pagination_changed = pagination_version != last_pagination_version

            if snapshot is not None:
                last_snapshot = snapshot
                cached_connected_zipped = list(snapshot.connected.rows_with_colors)
                cached_disconnected_zipped = list(snapshot.disconnected.rows_with_colors)
            elif last_snapshot is None or not (needs_filter_and_sort or pagination_changed):
                continue

            last_search_version = search_version
            last_pagination_version = pagination_version
            last_sort_version = sort_version
            last_session_filter_version = session_filter_version
            last_table_merge_version = table_merge_version
            last_session_id = current_session_id

            if needs_filter_and_sort:
                source_connected: list[tuple[tuple[str, ...], tuple[CellColor, ...]]]
                source_disconnected: list[tuple[tuple[str, ...], tuple[CellColor, ...]]]
                if 0 < selected_session < current_session_id:
                    source_connected = []
                    past_data = last_snapshot.past_sessions.get(selected_session)
                    source_disconnected = list(past_data.rows_with_colors) if past_data is not None else []
                elif selected_session == SessionFilterState.FILTER_CURRENT:
                    if TableMergeState.is_merged():
                        try:
                            connected_ip_col = last_snapshot.column_config.connected_column_names.index('IP Address')
                        except ValueError:
                            connected_ip_col = _COLUMN_NOT_FOUND

                        if connected_ip_col != _COLUMN_NOT_FOUND:
                            players_map = PlayersRegistry.get_players_map()
                            source_connected = [
                                entry
                                for entry in cached_connected_zipped
                                if (player := players_map.get(entry[0][connected_ip_col])) is not None and player.session_id == current_session_id
                            ]
                        else:
                            source_connected = cached_connected_zipped
                    else:
                        source_connected = cached_connected_zipped
                    try:
                        disconnected_ip_col = last_snapshot.column_config.disconnected_column_names.index('IP Address')
                    except ValueError:
                        disconnected_ip_col = _COLUMN_NOT_FOUND

                    if disconnected_ip_col != _COLUMN_NOT_FOUND:
                        players_map = PlayersRegistry.get_players_map()
                        source_disconnected = [
                            entry
                            for entry in cached_disconnected_zipped
                            if (player := players_map.get(entry[0][disconnected_ip_col])) is not None and player.session_id == current_session_id
                        ]
                    else:
                        source_disconnected = cached_disconnected_zipped
                else:
                    source_connected = cached_connected_zipped
                    source_disconnected = cached_disconnected_zipped

                # Apply search filter (before sorting and pagination so counts and pages stay accurate)
                if search_text:
                    if search_column_name and search_column_name != 'All Columns':
                        try:
                            connected_col = last_snapshot.column_config.connected_column_names.index(search_column_name)
                        except ValueError:
                            connected_col = _COLUMN_NOT_FOUND
                        try:
                            disconnected_col = last_snapshot.column_config.disconnected_column_names.index(search_column_name)
                        except ValueError:
                            disconnected_col = _COLUMN_NOT_FOUND
                    else:
                        connected_col = _COLUMN_ALL
                        disconnected_col = _COLUMN_ALL

                    filtered_connected = (
                        []
                        if connected_col == _COLUMN_NOT_FOUND or not source_connected
                        else _search_filter(source_connected, search_text, connected_col)
                    )
                    cached_connected_count = len(filtered_connected)

                    filtered_disconnected = (
                        []
                        if disconnected_col == _COLUMN_NOT_FOUND
                        else _search_filter(source_disconnected, search_text, disconnected_col)
                    )
                    cached_disconnected_count = len(filtered_disconnected)
                else:
                    filtered_connected = source_connected
                    cached_connected_count = len(source_connected)
                    filtered_disconnected = source_disconnected
                    cached_disconnected_count = len(source_disconnected)

                # Apply sorting (before pagination so each page contains the correct slice of sorted data)
                cached_connected_sorted = (
                    sort_table_rows(
                        filtered_connected,
                        connected_sort_col,
                        connected_sort_order,
                        last_snapshot.column_config.connected_column_names,
                    )
                    if filtered_connected
                    else ()
                )
                cached_disconnected_sorted = (
                    sort_table_rows(
                        filtered_disconnected,
                        disconnected_sort_col,
                        disconnected_sort_order,
                        last_snapshot.column_config.disconnected_column_names,
                    )
                    if filtered_disconnected
                    else ()
                )

            # Apply pagination
            connected_page_rows, connected_page, connected_total_pages = _paginate(
                cached_connected_sorted,
                cached_connected_count,
                connected_rows_per_page,
                connected_page,
            )
            disconnected_page_rows, disconnected_page, disconnected_total_pages = _paginate(
                cached_disconnected_sorted,
                cached_disconnected_count,
                disconnected_rows_per_page,
                disconnected_page,
            )

            self.update_signal.emit(
                GUIUpdatePayload(
                    snapshot_version=last_seen_version,
                    column_config=last_snapshot.column_config,
                    header_text=last_snapshot.status.header_text,
                    status_capture_text=last_snapshot.status.status_capture_text,
                    status_config_text=last_snapshot.status.status_config_text,
                    status_issues_text=last_snapshot.status.status_issues_text,
                    status_performance_text=last_snapshot.status.status_performance_text,
                    connected_rows_with_colors=connected_page_rows,
                    disconnected_rows_with_colors=disconnected_page_rows,
                    connected_count=cached_connected_count,
                    disconnected_count=cached_disconnected_count,
                    connected_rows_per_page=connected_rows_per_page,
                    disconnected_rows_per_page=disconnected_rows_per_page,
                    connected_page=connected_page,
                    disconnected_page=disconnected_page,
                    connected_total_pages=connected_total_pages,
                    disconnected_total_pages=disconnected_total_pages,
                ),
            )
