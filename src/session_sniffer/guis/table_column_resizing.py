"""Utilities for sizing and interactively resizing QTableView, QTreeView, and QTableWidget columns."""

from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING

from PySide6.QtCore import QAbstractItemModel, QPoint, QSize, Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QHeaderView, QMenu, QTableView, QTableWidget, QTreeView

from session_sniffer.constants.tables import (
    DEFAULT_MIN_COLUMN_WIDTH,
    FLEXIBLE_COLUMN_WEIGHTS,
    FLEXIBLE_STRETCH_COLUMNS,
)
from session_sniffer.guis.live_language import CANONICAL_HEADER_ROLE
from session_sniffer.guis.utils import add_icon_menu_action, create_styled_context_menu, scale_by_ui
from session_sniffer.i18n import tr

_MINIMUM_VIEWPORT_WIDTH_THRESHOLD = 100
_STANDARD_ICON_SIZE = 16

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Sequence


@dataclass(frozen=True, slots=True)
class ColumnSizingMenuCallbacks:
    """Optional callbacks for column sizing and order actions in a table header context menu."""

    on_reset: Callable[[], None] | None = None
    on_reset_order: Callable[[], None] | None = None
    on_fit_column: Callable[[int], None] | None = None
    on_fit_all: Callable[[], None] | None = None


def _get_canonical_header_label(model: QAbstractItemModel, column: int) -> str:
    """Return the canonical English header name for *column*, falling back to DisplayRole."""
    canonical = model.headerData(column, Qt.Orientation.Horizontal, CANONICAL_HEADER_ROLE)
    if isinstance(canonical, str) and canonical:
        return canonical
    display = model.headerData(column, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole)
    return str(display) if display is not None else ''


def _get_horizontal_header(table: QTableView | QTreeView | QTableWidget) -> QHeaderView | None:
    """Return the horizontal header for a QTableView, QTableWidget, or QTreeView."""
    if isinstance(table, QTableView):
        return table.horizontalHeader()
    return table.header()


def get_header_column_order(table: QTableView | QTreeView) -> list[str]:
    """Return canonical column header names in left-to-right visual order."""
    table_model = table.model()
    horizontal_header = _get_horizontal_header(table)
    if not table_model or not horizontal_header:
        return []
    column_count = table_model.columnCount()
    order: list[str] = []
    for visual_index in range(horizontal_header.count()):
        logical_index = horizontal_header.logicalIndex(visual_index)
        if 0 <= logical_index < column_count:
            label = _get_canonical_header_label(table_model, logical_index)
            if label:
                order.append(label)
    return order


def is_default_column_order(table: QTableView | QTreeView) -> bool:
    """Return `True` if every horizontal header section sits at its default logical visual index."""
    horizontal_header = _get_horizontal_header(table)
    if not horizontal_header:
        return True
    return all(horizontal_header.logicalIndex(visual_index) == visual_index for visual_index in range(horizontal_header.count()))


def merge_column_order(previous_order: Sequence[str] | None, current_order: Sequence[str]) -> list[str]:
    """Merge *current_order* of active columns with any hidden columns remembered from *previous_order*."""
    merged = list(dict.fromkeys(current_order))
    if previous_order is None or not previous_order:
        return merged

    deduped_previous = list(dict.fromkeys(previous_order))
    active_set = set(merged)
    for index, column_name in enumerate(deduped_previous):
        if column_name in active_set:
            continue
        insert_position = 0
        for preceding_index in range(index - 1, -1, -1):
            preceding_name = deduped_previous[preceding_index]
            if preceding_name in merged:
                insert_position = merged.index(preceding_name) + 1
                break
        merged.insert(insert_position, column_name)
    return merged


def apply_header_column_order(table: QTableView | QTreeView, column_order: Sequence[str]) -> bool:
    """Reorder horizontal header sections of *table* to match canonical names in *column_order*.

    Callers should guard their own `sectionMoved` slot with a programmatic flag rather than
    blocking header signals, because Qt views listen to `sectionMoved` internally to repaint.
    """
    table_model = table.model()
    horizontal_header = _get_horizontal_header(table)
    if not table_model or not horizontal_header or not column_order:
        return False

    section_count = min(horizontal_header.count(), table_model.columnCount())
    if section_count <= 1:
        return False

    label_to_logical: dict[str, int] = {}
    for logical_index in range(section_count):
        label = _get_canonical_header_label(table_model, logical_index)
        if label and label not in label_to_logical:
            label_to_logical[label] = logical_index

    target_logical_order: list[int] = []
    seen_logical: set[int] = set()
    for column_name in column_order:
        matched_logical = label_to_logical.get(column_name)
        if matched_logical is not None and matched_logical not in seen_logical:
            target_logical_order.append(matched_logical)
            seen_logical.add(matched_logical)

    if not target_logical_order:
        return False

    for logical_index in range(section_count):
        if logical_index in seen_logical:
            continue
        if not logical_index:
            target_logical_order.insert(0, 0)
        else:
            previous_position = target_logical_order.index(logical_index - 1)
            target_logical_order.insert(previous_position + 1, logical_index)
        seen_logical.add(logical_index)

    for target_visual, logical_index in enumerate(target_logical_order):
        current_visual = horizontal_header.visualIndex(logical_index)
        if current_visual != target_visual:
            horizontal_header.moveSection(current_visual, target_visual)
    return True


def reset_header_column_order(table: QTableView | QTreeView) -> None:
    """Restore every horizontal header section in *table* to its default logical order."""
    horizontal_header = _get_horizontal_header(table)
    if not horizontal_header:
        return
    for target_visual in range(horizontal_header.count()):
        current_visual = horizontal_header.visualIndex(target_visual)
        if current_visual != target_visual:
            horizontal_header.moveSection(current_visual, target_visual)


def get_column_min_width(
    horizontal_header: QHeaderView,
    column_index: int,
    column_label: str,
    widths_map: dict[str, int],
) -> int:
    """Return the minimum allowed pixel width for *column_index*."""
    return max(
        scale_by_ui(widths_map.get(column_label, DEFAULT_MIN_COLUMN_WIDTH)),
        horizontal_header.sectionSizeFromContents(column_index).width(),
    )


def _distribute_deficit_to_preceding_columns(
    horizontal_header: QHeaderView,
    preceding_columns: list[tuple[int, str]],
    deficit: int,
    custom_widths: dict[str, int] | None,
) -> None:
    """Distribute *deficit* pixels across flexible (or immediately preceding) columns."""
    if not preceding_columns or deficit <= 0:
        return

    target_columns = [(col, label) for col, label in preceding_columns if label in FLEXIBLE_STRETCH_COLUMNS]
    if not target_columns:
        target_columns = [preceding_columns[-1]]

    total_weight = sum(FLEXIBLE_COLUMN_WEIGHTS.get(label, 1) for _, label in target_columns)
    if total_weight <= 0:
        total_weight = len(target_columns)

    allocated = 0
    new_widths: dict[int, int] = {col: horizontal_header.sectionSize(col) for col, _ in target_columns}
    for col, label in target_columns:
        weight = FLEXIBLE_COLUMN_WEIGHTS.get(label, 1)
        share = (deficit * weight) // total_weight
        new_widths[col] += share
        allocated += share

    remainder = deficit - allocated
    if remainder > 0:
        top_column = max(target_columns, key=lambda item: FLEXIBLE_COLUMN_WEIGHTS.get(item[1], 1))[0]
        new_widths[top_column] += remainder

    for col, label in target_columns:
        width = new_widths[col]
        horizontal_header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
        if horizontal_header.sectionSize(col) != width:
            horizontal_header.resizeSection(col, width)
        if custom_widths is not None and label:
            custom_widths[label] = width


def _reclaim_overflow_from_preceding_columns(
    horizontal_header: QHeaderView,
    preceding_columns: list[tuple[int, str]],
    overflow: int,
    widths_map: dict[str, int],
    custom_widths: dict[str, int] | None,
) -> None:
    """Reclaim up to *overflow* pixels from preceding columns sitting above their minimum widths."""
    if not preceding_columns or overflow <= 0:
        return

    flexible_candidates = [(col, label) for col, label in preceding_columns if label in FLEXIBLE_STRETCH_COLUMNS]
    other_candidates = [(col, label) for col, label in reversed(preceding_columns) if label not in FLEXIBLE_STRETCH_COLUMNS]
    remaining_overflow = overflow

    for col, label in (*flexible_candidates, *other_candidates):
        if remaining_overflow <= 0:
            break
        current_width = horizontal_header.sectionSize(col)
        min_width = get_column_min_width(horizontal_header, col, label, widths_map)
        if current_width > min_width:
            reclaimed = min(current_width - min_width, remaining_overflow)
            new_width = current_width - reclaimed
            horizontal_header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
            horizontal_header.resizeSection(col, new_width)
            if custom_widths is not None and label:
                custom_widths[label] = new_width
            remaining_overflow -= reclaimed


def adjust_last_visible_column_to_viewport(
    table: QTableView | QTreeView,
    *,
    resized_column: int | None = None,
    min_column_widths: dict[str, int] | None = None,
    custom_widths: dict[str, int] | None = None,
    preserve_custom_widths: bool = False,
) -> None:
    """Adjust the last visible column so the table stays flush with the viewport right edge when columns are resized."""
    table_model = table.model()
    horizontal_header = _get_horizontal_header(table)
    if not table_model or not horizontal_header:
        return

    viewport = table.viewport()
    viewport_width = viewport.width() if viewport and viewport.width() > _MINIMUM_VIEWPORT_WIDTH_THRESHOLD else table.width()
    if viewport_width <= 0:
        return

    visible_logical_columns: list[int] = []
    for visual_index in range(horizontal_header.count()):
        logical_index = horizontal_header.logicalIndex(visual_index)
        if logical_index >= 0 and not horizontal_header.isSectionHidden(logical_index):
            visible_logical_columns.append(logical_index)

    if not visible_logical_columns:
        return

    last_column = visible_logical_columns[-1]
    last_label = _get_canonical_header_label(table_model, last_column)
    widths_map = min_column_widths or {}
    last_min_width = get_column_min_width(horizontal_header, last_column, last_label, widths_map)

    preceding_columns = [
        (column, _get_canonical_header_label(table_model, column))
        for column in visible_logical_columns[:-1]
    ]
    other_widths = sum(horizontal_header.sectionSize(column) for column, _ in preceding_columns)
    current_last_width = horizontal_header.sectionSize(last_column)

    if preserve_custom_widths and custom_widths is not None:
        saved_last_width = custom_widths.get(last_label) if last_label else None
        base_last_width = max(last_min_width, saved_last_width) if saved_last_width is not None and saved_last_width > 0 else max(last_min_width, current_last_width)
        target_last_width = max(base_last_width, viewport_width - other_widths)
        if target_last_width != current_last_width:
            horizontal_header.setSectionResizeMode(last_column, QHeaderView.ResizeMode.Interactive)
            horizontal_header.resizeSection(last_column, target_last_width)
        return

    if resized_column == last_column:
        target_last_width = max(last_min_width, current_last_width)
        if target_last_width != current_last_width:
            horizontal_header.setSectionResizeMode(last_column, QHeaderView.ResizeMode.Interactive)
            horizontal_header.resizeSection(last_column, target_last_width)
            current_last_width = target_last_width

        if other_widths + current_last_width < viewport_width:
            _distribute_deficit_to_preceding_columns(
                horizontal_header,
                preceding_columns,
                viewport_width - (other_widths + current_last_width),
                custom_widths,
            )
        elif not horizontal_header.offset() and other_widths + current_last_width > viewport_width:
            _reclaim_overflow_from_preceding_columns(
                horizontal_header,
                preceding_columns,
                (other_widths + current_last_width) - viewport_width,
                widths_map,
                custom_widths,
            )
    else:
        ideal_last_width = max(last_min_width, viewport_width - other_widths)
        target_last_width = current_last_width
        if other_widths + current_last_width < viewport_width or (
            other_widths + current_last_width > viewport_width and current_last_width > ideal_last_width
        ):
            target_last_width = ideal_last_width

        if target_last_width != current_last_width:
            horizontal_header.setSectionResizeMode(last_column, QHeaderView.ResizeMode.Interactive)
            horizontal_header.resizeSection(last_column, target_last_width)

    if custom_widths is not None and last_label:
        custom_widths[last_label] = horizontal_header.sectionSize(last_column)


def size_column_to_fit(
    table: QTableView | QTreeView,
    column_index: int,
    *,
    min_column_widths: dict[str, int] | None = None,
) -> None:
    """Resize a single column to fit its contents (header label and cell values)."""
    table_model = table.model()
    if not table_model:
        return

    if not 0 <= column_index < table_model.columnCount():
        return

    horizontal_header = _get_horizontal_header(table)
    if not horizontal_header:
        return

    horizontal_header.setSectionResizeMode(column_index, QHeaderView.ResizeMode.Interactive)
    table.resizeColumnToContents(column_index)
    if min_column_widths is not None:
        header_label = _get_canonical_header_label(table_model, column_index)
        min_width = get_column_min_width(horizontal_header, column_index, header_label, min_column_widths)
        if horizontal_header.sectionSize(column_index) < min_width:
            horizontal_header.resizeSection(column_index, min_width)
    adjust_last_visible_column_to_viewport(table, resized_column=column_index, min_column_widths=min_column_widths)


def size_all_columns_to_fit(
    table: QTableView | QTreeView,
    *,
    min_column_widths: dict[str, int] | None = None,
) -> None:
    """Resize all visible columns in *table* to fit their contents."""
    table_model = table.model()
    horizontal_header = _get_horizontal_header(table)
    if not table_model or not horizontal_header:
        return

    column_count = table_model.columnCount()
    for visual_index in range(horizontal_header.count()):
        column_index = horizontal_header.logicalIndex(visual_index)
        if 0 <= column_index < column_count and not horizontal_header.isSectionHidden(column_index):
            horizontal_header.setSectionResizeMode(column_index, QHeaderView.ResizeMode.Interactive)
            table.resizeColumnToContents(column_index)
            if min_column_widths is not None:
                header_label = _get_canonical_header_label(table_model, column_index)
                min_width = get_column_min_width(horizontal_header, column_index, header_label, min_column_widths)
                if horizontal_header.sectionSize(column_index) < min_width:
                    horizontal_header.resizeSection(column_index, min_width)
    adjust_last_visible_column_to_viewport(table, min_column_widths=min_column_widths)


def add_column_sizing_actions(
    menu: QMenu,
    table: QTableView | QTreeView,
    *,
    clicked_column: int | None = None,
    callbacks: ColumnSizingMenuCallbacks | None = None,
) -> None:
    """Add standardized column sizing and optional reset actions to *menu*."""
    resolved = callbacks if callbacks is not None else ColumnSizingMenuCallbacks()
    table_model = table.model()
    clicked_column_name: str | None = None
    is_valid_clicked_column = False

    if clicked_column is not None and table_model and 0 <= clicked_column < table_model.columnCount():
        is_valid_clicked_column = True
        header_value = table_model.headerData(clicked_column, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole)
        if isinstance(header_value, str) and header_value:
            clicked_column_name = header_value

    size_column_tooltip = (
        tr(
            "Resize the '{column}' column so all text is fully visible without truncation or ellipses.",
            column=clicked_column_name,
        )
        if bool(clicked_column_name)
        else tr('Resize the selected column so all text is fully visible without truncation or ellipses.')
    )
    size_column_cb: Callable[[], None] | None = None
    if is_valid_clicked_column and clicked_column is not None:
        target_column = clicked_column

        def _size_clicked() -> None:
            if resolved.on_fit_column is not None:
                resolved.on_fit_column(target_column)
            else:
                size_column_to_fit(table, target_column)

        size_column_cb = _size_clicked
    size_column_action = add_icon_menu_action(menu, 'move-horizontal.svg', tr('Size Column to Fit'), size_column_cb, tooltip=size_column_tooltip)
    size_column_action.setEnabled(is_valid_clicked_column)

    add_icon_menu_action(
        menu,
        'move-vertical.svg',
        tr('Size All Columns to Fit'),
        resolved.on_fit_all if resolved.on_fit_all is not None else lambda: size_all_columns_to_fit(table),
        tooltip=tr('Resize all visible columns so that any truncated text across the entire table is fully visible without ellipses.'),
    )

    if resolved.on_reset is not None:
        add_icon_menu_action(
            menu,
            'refresh-cw.svg',
            tr('Reset Column Sizes'),
            resolved.on_reset,
            tooltip=tr('Reset all column widths back to their initial default layout.'),
        )

    if resolved.on_reset_order is not None:
        add_icon_menu_action(
            menu,
            'rotate-ccw.svg',
            tr('Reset Column Order'),
            resolved.on_reset_order,
            tooltip=tr('Reset all columns back to their initial default order.'),
        )


def setup_table_header_context_menu(
    table: QTableView | QTreeView,
    *,
    on_reset: Callable[[], None] | None = None,
    callbacks: ColumnSizingMenuCallbacks | None = None,
) -> None:
    """Configure the horizontal header of *table* with a standardized right-click context menu for column sizing."""
    horizontal_header = _get_horizontal_header(table)
    if not horizontal_header:
        message = 'Failed to get horizontal header from table'
        raise RuntimeError(message)

    resolved_callbacks = callbacks if callbacks is not None else ColumnSizingMenuCallbacks(on_reset=on_reset)
    horizontal_header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

    def _on_header_context_menu_requested(position: QPoint) -> None:
        clicked_column = horizontal_header.logicalIndexAt(position)
        menu = create_styled_context_menu(table)
        add_column_sizing_actions(menu, table, clicked_column=clicked_column, callbacks=resolved_callbacks)
        menu.popup(horizontal_header.mapToGlobal(position))

    horizontal_header.customContextMenuRequested.connect(_on_header_context_menu_requested)


def setup_static_table_column_resizing(
    table: QTableView,
    *,
    custom_widths: dict[str, int] | None = None,
    min_column_widths: dict[str, int] | None = None,
    max_column_widths: dict[str, int] | None = None,
) -> None:
    """Set up column sizing for a table, fitting columns and distributing extra space to flexible columns."""
    table_model = table.model()
    if not table_model:
        return

    horizontal_header = table.horizontalHeader()
    if not horizontal_header:
        return

    viewport = table.viewport()
    viewport_width = viewport.width() if viewport and viewport.width() > _MINIMUM_VIEWPORT_WIDTH_THRESHOLD else table.width()
    if viewport_width <= 0:
        return

    font_metrics = table.fontMetrics()
    header_font_metrics = horizontal_header.fontMetrics()
    header_sort_padding = scale_by_ui(28)
    cell_padding = scale_by_ui(32)
    row_count = table_model.rowCount()
    widths_map = min_column_widths or {}
    max_bounds_map = max_column_widths or {}

    is_sort_active = horizontal_header.isSortIndicatorShown()
    sorted_column_index = horizontal_header.sortIndicatorSection() if is_sort_active else -1

    visible_columns: list[tuple[int, str, int, int]] = []
    min_bounds: dict[int, int] = {}
    column_count = table_model.columnCount()
    for visual_index in range(horizontal_header.count()):
        column = horizontal_header.logicalIndex(visual_index)
        if column < 0 or column >= column_count or horizontal_header.isSectionHidden(column):
            continue
        header_key = _get_canonical_header_label(table_model, column)
        display_label = str(table_model.headerData(column, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole) or '')
        sort_padding = header_sort_padding if column == sorted_column_index else 0
        header_needed = max(
            header_font_metrics.horizontalAdvance(display_label) + sort_padding,
            horizontal_header.sectionSizeFromContents(column).width(),
        )
        min_width = max(scale_by_ui(widths_map.get(header_key, DEFAULT_MIN_COLUMN_WIDTH)), header_needed)
        min_bounds[column] = min_width
        custom_width = custom_widths.get(header_key) if custom_widths is not None else None
        floor_width = max(min_width, custom_width) if custom_width is not None else min_width

        needed_width = min_width

        sample_rows = min(row_count, 100)
        for row in range(sample_rows):
            index = table_model.index(row, column)
            text = table_model.data(index, Qt.ItemDataRole.DisplayRole)
            text_str = str(text) if text is not None and not isinstance(text, bool) else ''
            text_width = font_metrics.horizontalAdvance(text_str) if text_str else 0
            icon = table_model.data(index, Qt.ItemDataRole.DecorationRole)
            icon_offset = 0
            if isinstance(icon, QIcon):
                icon_width = icon.actualSize(QSize(100, _STANDARD_ICON_SIZE)).width()
                icon_offset = icon_width + scale_by_ui(6)
            elif icon is not None:
                icon_offset = scale_by_ui(22)
            cell_needed = text_width + icon_offset + cell_padding
            needed_width = max(needed_width, cell_needed)

        max_bound = scale_by_ui(max_bounds_map[header_key]) if header_key in max_bounds_map else None
        if max_bound is not None:
            needed_width = min(needed_width, max(floor_width, max_bound))

        visible_columns.append((column, header_key, floor_width, needed_width))

    if not visible_columns:
        return

    final_widths: dict[int, int] = {column_index: floor_width for column_index, _, floor_width, _ in visible_columns}
    total_allocated = sum(final_widths.values())
    surplus = viewport_width - total_allocated

    # Detect truncated columns: columns whose needed content width exceeds currently allocated floor width
    truncated_columns: dict[int, int] = {}
    for column_index, header_key, floor_width, needed_width in visible_columns:
        if custom_widths is not None and header_key in custom_widths:
            continue
        if needed_width > floor_width:
            truncated_columns[column_index] = needed_width - floor_width

    total_deficit = sum(truncated_columns.values())

    # If there is a deficit and surplus is insufficient, reclaim excess width from columns sitting above their needed width
    if total_deficit > 0 and surplus < total_deficit:
        deficit_to_cover = total_deficit - max(0, surplus)
        for column_index, header_key, _, needed_width in visible_columns:
            if custom_widths is not None and header_key in custom_widths:
                continue
            if deficit_to_cover <= 0:
                break
            reclaim_limit = max(min_bounds[column_index], needed_width)
            if final_widths[column_index] > reclaim_limit:
                available_to_reclaim = final_widths[column_index] - reclaim_limit
                reclaimed_amount = min(available_to_reclaim, deficit_to_cover)
                final_widths[column_index] -= reclaimed_amount
                surplus += reclaimed_amount
                deficit_to_cover -= reclaimed_amount

    # Allocate surplus to truncated columns to eliminate or reduce text clipping
    if surplus > 0 and total_deficit > 0:
        if surplus >= total_deficit:
            for column_index, deficit in truncated_columns.items():
                final_widths[column_index] += deficit
            surplus -= total_deficit
        else:
            allocated = 0
            for column_index, deficit in truncated_columns.items():
                share = (surplus * deficit) // total_deficit
                final_widths[column_index] += share
                allocated += share
            remainder = surplus - allocated
            if remainder > 0:
                top_column = max(truncated_columns, key=lambda col_idx: truncated_columns[col_idx])
                final_widths[top_column] += remainder
            surplus = 0

    # Distribute any remaining surplus across flexible stretch columns to fill the table to the right edge
    if surplus > 0:
        flexible_columns = [
            (column_index, label)
            for column_index, label, _, _ in visible_columns
            if label in FLEXIBLE_STRETCH_COLUMNS and (custom_widths is None or label not in custom_widths)
        ]
        if not flexible_columns:
            non_custom_visible = [(column_index, label) for column_index, label, _, _ in visible_columns if custom_widths is None or label not in custom_widths]
            if non_custom_visible:
                flexible_columns = [non_custom_visible[-1]]
            elif custom_widths is not None:
                flexible_columns = [(visible_columns[-1][0], visible_columns[-1][1])]
            else:
                flexible_columns = [(column_index, label) for column_index, label, _, _ in visible_columns if label in FLEXIBLE_STRETCH_COLUMNS]
                if not flexible_columns:
                    flexible_columns = [(visible_columns[-1][0], visible_columns[-1][1])]

        total_weight = sum(FLEXIBLE_COLUMN_WEIGHTS.get(label, 1) for _, label in flexible_columns)
        if total_weight <= 0:
            total_weight = len(flexible_columns)

        allocated = 0
        for column_index, label in flexible_columns:
            weight = FLEXIBLE_COLUMN_WEIGHTS.get(label, 1)
            share = (surplus * weight) // total_weight
            final_widths[column_index] += share
            allocated += share

        remainder = surplus - allocated
        if remainder > 0:
            top_column = max(flexible_columns, key=lambda item: FLEXIBLE_COLUMN_WEIGHTS.get(item[1], 1))[0]
            final_widths[top_column] += remainder

    for column, width in final_widths.items():
        horizontal_header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
        if horizontal_header.sectionSize(column) != width:
            horizontal_header.resizeSection(column, width)


class TableColumnLayoutController:
    """Tracks custom column widths and visual column order for movable, resizable tables."""

    def __init__(
        self,
        table: QTableView | QTreeView,
        *,
        min_column_widths: dict[str, int] | None = None,
        clamp_to_min: bool = True,
        on_after_move: Callable[[], None] | None = None,
    ) -> None:
        """Initialize column width and order tracking for *table*."""
        self._table = table
        self._min_column_widths = min_column_widths
        self._clamp_to_min = clamp_to_min
        self._on_after_move = on_after_move
        self.custom_widths: dict[str, int] | None = None
        self.custom_order: list[str] | None = None
        self._is_programmatic_resizing: bool = False
        self._is_programmatic_reordering: bool = False

    def set_on_after_move(self, callback: Callable[[], None] | None) -> None:
        """Set or replace the callback invoked after user-driven column reordering."""
        self._on_after_move = callback

    @contextmanager
    def programmatic_resize(self) -> Generator[None]:
        """Suppress `on_section_resized` tracking during programmatic section width updates."""
        previous_state = self._is_programmatic_resizing
        self._is_programmatic_resizing = True
        try:
            yield
        finally:
            self._is_programmatic_resizing = previous_state

    @contextmanager
    def programmatic_reorder(self) -> Generator[None]:
        """Suppress `on_section_moved` tracking during programmatic section moves."""
        previous_state = self._is_programmatic_reordering
        self._is_programmatic_reordering = True
        try:
            yield
        finally:
            self._is_programmatic_reordering = previous_state

    def on_section_resized(self, logical_index: int, _old_size: int, new_size: int) -> None:
        """Track user-driven column resizing while keeping the rightmost column flush with the viewport."""
        if self._is_programmatic_resizing:
            return
        table_model = self._table.model()
        horizontal_header = _get_horizontal_header(self._table)
        if not table_model or not horizontal_header:
            return
        header_label = _get_canonical_header_label(table_model, logical_index)
        if not header_label:
            return
        if self.custom_widths is None:
            self.custom_widths = self.get_column_widths()
        with self.programmatic_resize():
            effective_size = new_size
            if self._clamp_to_min:
                min_width = get_column_min_width(horizontal_header, logical_index, header_label, self._min_column_widths or {})
                if new_size < min_width:
                    horizontal_header.resizeSection(logical_index, min_width)
                    effective_size = min_width
            self.custom_widths[header_label] = effective_size
            adjust_last_visible_column_to_viewport(
                self._table,
                resized_column=logical_index,
                min_column_widths=self._min_column_widths,
                custom_widths=self.custom_widths,
            )

    def on_section_moved(self, _logical_index: int, _old_visual_index: int, _new_visual_index: int) -> None:
        """Track user-driven column reordering across active and remembered columns."""
        if self._is_programmatic_reordering:
            return
        current_order = get_header_column_order(self._table)
        if not current_order:
            return
        if self.custom_order is None and is_default_column_order(self._table):
            return
        merged = merge_column_order(self.custom_order, current_order)
        if len(merged) == len(current_order) and is_default_column_order(self._table):
            self.custom_order = None
        else:
            self.custom_order = merged
        if self.custom_widths is not None and self._on_after_move is not None:
            self._on_after_move()

    def get_column_widths(self) -> dict[str, int]:
        """Return visible column widths by canonical name while preserving widths for hidden columns."""
        widths = dict(self.custom_widths) if self.custom_widths is not None else {}
        table_model = self._table.model()
        horizontal_header = _get_horizontal_header(self._table)
        if not table_model or not horizontal_header:
            return widths
        for column_index in range(table_model.columnCount()):
            if horizontal_header.isSectionHidden(column_index):
                continue
            width = horizontal_header.sectionSize(column_index)
            if width > 0 and (header_label := _get_canonical_header_label(table_model, column_index)):
                widths[header_label] = width
        return widths

    def get_persisted_widths(self) -> dict[str, int] | None:
        """Return custom widths to persist, or `None` when using automatic/default sizing."""
        return dict(self.custom_widths) if self.custom_widths is not None else None

    def get_persisted_order(self) -> list[str] | None:
        """Return custom visual column order to persist, or `None` when using default order."""
        return list(self.custom_order) if self.custom_order is not None else None

    def apply_column_widths(self, widths: dict[str, int]) -> None:
        """Apply saved column widths to matching visible header sections."""
        table_model = self._table.model()
        horizontal_header = _get_horizontal_header(self._table)
        if not table_model or not horizontal_header:
            return
        with self.programmatic_resize():
            for column_index in range(table_model.columnCount()):
                if horizontal_header.isSectionHidden(column_index):
                    continue
                header_label = _get_canonical_header_label(table_model, column_index)
                if header_label in widths and widths[header_label] > 0:
                    target_width = widths[header_label]
                    if self._clamp_to_min:
                        min_width = get_column_min_width(horizontal_header, column_index, header_label, self._min_column_widths or {})
                        target_width = max(min_width, target_width)
                    horizontal_header.setSectionResizeMode(column_index, QHeaderView.ResizeMode.Interactive)
                    horizontal_header.resizeSection(column_index, target_width)
            self.custom_widths = dict(widths)

    def apply_column_order(self, column_order: Sequence[str], *, preserve_hidden: bool = False) -> None:
        """Apply saved visual column order to matching header sections."""
        if not column_order:
            return
        with self.programmatic_reorder():
            apply_header_column_order(self._table, column_order)
            if preserve_hidden:
                self.custom_order = list(column_order)
            else:
                self.custom_order = None if is_default_column_order(self._table) else list(column_order)

    def reapply_column_order(self) -> None:
        """Reset stale Qt section mappings after model header changes and re-apply any custom order."""
        with self.programmatic_reorder():
            reset_header_column_order(self._table)
            if self.custom_order is not None:
                apply_header_column_order(self._table, self.custom_order)

    def reset_column_order(self) -> None:
        """Restore default logical column order and clear tracked custom order."""
        self.custom_order = None
        with self.programmatic_reorder():
            reset_header_column_order(self._table)

    def bind_header(self) -> None:
        """Configure interactive movable header behavior and connect resize/move tracking signals."""
        horizontal_header = _get_horizontal_header(self._table)
        if not horizontal_header:
            return
        horizontal_header.setStretchLastSection(False)
        horizontal_header.setSectionsMovable(True)
        horizontal_header.setMinimumSectionSize(scale_by_ui(DEFAULT_MIN_COLUMN_WIDTH))
        horizontal_header.sectionResized.connect(self.on_section_resized)
        horizontal_header.sectionMoved.connect(self.on_section_moved)

    def setup_column_resizing(self) -> None:
        """Apply smart viewport-aware column sizing to a `QTableView` while honoring custom widths."""
        if not isinstance(self._table, QTableView):
            return
        with self.programmatic_resize():
            setup_static_table_column_resizing(
                self._table,
                custom_widths=self.custom_widths,
                min_column_widths=self._min_column_widths,
            )

    def reset_column_sizes(self) -> None:
        """Clear custom widths and reapply automatic default column sizing."""
        self.custom_widths = None
        self.setup_column_resizing()

    def size_column_to_fit(self, column_index: int) -> None:
        """Fit *column_index* to its contents and record resulting custom widths."""
        with self.programmatic_resize():
            size_column_to_fit(self._table, column_index, min_column_widths=self._min_column_widths)
            self.custom_widths = self.get_column_widths()

    def size_all_columns_to_fit(self) -> None:
        """Fit all visible columns to their contents and record resulting custom widths."""
        with self.programmatic_resize():
            size_all_columns_to_fit(self._table, min_column_widths=self._min_column_widths)
            self.custom_widths = self.get_column_widths()

    def menu_callbacks(
        self,
        *,
        on_reset: Callable[[], None],
        on_reset_order: Callable[[], None],
    ) -> ColumnSizingMenuCallbacks:
        """Build a `ColumnSizingMenuCallbacks` bundle wired to this controller's fit actions."""
        return ColumnSizingMenuCallbacks(
            on_reset=on_reset,
            on_reset_order=on_reset_order,
            on_fit_column=self.size_column_to_fit,
            on_fit_all=self.size_all_columns_to_fit,
        )
