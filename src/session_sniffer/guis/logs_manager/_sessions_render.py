"""Caching, search matching, table formatting, and safe file deletion helpers for `SessionsLogTab`."""

import logging
import os
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

from pydantic import ValidationError

from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.constants.tables import DATETIME_TRACKING_COLUMNS, SEARCHABLE_COLUMN_EXCLUSIONS
from session_sniffer.i18n import tr
from session_sniffer.models import SessionLogFile
from session_sniffer.settings import Settings
from session_sniffer.text_utils import format_single_border_table

if TYPE_CHECKING:
    import threading
    from typing import Any

logger = logging.getLogger(__name__)

SEARCH_ALL = 'All Searchable Columns'


def _build_searchable_columns() -> tuple[str, ...]:
    columns: list[str] = []
    seen: set[str] = set()
    for source_columns in (Settings.GUI_ALL_CONNECTED_COLUMNS, Settings.GUI_ALL_DISCONNECTED_COLUMNS):
        for column in source_columns:
            if column not in SEARCHABLE_COLUMN_EXCLUSIONS and column not in seen:
                seen.add(column)
                columns.append(column)
    return (SEARCH_ALL, *columns)


SEARCHABLE_COLUMNS: tuple[str, ...] = _build_searchable_columns()


@dataclass(frozen=True, slots=True)
class SessionTableRenderConfig:
    """Column sort and title configuration for a rendered session player table."""

    title: str
    sort_column: str
    descending: bool


@dataclass(frozen=True, slots=True)
class CachedPlayerSearchEntry:
    """Pre-normalized searchable fields for a single player entry in a session log."""

    section_name: str
    ip: str
    fields: dict[str, str]
    fields_lower: dict[str, str]
    all_fields_lower: str
    fallback_all_text_lower: str
    non_empty_columns: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CachedTableRow:
    """Parsed table row line from a rendered session log for fast column-scoped search."""

    line_num: int
    line: str
    parsed_cells: list[str]
    cells_by_col_lower: dict[str, str]
    all_cells_lower: str
    has_headers: bool


@dataclass(slots=True)
class CachedSessionFile:
    """Cached parsed and lazily rendered representation of a session `.json` file."""

    mtime_ns: int
    size: int
    session_log: SessionLogFile
    player_entries: tuple[CachedPlayerSearchEntry, ...]
    combined_haystack_lower: str
    rendered_text: str | None = None
    line_number_width: int = 0
    table_rows: tuple[CachedTableRow, ...] | None = None


def collect_session_json_files(directory: Path) -> list[tuple[Path, int, int]]:
    """Return sorted `(file_path, mtime_ns, size)` tuples for all `.json` files under *directory*."""
    if not directory.is_dir():
        return []
    collected: list[tuple[Path, int, int]] = []
    stack = [str(directory)]
    while stack:
        try:
            with os.scandir(stack.pop()) as it:
                for entry in it:
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    elif entry.name.endswith('.json') and entry.is_file(follow_symlinks=False):
                        st = entry.stat(follow_symlinks=False)
                        collected.append((Path(entry.path), st.st_mtime_ns, st.st_size))
        except OSError:
            continue
    collected.sort(key=lambda item: item[0])
    return collected


def count_json_files_and_size(directory: Path) -> tuple[int, int]:
    """Return `(total_bytes, file_count)` for all `.json` files under *directory*."""
    files = collect_session_json_files(directory)
    return sum(size for _, _, size in files), len(files)


def normalize_fs_path(path: Path) -> str:
    """Return a case-normalized absolute path string for safe cross-platform path comparisons."""
    return os.path.normcase(str(path.resolve()))


def prune_nested_paths(paths: list[Path]) -> list[Path]:
    """Remove any path in *paths* whose ancestor directory is also present in *paths*."""
    dir_norms = {normalize_fs_path(path) for path in paths if path.is_dir()}
    if not dir_norms:
        return list(paths)
    return [
        path
        for path in paths
        if not any(normalize_fs_path(parent) in dir_norms for parent in path.parents)
    ]


def _try_rmdir(directory: Path) -> int:
    try:
        directory.rmdir()
    except OSError:
        return 0
    return 1


def _delete_dir_preserving_active(target: Path, protected_norm: str) -> tuple[int, int, bool]:
    """Delete all files and empty subdirectories under *target* except *protected_norm*."""
    files_deleted = 0
    folders_deleted = 0
    skipped_active = False
    for root, dirs, files in os.walk(target, topdown=False):
        root_path = Path(root)
        for filename in files:
            candidate = root_path / filename
            if normalize_fs_path(candidate) == protected_norm:
                skipped_active = True
                continue
            try:
                candidate.unlink()
            except OSError:
                continue
            if filename.endswith('.json'):
                files_deleted += 1
        for dirname in dirs:
            folders_deleted += _try_rmdir(root_path / dirname)
    folders_deleted += _try_rmdir(target)
    return files_deleted, folders_deleted, skipped_active


def delete_session_paths(paths: list[Path], *, protected_active_file: Path | None) -> tuple[int, int, bool]:
    """Delete *paths* (files and folders) while preserving *protected_active_file* if encountered.

    Returns `(files_deleted, folders_deleted, skipped_active_file)`.
    """
    top_paths = prune_nested_paths(paths)
    protected_norm = normalize_fs_path(protected_active_file) if protected_active_file is not None else None
    files_deleted = 0
    folders_deleted = 0
    skipped_active = False

    for target in top_paths:
        if not target.exists():
            continue
        target_norm = normalize_fs_path(target)
        if target.is_file():
            if protected_norm is not None and target_norm == protected_norm:
                skipped_active = True
                continue
            target.unlink(missing_ok=True)
            files_deleted += 1
            continue

        if target.is_dir():
            if protected_norm is not None and (protected_norm == target_norm or protected_norm.startswith(target_norm + os.sep)):
                f_del, d_del, skipped = _delete_dir_preserving_active(target, protected_norm)
                files_deleted += f_del
                folders_deleted += d_del
                skipped_active = skipped_active or skipped
            else:
                _, nested_json_count = count_json_files_and_size(target)
                shutil.rmtree(target)
                files_deleted += nested_json_count
                folders_deleted += 1

    return files_deleted, folders_deleted, skipped_active


def _normalize_search_value(value: object) -> str:
    if isinstance(value, list):
        return ', '.join(str(item) for item in cast('list[object]', value))
    if value is None:
        return ''
    text = str(value)
    return '' if text in {'N/A', '...'} else text


def _get_column_snapshot(player_info: dict[str, Any]) -> dict[str, Any]:
    columns_raw = player_info.get('columns')
    return cast('dict[str, Any]', columns_raw) if isinstance(columns_raw, dict) else player_info


def _build_player_search_fields(ip: str, info: dict[str, Any]) -> dict[str, str]:
    columns = _get_column_snapshot(info)
    return {
        column: ip if column == 'IP Address' else _normalize_search_value(columns.get(column, info.get(column)))
        for column in SEARCHABLE_COLUMNS[1:]
    }


def _iter_json_text_values(value: object) -> list[str]:
    if isinstance(value, dict):
        return [
            text
            for k, v in cast('dict[object, object]', value).items()
            if k not in SEARCHABLE_COLUMN_EXCLUSIONS
            for text in _iter_json_text_values(v)
        ]
    if isinstance(value, list):
        return [text for item in cast('list[object]', value) for text in _iter_json_text_values(item)]
    return [normalized] if (normalized := _normalize_search_value(value)) else []


def build_cached_session_file(file_path: Path, mtime_ns: int, size: int) -> CachedSessionFile | None:
    """Parse *file_path* into a `CachedSessionFile` with pre-indexed player search entries."""
    try:
        session_log = SessionLogFile.model_validate_json(file_path.read_text(encoding='utf-8', errors='replace'))
    except (OSError, ValidationError) as e:
        logger.warning('Failed to load session log from %s: %s', file_path, e)
        return None

    player_entries: list[CachedPlayerSearchEntry] = []
    haystack_parts: list[str] = []
    for section_name, players in (('connected', session_log.connected), ('disconnected', session_log.disconnected)):
        for ip, info in players.items():
            fields = _build_player_search_fields(ip, info)
            fields_lower = {column: value.lower() for column, value in fields.items()}
            all_fields_lower = '\x00'.join(fields_lower.values())
            fallback_all_text_lower = ' '.join((ip, *_iter_json_text_values(info))).lower()
            non_empty_columns = tuple(column for column, value in fields.items() if value)
            haystack_parts.extend((all_fields_lower, fallback_all_text_lower))
            player_entries.append(
                CachedPlayerSearchEntry(section_name, ip, fields, fields_lower, all_fields_lower, fallback_all_text_lower, non_empty_columns),
            )
    return CachedSessionFile(mtime_ns, size, session_log, tuple(player_entries), '\x00'.join(haystack_parts))


def collect_structured_matches_from_cached(cached: CachedSessionFile, search_lower: str, selected_column: str) -> list[str]:
    """Return formatted player field matches from *cached* for *search_lower* and *selected_column*."""
    if search_lower not in cached.combined_haystack_lower:
        return []
    matches: list[str] = []
    is_search_all = selected_column == SEARCH_ALL
    for entry in cached.player_entries:
        if is_search_all:
            if search_lower in entry.all_fields_lower:
                matched_columns = [column for column, val_lower in entry.fields_lower.items() if search_lower in val_lower]
            else:
                matched_columns = list(entry.non_empty_columns) if search_lower in entry.fallback_all_text_lower else []
        else:
            matched_columns = [selected_column] if search_lower in entry.fields_lower.get(selected_column, '') else []
        if matched_columns:
            section_label = tr('connected') if entry.section_name == 'connected' else tr('disconnected')
            fields_summary = ', '.join(f'{tr(column)}: {entry.fields[column]}' for column in matched_columns)
            matches.append(f'  [{section_label}] {entry.ip}  |  {fields_summary}')
    return matches


def _try_parse_table_row(line: str) -> list[str] | None:
    stripped = line.strip()
    if not (stripped.startswith('│') and stripped.endswith('│')):
        return None
    raw_cells = stripped.split('│')[1:-1]
    return [cell.strip() for cell in raw_cells] if raw_cells else None


def _format_table_row(cells: list[str], column_widths: list[int]) -> str:
    padded = [cell.ljust(column_widths[i]) if i < len(column_widths) else cell for i, cell in enumerate(cells)]
    return f'│ {" │ ".join(padded)} │'


def _build_effective_column_widths(base_widths: list[int], header_cells: list[str]) -> list[int]:
    effective_widths = list(base_widths)
    for i, header_cell in enumerate(header_cells):
        if i >= len(effective_widths):
            effective_widths.append(len(header_cell))
        else:
            effective_widths[i] = max(effective_widths[i], len(header_cell))
    return effective_widths


def _format_table_separator(column_widths: list[int], column_count: int) -> str:
    if column_count <= 0:
        return ''
    widths = [column_widths[i] if i < len(column_widths) else 0 for i in range(column_count)]
    return f'├─{"─┼─".join("─" * width for width in widths)}─┤'


def _column_headers_for_row_length(row_length: int) -> list[str] | None:
    if row_length == len(Settings.GUI_ALL_CONNECTED_COLUMNS):
        return list(Settings.GUI_ALL_CONNECTED_COLUMNS)
    if row_length == len(Settings.GUI_ALL_DISCONNECTED_COLUMNS):
        return list(Settings.GUI_ALL_DISCONNECTED_COLUMNS)
    return None


def _schema_label_for_row_length(row_length: int) -> str | None:
    if row_length == len(Settings.GUI_ALL_CONNECTED_COLUMNS):
        return tr('Connected Columns')
    if row_length == len(Settings.GUI_ALL_DISCONNECTED_COLUMNS):
        return tr('Disconnected Columns')
    return None


def render_aligned_line_matches(
    *,
    line_matches: list[tuple[int, str, list[str] | None]],
    line_number_width: int,
    column_widths_by_length: dict[int, list[int]],
) -> list[str]:
    """Format matched table lines with aligned columns and schema headers."""
    rendered_lines: list[str] = []
    active_row_length = -1
    active_column_widths: list[int] = []
    has_rendered_schema_header = False

    for line_num, line, parsed_cells in line_matches:
        rendered_line = line
        if parsed_cells is not None:
            row_length = len(parsed_cells)
            if row_length != active_row_length:
                if has_rendered_schema_header:
                    rendered_lines.append('')
                active_row_length = row_length
                active_column_widths = list(column_widths_by_length.get(row_length, []))
                if (header_cells := _column_headers_for_row_length(row_length)) is not None:
                    display_headers = [tr(h) for h in header_cells]
                    if (schema_label := _schema_label_for_row_length(row_length)) is not None:
                        rendered_lines.append(f'  {" " * line_number_width}  ── {schema_label} ──')
                    active_column_widths = _build_effective_column_widths(active_column_widths, display_headers)
                    rendered_lines.append(f'  {" " * line_number_width}  {_format_table_row(display_headers, active_column_widths)}')
                    rendered_lines.append(f'  {" " * line_number_width}  {_format_table_separator(active_column_widths, len(display_headers))}')
                    has_rendered_schema_header = True
            rendered_line = _format_table_row(parsed_cells, active_column_widths)
        rendered_lines.append(f'  {line_num:>{line_number_width}}: {rendered_line}')
    return rendered_lines


def _format_session_datetime(value: object) -> str:
    if not isinstance(value, str) or not value or value == 'N/A':
        return tr('N/A')
    try:
        return datetime.fromisoformat(value).strftime('%H:%M:%S.%f')[:-3]
    except ValueError:
        return value


def _format_table_value(value: object) -> str:
    if value is None or value == 'N/A':
        return tr('N/A')
    if isinstance(value, bool):
        return tr('Yes') if value else tr('No')
    return ', '.join(str(item) for item in cast('list[object]', value)) if isinstance(value, list) else str(value)


def _player_datetime_sort_key(player_info: dict[str, Any], sort_column: str) -> datetime:
    for candidate in (player_info.get(sort_column), _get_column_snapshot(player_info).get(sort_column)):
        if not isinstance(candidate, str) or not candidate:
            continue
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=LOCAL_TZ)
        except ValueError:
            try:
                return datetime.strptime(candidate, '%m/%d/%Y %H:%M:%S.%f').replace(tzinfo=LOCAL_TZ)
            except ValueError:
                continue
    return datetime.min.replace(tzinfo=LOCAL_TZ)


def _build_session_table(*, players: dict[str, dict[str, Any]], column_names: tuple[str, ...], config: SessionTableRenderConfig) -> str:
    headers = [
        f'{tr(col)} ↓' if col == config.sort_column and config.descending else f'{tr(col)} ↑' if col == config.sort_column else tr(col)
        for col in column_names
    ]
    sorted_players = sorted(players.items(), key=lambda item: _player_datetime_sort_key(item[1], config.sort_column), reverse=not config.descending)
    rows = [
        [
            _format_session_datetime(columns.get(col, info.get(col, 'N/A')))
            if col in DATETIME_TRACKING_COLUMNS
            else _format_table_value(columns.get(col, info.get(col, 'N/A')) if col != 'IP Address' else ip)
            for col in column_names
        ]
        for ip, info in sorted_players
        for columns in (_get_column_snapshot(info),)
    ]
    return format_single_border_table(headers, rows, title=config.title)


def _build_connected_table(players: dict[str, dict[str, Any]]) -> str:
    config = SessionTableRenderConfig(tr('Players connected in your session ({count}):', count=len(players)), 'Last Rejoin', descending=True)
    return _build_session_table(players=players, column_names=Settings.GUI_ALL_CONNECTED_COLUMNS, config=config)


def _build_disconnected_table(players: dict[str, dict[str, Any]]) -> str:
    config = SessionTableRenderConfig(tr("Players who've left your session ({count}):", count=len(players)), 'Last Seen', descending=False)
    return _build_session_table(players=players, column_names=Settings.GUI_ALL_DISCONNECTED_COLUMNS, config=config)


def ensure_cached_session_rendered(cached: CachedSessionFile, cache_lock: threading.Lock) -> tuple[str, int, tuple[CachedTableRow, ...]]:
    """Ensure *cached* has its rendered ASCII table text and parsed table rows populated."""
    if cached.rendered_text is not None and cached.table_rows is not None:
        return cached.rendered_text, cached.line_number_width, cached.table_rows
    rendered = f'{_build_connected_table(cached.session_log.connected)}\n{_build_disconnected_table(cached.session_log.disconnected)}'
    lines = rendered.splitlines()
    line_number_width = max(len(str(len(lines))), 1)
    na_display = tr('N/A')
    table_rows: list[CachedTableRow] = []
    for line_num, line in enumerate(lines, start=1):
        if (parsed_cells := _try_parse_table_row(line)) is None:
            continue
        header_cells = _column_headers_for_row_length(len(parsed_cells))
        if header_cells is not None and all(
            cell in (tr(h), f'{tr(h)} ↓', f'{tr(h)} ↑') for cell, h in zip(parsed_cells, header_cells, strict=True)
        ):
            continue
        if header_cells is None:
            cells_by_col_lower, all_cells_lower, has_headers = {}, line.lower(), False
        else:
            cells_by_col_lower = {
                col: cell.lower()
                for col, cell in zip(header_cells, parsed_cells, strict=False)
                if col not in SEARCHABLE_COLUMN_EXCLUSIONS and cell not in {'N/A', '...', na_display}
            }
            all_cells_lower, has_headers = '\x00'.join(cells_by_col_lower.values()), True
        table_rows.append(CachedTableRow(line_num, line, parsed_cells, cells_by_col_lower, all_cells_lower, has_headers))
    rows_tuple = tuple(table_rows)
    with cache_lock:
        cached.rendered_text, cached.line_number_width, cached.table_rows = rendered, line_number_width, rows_tuple
    return rendered, line_number_width, rows_tuple
