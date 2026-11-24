"""Multi-selection batch helpers for the UserIP Databases Manager file tree."""

import html
import logging
import shutil
import sys
import zipfile
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from pathlib import Path
from typing import TYPE_CHECKING, cast

from PySide6.QtCore import QModelIndex, QSignalBlocker, Qt, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QIcon
from PySide6.QtWidgets import QDialog, QFileDialog, QHBoxLayout, QMenu, QMessageBox, QPushButton, QTreeView, QTreeWidget, QWidget

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.loading_overlay import run_async_with_loading, run_blocking_with_loading
from session_sniffer.guis.looky_text import configure_looky_action
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET
from session_sniffer.guis.tables_player_actions import create_ping_menu, scan_ports_ip, show_detailed_ip_lookup
from session_sniffer.guis.theming import ICONS_DIR_PATH, themed_qss
from session_sniffer.guis.userip_manager_helpers import (
    load_userip_database_model,
    refresh_userip_and_wake_renderer,
    save_userip_database_model,
)
from session_sniffer.guis.utils import add_icon_menu_action, find_main_window, open_file_location, set_clipboard_text
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.models.userip_settings_model import DEFAULT_USERIP_FILES_SETTINGS, EntrySource, UserIPDatabaseFile
from session_sniffer.player.userip_loader import rebind_in_app_userip_db_path, userip_databases_lock
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from session_sniffer.guis._main_window_files_mixin import FilesMixin
    from session_sniffer.guis.file_watch import DebouncedFileWatcher

logger = logging.getLogger(__name__)

SIDE_ROLE = Qt.ItemDataRole.UserRole
_MAX_LISTED_COLLISIONS = 5


@dataclass(slots=True)
class SideDetails:
    """Aggregated usernames, notes, Looky state, and timestamps for a resolver tree row."""

    usernames: list[str] = field(default_factory=list[str])
    looky_usernames: set[str] = field(default_factory=set[str])
    notes: list[str] = field(default_factory=list[str])
    sources: list[EntrySource] = field(default_factory=list[EntrySource])
    detections_count: int = 0
    added_at: str | None = None
    updated_at: str | None = None
    first_seen_at: str | None = None
    last_seen_at: str | None = None


@dataclass(frozen=True, slots=True)
class TreeBatchHooks:
    """Widget references and callbacks used by multi-selection database tree operations."""

    dialog: QDialog
    fs_watcher: DebouncedFileWatcher
    is_db_enabled: Callable[[Path], bool]
    unwatch_path: Callable[[Path], None]
    refresh_databases_looky: Callable[[list[Path]], None]
    rebind_open_path: Callable[[Path, Path], None]
    clear_if_open_deleted: Callable[[Path], None]
    set_status: Callable[[str], None]
    on_mutated: Callable[[str], None]


def is_default_userip_db(path: Path) -> bool:
    """Return `True` when *path* is one of the root factory-default UserIP database files."""
    return path.parent == USERIP_DATABASES_DIR_PATH and path.name in DEFAULT_USERIP_FILES_SETTINGS


def get_selected_tree_paths(
    tree: QTreeView,
    index_to_path: Callable[[QModelIndex], Path | None],
) -> list[Path]:
    """Return unique filesystem paths for selected column-0 rows in *tree*."""
    seen: set[Path] = set()
    paths: list[Path] = []
    for idx in tree.selectedIndexes():
        if idx.column():
            continue
        path = index_to_path(idx)
        if path is not None and path not in seen:
            seen.add(path)
            paths.append(path)
    return paths


def prune_nested_tree_paths(paths: Sequence[Path]) -> list[Path]:
    """Remove any path in *paths* whose ancestor directory is also present in *paths*."""
    resolved_dirs = {path.resolve() for path in paths if path.is_dir()}
    if not resolved_dirs:
        return list(paths)
    kept: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if any(parent in resolved_dirs for parent in resolved.parents):
            continue
        kept.append(path)
    return kept


def collect_json_databases_from_paths(paths: Sequence[Path]) -> list[Path]:
    """Collect unique `.json` database files from *paths* (both direct files and folders)."""
    seen: set[Path] = set()
    collected: list[Path] = []
    for path in paths:
        if path.is_file() and path.suffix.lower() == '.json':
            if path not in seen:
                seen.add(path)
                collected.append(path)
        elif path.is_dir():
            for child in sorted(path.rglob('*.json')):
                if child.is_file() and child not in seen:
                    seen.add(child)
                    collected.append(child)
    return collected


def partition_selected_tree_paths(paths: Sequence[Path]) -> tuple[list[Path], list[Path]]:
    """Split pruned top-level *paths* into `(deletable_custom_paths, default_db_paths)`."""
    pruned = prune_nested_tree_paths(paths)
    default_dbs = [path for path in pruned if is_default_userip_db(path)]
    deletable = [path for path in pruned if not is_default_userip_db(path)]
    return deletable, default_dbs


def format_multi_tree_selection_info(selected_paths: Sequence[Path]) -> tuple[str, str]:
    """Return `(file_info_html, status_html)` summarizing a multi-item tree selection."""
    direct_dbs = sum(1 for path in selected_paths if path.is_file() and path.suffix.lower() == '.json')
    folders = sum(1 for path in selected_paths if path.is_dir())
    total_dbs = len(collect_json_databases_from_paths(selected_paths))

    if direct_dbs and folders:
        breakdown = tr(
            '{databases}, {folders}',
            databases=tr_plural('{count} database', '{count} databases', direct_dbs),
            folders=tr_plural('{count} folder', '{count} folders', folders),
        )
    elif direct_dbs:
        breakdown = tr_plural('{count} database', '{count} databases', direct_dbs)
    elif folders:
        breakdown = tr_plural('{count} folder', '{count} folders', folders)
    else:
        breakdown = tr_plural('{count} item', '{count} items', len(selected_paths))

    selected_label = html.escape(tr('Selected:'))
    selected_count = html.escape(tr_plural('{count} item', '{count} items', len(selected_paths)))
    dbs_label = html.escape(tr('Databases in selection:'))
    status_text = html.escape(tr('Right-click selection for batch actions'))

    info_html = themed_qss(
        f'<span style="color:#8a9bad;">{selected_label}</span> <b style="color:#6db3f2;">{selected_count}</b> '
        f'<span style="color:#a0b0c0;">({html.escape(breakdown)})</span><br>'
        f'<span style="color:#8a9bad;">{dbs_label}</span> <b style="color:#e0e0e0;">{total_dbs}</b>',
    )
    status_html = themed_qss(f'<span style="color:#a0b0c0;"><i>{status_text}</i></span>')
    return info_html, status_html


def set_databases_enabled_batch(hooks: TreeBatchHooks, db_paths: Sequence[Path], *, enabled: bool) -> None:
    """Enable or disable all target `.json` databases in a single locked update."""
    targets = [
        path
        for path in db_paths
        if path.is_file() and path.suffix.lower() == '.json' and hooks.is_db_enabled(path) != enabled
    ]
    if not targets:
        return

    action_title = tr('Enabling Databases\u2026') if enabled else tr('Disabling Databases\u2026')

    def _apply() -> None:
        with userip_databases_lock():
            for path in targets:
                db_model = load_userip_database_model(path)
                db_model.settings.ENABLED = enabled
                save_userip_database_model(path, db_model)
            refresh_userip_and_wake_renderer()

    with QSignalBlocker(hooks.fs_watcher):
        if hooks.dialog.isVisible():
            run_blocking_with_loading(
                hooks.dialog,
                action_title,
                tr_plural('Updating {count} database\u2026', 'Updating {count} databases\u2026', len(targets)),
                _apply,
            )
        else:
            _apply()

    status_msg = (
        tr_plural('Enabled {count} database', 'Enabled {count} databases', len(targets))
        if enabled
        else tr_plural('Disabled {count} database', 'Disabled {count} databases', len(targets))
    )
    hooks.on_mutated(status_msg)


def _plan_batch_move(dialog: QDialog, movable: Sequence[Path], dest: Path) -> list[tuple[Path, Path]] | None:
    """Validate destination paths for a batch move and return `(old, new)` pairs, or `None` on validation error."""
    to_move: list[tuple[Path, Path]] = []
    collisions: list[str] = []
    seen_dest_names: set[str] = set()
    duplicate_names: list[str] = []
    seen_duplicate_keys: set[str] = set()
    case_insensitive_fs = sys.platform in ('win32', 'darwin')
    for path in movable:
        if dest == path or path in dest.parents:
            QMessageBox.warning(dialog, TITLE, tr('Cannot move "{name}" into itself.', name=path.name))
            return None
        if path.parent == dest:
            continue
        dest_key = path.name.casefold() if case_insensitive_fs else path.name
        if dest_key in seen_dest_names:
            if dest_key not in seen_duplicate_keys:
                seen_duplicate_keys.add(dest_key)
                duplicate_names.append(path.name)
            continue
        seen_dest_names.add(dest_key)
        new_path = dest / path.name
        if new_path.exists():
            collisions.append(path.name)
        else:
            to_move.append((path, new_path))

    if duplicate_names:
        names = ', '.join(f'"{name}"' for name in duplicate_names[:_MAX_LISTED_COLLISIONS])
        if len(duplicate_names) > _MAX_LISTED_COLLISIONS:
            duplicate_text = tr(
                'Selection contains duplicate item names: {names} (+{extra} more). Nothing was moved.',
                names=names,
                extra=len(duplicate_names) - _MAX_LISTED_COLLISIONS,
            )
        else:
            duplicate_text = tr('Selection contains duplicate item names: {names}. Nothing was moved.', names=names)
        QMessageBox.warning(dialog, TITLE, duplicate_text)
        return None
    if collisions:
        names = ', '.join(f'"{name}"' for name in collisions[:_MAX_LISTED_COLLISIONS])
        if len(collisions) > _MAX_LISTED_COLLISIONS:
            collision_text = tr(
                'Destination already contains {names} (+{extra} more). Nothing was moved.',
                names=names,
                extra=len(collisions) - _MAX_LISTED_COLLISIONS,
            )
        else:
            collision_text = tr('Destination already contains {names}. Nothing was moved.', names=names)
        QMessageBox.warning(dialog, TITLE, collision_text)
        return None
    return to_move


def move_selected_tree_items(hooks: TreeBatchHooks, selected_paths: Sequence[Path]) -> None:
    """Move all movable top-level items in *selected_paths* into a chosen directory."""
    pruned = prune_nested_tree_paths(selected_paths)
    movable = [path for path in pruned if not is_default_userip_db(path)]
    skipped_defaults = len(pruned) - len(movable)
    if not movable:
        QMessageBox.information(hooks.dialog, TITLE, tr('Default factory databases must remain in the root UserIP Databases folder.'))
        return

    target_dir = QFileDialog.getExistingDirectory(
        hooks.dialog,
        tr_plural('Move {count} selected item to...', 'Move {count} selected items to...', len(movable)),
        str(USERIP_DATABASES_DIR_PATH),
    )
    if not target_dir:
        return

    dest = Path(target_dir)
    try:
        rel_dest = dest.relative_to(USERIP_DATABASES_DIR_PATH)
    except ValueError:
        QMessageBox.warning(hooks.dialog, TITLE, tr('Destination must be within the UserIP Databases directory.'))
        return

    to_move = _plan_batch_move(hooks.dialog, movable, dest)
    if to_move is None:
        return
    if not to_move:
        hooks.set_status(tr('Selected items are already in that folder.'))
        return

    for old_path, _ in to_move:
        hooks.unwatch_path(old_path)

    def _move_batch() -> tuple[list[tuple[Path, Path]], int, OSError | None]:
        moved_pairs: list[tuple[Path, Path]] = []
        failed_count = 0
        first_error: OSError | None = None
        with userip_databases_lock():
            for old_path, new_path in to_move:
                try:
                    shutil.move(str(old_path), str(new_path))
                except OSError as e:
                    logger.warning('Failed to move UserIP item "%s" to "%s": %s', old_path, new_path, e)
                    failed_count += 1
                    if first_error is None:
                        first_error = e
                    continue
                rebind_in_app_userip_db_path(old_path, new_path)
                moved_pairs.append((old_path, new_path))
            if moved_pairs:
                refresh_userip_and_wake_renderer()
        return moved_pairs, failed_count, first_error

    moved_pairs, failed_count, first_error = (
        run_blocking_with_loading(
            hooks.dialog,
            tr('Moving Databases\u2026'),
            tr_plural('Moving {count} item\u2026', 'Moving {count} items\u2026', len(to_move)),
            _move_batch,
        )
        if hooks.dialog.isVisible()
        else _move_batch()
    )

    for old_path, new_path in moved_pairs:
        hooks.rebind_open_path(old_path, new_path)

    if failed_count and first_error is not None:
        QMessageBox.warning(
            hooks.dialog,
            TITLE,
            tr_plural(
                'Failed to move {count} item:\n{error}',
                'Failed to move {count} items:\n{error}',
                failed_count,
                error=first_error,
            ),
        )
    if not moved_pairs:
        hooks.on_mutated('')
        return

    dest_label = tr('root') if rel_dest == Path() else str(rel_dest)
    moved_part = tr_plural('Moved {count} item', 'Moved {count} items', len(moved_pairs))
    if skipped_defaults:
        kept_note = tr_plural(
            '{count} default database kept in root',
            '{count} default databases kept in root',
            skipped_defaults,
        )
        hooks.on_mutated(tr('{moved} \u2192 {destination} ({note})', moved=moved_part, destination=dest_label, note=kept_note))
    else:
        hooks.on_mutated(tr('{moved} \u2192 {destination}', moved=moved_part, destination=dest_label))


def move_single_tree_item(hooks: TreeBatchHooks, path: Path) -> None:
    """Move a single file or folder to a user-chosen destination inside the UserIP root."""
    target_dir = QFileDialog.getExistingDirectory(hooks.dialog, tr('Move "{name}" to...', name=path.name), str(USERIP_DATABASES_DIR_PATH))
    if not target_dir:
        return
    dest = Path(target_dir)
    try:
        rel_dest = dest.relative_to(USERIP_DATABASES_DIR_PATH)
    except ValueError:
        QMessageBox.warning(hooks.dialog, TITLE, tr('Destination must be within the UserIP Databases directory.'))
        return
    if dest == path or path in dest.parents:
        QMessageBox.warning(hooks.dialog, TITLE, tr('Cannot move "{name}" into itself.', name=path.name))
        return
    new_path = dest / path.name
    if new_path.exists():
        QMessageBox.warning(hooks.dialog, TITLE, tr('"{name}" already exists in the destination folder.', name=path.name))
        return

    hooks.unwatch_path(path)

    def _move_one() -> OSError | None:
        with userip_databases_lock():
            try:
                shutil.move(str(path), str(new_path))
            except OSError as e:
                logger.warning('Failed to move UserIP item "%s" to "%s": %s', path, new_path, e)
                return e
            rebind_in_app_userip_db_path(path, new_path)
            refresh_userip_and_wake_renderer()
        return None

    move_error = (
        run_blocking_with_loading(
            hooks.dialog,
            tr('Moving Database\u2026'),
            tr('Moving "{name}"\u2026', name=path.name),
            _move_one,
        )
        if hooks.dialog.isVisible()
        else _move_one()
    )
    if move_error is not None:
        hooks.on_mutated('')
        QMessageBox.warning(hooks.dialog, TITLE, tr('Failed to move "{name}":\n{error}', name=path.name, error=move_error))
        return
    hooks.rebind_open_path(path, new_path)

    dest_label = tr('root') if rel_dest == Path() else str(rel_dest)
    hooks.on_mutated(tr('Moved "{name}" \u2192 {destination}', name=path.name, destination=dest_label))


def delete_single_tree_path(hooks: TreeBatchHooks, path: Path) -> None:
    """Delete a single file or folder after user confirmation."""
    if path.is_dir():
        try:
            children = list(path.iterdir())
        except OSError:
            children = []
        message = (
            tr_plural(
                'Folder "{name}" is not empty ({count} item).\n\nDelete it and all its contents?',
                'Folder "{name}" is not empty ({count} items).\n\nDelete it and all its contents?',
                len(children),
                name=path.name,
            )
            if children
            else tr('Delete empty folder "{name}"?', name=path.name)
        )
    else:
        message = tr('Delete database "{name}"?', name=path.name)

    result = QMessageBox.warning(
        hooks.dialog,
        TITLE,
        message,
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No,
    )
    if result != QMessageBox.StandardButton.Yes:
        return

    hooks.unwatch_path(path)

    def _delete_one() -> OSError | None:
        with userip_databases_lock():
            try:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
            except OSError as e:
                logger.warning('Failed to delete UserIP item "%s": %s', path, e)
                return e
            refresh_userip_and_wake_renderer()
        return None

    delete_error = (
        run_blocking_with_loading(
            hooks.dialog,
            tr('Deleting Database\u2026'),
            tr('Removing "{name}"\u2026', name=path.name),
            _delete_one,
        )
        if hooks.dialog.isVisible()
        else _delete_one()
    )
    if delete_error is not None:
        hooks.on_mutated('')
        QMessageBox.warning(hooks.dialog, TITLE, tr('Failed to delete "{name}":\n{error}', name=path.name, error=delete_error))
        return

    hooks.clear_if_open_deleted(path)
    hooks.on_mutated(tr('Deleted: {name}', name=path.name))


def export_json_databases_to_zip(
    dialog: QDialog,
    json_files: Sequence[Path],
    set_status: Callable[[str], None],
    *,
    selected_only: bool = False,
) -> None:
    """Prompt for a destination ZIP file and asynchronously compress *json_files* into it."""
    dialog_title = tr('Export Selected Databases as ZIP') if selected_only else tr('Export All Databases as ZIP')
    default_filename = 'UserIP_Selected_Databases.zip' if selected_only else 'UserIP_Databases.zip'
    loading_detail = (
        tr('Compressing selected UserIP databases into ZIP archive\u2026')
        if selected_only
        else tr('Compressing UserIP databases into ZIP archive\u2026')
    )
    dest_path, _ = QFileDialog.getSaveFileName(
        dialog,
        dialog_title,
        default_filename,
        tr('ZIP archives (*.zip);;All Files (*)'),
    )
    if not dest_path:
        return

    def _write_zip() -> str | None:
        try:
            with zipfile.ZipFile(dest_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                for json_path in json_files:
                    arcname = json_path.relative_to(USERIP_DATABASES_DIR_PATH)
                    zf.write(str(json_path), str(arcname))
        except OSError as exc:
            return str(exc)
        return None

    def _on_done(error_msg: str | None) -> None:
        if error_msg is not None:
            set_status(tr('ZIP export failed.'))
            QMessageBox.critical(dialog, TITLE, tr('Failed to export ZIP archive:\n\n{error}', error=error_msg))
            return
        status_text = (
            tr_plural(
                'Exported {count} selected database to {path}',
                'Exported {count} selected databases to {path}',
                len(json_files),
                path=dest_path,
            )
            if selected_only
            else tr_plural(
                'Exported {count} database to {path}',
                'Exported {count} databases to {path}',
                len(json_files),
                path=dest_path,
            )
        )
        set_status(status_text)

    run_async_with_loading(
        dialog,
        tr('Exporting Databases\u2026'),
        loading_detail,
        _write_zip,
        _on_done,
    )


def export_selected_tree_paths_as_zip(
    dialog: QDialog,
    selected_paths: Sequence[Path],
    set_status: Callable[[str], None],
) -> None:
    """Export all `.json` databases covered by *selected_paths* into a ZIP archive."""
    json_files = collect_json_databases_from_paths(selected_paths)
    if not json_files:
        QMessageBox.information(dialog, TITLE, tr('No database files found in the current selection.'))
        return

    export_json_databases_to_zip(dialog, json_files, set_status, selected_only=True)


def delete_selected_tree_items(hooks: TreeBatchHooks, selected_paths: Sequence[Path]) -> None:
    """Delete all selected custom databases/folders after confirmation (preserving factory-default DBs)."""
    deletable, default_dbs = partition_selected_tree_paths(selected_paths)
    if not deletable:
        if default_dbs:
            reset_selected_default_databases(hooks, default_dbs)
        return

    db_count = sum(1 for path in deletable if path.is_file())
    dir_count = sum(1 for path in deletable if path.is_dir())
    if db_count and dir_count:
        summary = tr(
            '{databases} and {folders}',
            databases=tr_plural('{count} database', '{count} databases', db_count),
            folders=tr_plural('{count} folder (and its contents)', '{count} folders (and their contents)', dir_count),
        )
    elif db_count:
        summary = tr_plural('{count} database', '{count} databases', db_count)
    else:
        summary = tr_plural('{count} folder (and its contents)', '{count} folders (and their contents)', dir_count)

    if default_dbs:
        prompt = tr_plural(
            'Permanently delete {summary}?\n\nNote: {count} factory-default database in the selection will be kept intact.\n\nThis cannot be undone.',
            'Permanently delete {summary}?\n\nNote: {count} factory-default databases in the selection will be kept intact.\n\nThis cannot be undone.',
            len(default_dbs),
            summary=summary,
        )
    else:
        prompt = tr('Permanently delete {summary}?\n\nThis cannot be undone.', summary=summary)

    result = QMessageBox.warning(
        hooks.dialog,
        TITLE,
        prompt,
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No,
    )
    if result != QMessageBox.StandardButton.Yes:
        return

    for path in deletable:
        hooks.unwatch_path(path)
        hooks.clear_if_open_deleted(path)

    def _delete_work() -> int:
        removed = 0
        with userip_databases_lock():
            for path in deletable:
                try:
                    if path.is_dir():
                        shutil.rmtree(path)
                    elif path.exists():
                        path.unlink()
                    removed += 1
                except OSError as exc:
                    logger.warning('Failed to delete %s: %s', path, exc)
            refresh_userip_and_wake_renderer()
        return removed

    removed_count = (
        run_blocking_with_loading(hooks.dialog, tr('Deleting Databases\u2026'), tr('Removing selected items\u2026'), _delete_work)
        if hooks.dialog.isVisible()
        else _delete_work()
    )

    if default_dbs:
        deleted_text = tr_plural('Deleted {count} selected item', 'Deleted {count} selected items', removed_count)
        kept_text = tr_plural('{count} default kept', '{count} defaults kept', len(default_dbs))
        hooks.on_mutated(tr('{deleted} ({kept})', deleted=deleted_text, kept=kept_text))
    else:
        hooks.on_mutated(tr_plural('Deleted {count} selected item', 'Deleted {count} selected items', removed_count))


def reset_selected_default_databases(hooks: TreeBatchHooks, default_paths: Sequence[Path]) -> None:
    """Reset one or more selected factory-default databases after user confirmation."""
    targets = [path for path in default_paths if is_default_userip_db(path)]
    if not targets:
        return

    if len(targets) == 1:
        prompt = tr('Reset "{name}" to factory content?\n\nAll entries and settings in this file will be lost.', name=targets[0].name)
    else:
        names = ', '.join(f'"{path.name}"' for path in targets)
        prompt = tr_plural(
            'Reset {count} default database ({names}) to factory content?\n\nAll entries and custom settings in these files will be lost.',
            'Reset {count} default databases ({names}) to factory content?\n\nAll entries and custom settings in these files will be lost.',
            len(targets),
            names=names,
        )
    result = QMessageBox.warning(
        hooks.dialog,
        TITLE,
        prompt,
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No,
    )
    if result != QMessageBox.StandardButton.Yes:
        return

    def _reset_work() -> None:
        with userip_databases_lock():
            for path in targets:
                save_userip_database_model(path, UserIPDatabaseFile(settings=DEFAULT_USERIP_FILES_SETTINGS[path.name]))
            refresh_userip_and_wake_renderer()

    if hooks.dialog.isVisible():
        run_blocking_with_loading(
            hooks.dialog,
            tr('Resetting Databases\u2026'),
            tr('Restoring factory defaults\u2026'),
            _reset_work,
        )
    else:
        _reset_work()

    status = (
        tr('Reset "{name}" to factory defaults.', name=targets[0].name)
        if len(targets) == 1
        else tr_plural('Reset {count} default database to factory defaults.', 'Reset {count} default databases to factory defaults.', len(targets))
    )
    hooks.on_mutated(status)


def populate_multi_tree_context_menu(
    hooks: TreeBatchHooks,
    menu: QMenu,
    selected_paths: Sequence[Path],
) -> None:
    """Populate *menu* with batch operations for a multi-selected set of tree items."""
    all_dbs = collect_json_databases_from_paths(selected_paths)
    disabled_count = sum(1 for db_path in all_dbs if not hooks.is_db_enabled(db_path))
    enabled_count = len(all_dbs) - disabled_count

    if disabled_count:
        enable_act = QAction(QIcon(str(ICONS_DIR_PATH / 'check.svg')), tr('Enable Databases ({count})', count=disabled_count), hooks.dialog)
        enable_act.triggered.connect(lambda: set_databases_enabled_batch(hooks, all_dbs, enabled=True))
        menu.addAction(enable_act)
    if enabled_count:
        disable_act = QAction(QIcon(str(ICONS_DIR_PATH / 'x.svg')), tr('Disable Databases ({count})', count=enabled_count), hooks.dialog)
        disable_act.triggered.connect(lambda: set_databases_enabled_batch(hooks, all_dbs, enabled=False))
        menu.addAction(disable_act)
    if disabled_count or enabled_count:
        menu.addSeparator()

    deletable, default_dbs = partition_selected_tree_paths(selected_paths)
    move_act = QAction(QIcon(str(ICONS_DIR_PATH / 'box.svg')), tr('Move Selected ({count}) to...', count=len(deletable)), hooks.dialog)
    move_act.setEnabled(bool(deletable))
    move_act.triggered.connect(lambda: move_selected_tree_items(hooks, selected_paths))
    menu.addAction(move_act)

    if all_dbs and Settings.is_gta5_feature_set() and CaptureState.is_local_capture():
        menu.addSeparator()
        refresh_act = QAction(
            QIcon(str(ICONS_DIR_PATH / 'eye.svg')),
            tr('Refresh Selected ({count}) (Looky System)', count=len(all_dbs)),
            hooks.dialog,
        )
        refresh_act.triggered.connect(lambda: hooks.refresh_databases_looky(list(all_dbs)))
        configure_looky_action(
            refresh_act,
            tr_plural(
                'Scan all IPs and usernames across the {count} selected database via Looky System.',
                'Scan all IPs and usernames across the {count} selected databases via Looky System.',
                len(all_dbs),
            ),
        )
        menu.addAction(refresh_act)

    menu.addSeparator()
    export_act = QAction(QIcon(str(ICONS_DIR_PATH / 'upload.svg')), tr('Export Selected as ZIP\u2026'), hooks.dialog)
    export_act.setEnabled(bool(all_dbs))
    export_act.triggered.connect(lambda: export_selected_tree_paths_as_zip(hooks.dialog, selected_paths, hooks.set_status))
    menu.addAction(export_act)

    menu.addSeparator()
    if deletable:
        del_act = QAction(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), tr('Delete ({count})', count=len(deletable)), hooks.dialog)
        del_act.setShortcut('Delete')
        del_act.triggered.connect(lambda: delete_selected_tree_items(hooks, selected_paths))
        menu.addAction(del_act)
    if default_dbs:
        reset_act = QAction(QIcon(str(ICONS_DIR_PATH / 'refresh-cw.svg')), tr('Reset Default ({count})', count=len(default_dbs)), hooks.dialog)
        if not deletable:
            reset_act.setShortcut('Delete')
        reset_act.triggered.connect(lambda: reset_selected_default_databases(hooks, default_dbs))
        menu.addAction(reset_act)


def populate_userip_databases_menu(
    parent_menu: QMenu,
    database_paths: list[Path],
    tooltip: str,
    handler_factory: Callable[[Path], Callable[[], None]],
    *,
    disabled_path: Path | None = None,
) -> int:
    """Add database entries to *parent_menu*, nesting subfolders as child menus, and return the enabled action count."""
    folder_menus: dict[tuple[str, ...], QMenu] = {}
    menus_with_folders: set[QMenu] = set()
    enabled_count = 0

    def _sort_key(db_path: Path) -> tuple[tuple[int, str], ...]:
        rel = db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
        return tuple((0, part.casefold()) if i < len(rel.parts) - 1 else (1, part.casefold()) for i, part in enumerate(rel.parts))

    for db_path in sorted(database_paths, key=_sort_key):
        rel = db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
        current_menu = parent_menu
        for depth in range(len(rel.parts) - 1):
            folder_key = rel.parts[: depth + 1]
            if folder_key not in folder_menus:
                folder_menu = current_menu.addMenu(QIcon(str(ICONS_DIR_PATH / 'folder.svg')), rel.parts[depth])
                folder_menu.setToolTipsVisible(True)
                folder_menus[folder_key] = folder_menu
                menus_with_folders.add(current_menu)
            current_menu = folder_menus[folder_key]

        if current_menu in menus_with_folders:
            current_menu.addSeparator()
            menus_with_folders.remove(current_menu)

        action = current_menu.addAction(QIcon(str(ICONS_DIR_PATH / 'database.svg')), rel.parts[-1])
        action.setToolTip(tooltip)
        action.triggered.connect(handler_factory(db_path))
        if disabled_path is not None and db_path == disabled_path:
            action.setEnabled(False)
        else:
            enabled_count += 1

    return enabled_count


def is_single_ipv4(entry_text: str) -> bool:
    """Return `True` if `entry_text` is a single IPv4 address rather than a range or CIDR subnet."""
    if not entry_text or '/' in entry_text or '-' in entry_text or '*' in entry_text:
        return False
    try:
        IPv4Address(entry_text)
    except ValueError:
        return False
    return True


def navigate_to_database_in_manager(db_path: Path, *, username: str = '', ip_or_range: str = '') -> None:
    """Open or focus the UserIP Databases Manager on `db_path` and select the matching entry."""
    main_window = cast('FilesMixin | None', find_main_window())
    if main_window is not None:
        main_window.open_userip_manager_and_navigate(db_path, username=username, ip_or_range=ip_or_range)


def copy_resolver_selected_row(tree: QTreeWidget) -> None:
    """Copy visible cell values of selected child row(s) in *tree* as tab-separated lines."""
    child_items = sorted(
        (item for item in tree.selectedItems() if isinstance(item.data(0, SIDE_ROLE), int)),
        key=lambda item: int(item.data(0, SIDE_ROLE)),
    )
    if not child_items:
        return
    header = tree.header()
    visible_cols = [col for col in range(tree.columnCount()) if not header.isSectionHidden(col)]
    set_clipboard_text('\n'.join('\t'.join(item.text(col) for col in visible_cols) for item in child_items))


def create_resolver_tail_buttons(
    buttons_layout: QHBoxLayout, *, on_edit: Callable[[], object], on_delete: Callable[[], object], on_close: Callable[[], object],
) -> tuple[QPushButton, QPushButton, QPushButton]:
    """Append `Edit Entry…`, `Delete This Entry…`, stretch, and `Close` buttons; return `(edit_btn, delete_btn, close_btn)`."""
    edit_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'square-pen.svg')), f" {tr('Edit Entry\u2026')}")
    edit_button.setAutoDefault(False)
    edit_button.setToolTip(tr('Change the IP or range of the selected entry using the builder'))
    edit_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    edit_button.clicked.connect(on_edit)
    buttons_layout.addWidget(edit_button)

    delete_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), f" {tr('Delete This Entry\u2026')}")
    delete_button.setAutoDefault(False)
    delete_button.setToolTip(tr('Delete only the selected entry from its database (you will be asked to confirm)'))
    delete_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
    delete_button.clicked.connect(on_delete)
    buttons_layout.addWidget(delete_button)

    buttons_layout.addStretch()

    close_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'x.svg')), f" {tr('Close')}")
    close_button.setAutoDefault(False)
    close_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    close_button.clicked.connect(on_close)
    buttons_layout.addWidget(close_button)
    return edit_button, delete_button, close_button


def retranslate_resolver_tail_buttons(edit_button: QPushButton, delete_button: QPushButton, close_button: QPushButton) -> None:
    """Refresh static labels and tooltips on the resolver tail buttons."""
    edit_button.setText(f" {tr('Edit Entry\u2026')}")
    edit_button.setToolTip(tr('Change the IP or range of the selected entry using the builder'))
    delete_button.setToolTip(tr('Delete only the selected entry from its database (you will be asked to confirm)'))
    close_button.setText(f" {tr('Close')}")


def populate_resolver_common_menu_prefix(
    menu: QMenu, tree: QTreeWidget, *, db_path: Path, entry_ip: str, details: SideDetails,
) -> bool:
    """Append standard Copy and Database navigation actions to *menu* and return `is_single_ipv4(entry_ip)`."""
    single_ip = is_single_ipv4(entry_ip)
    copy_row = add_icon_menu_action(menu, 'copy.svg', tr('Copy Row'), lambda: copy_resolver_selected_row(tree))
    copy_row.setShortcut('Ctrl+C')
    if details.usernames:
        names_txt = ', '.join(details.usernames)
        add_icon_menu_action(menu, 'copy.svg', tr_plural('Copy Username', 'Copy Usernames', len(details.usernames)), lambda: set_clipboard_text(names_txt))
    add_icon_menu_action(menu, 'copy.svg', tr('Copy IP') if single_ip else tr('Copy Range'), lambda: set_clipboard_text(entry_ip))
    if details.notes:
        notes_txt = ', '.join(details.notes)
        add_icon_menu_action(menu, 'copy.svg', tr('Copy Note'), lambda: set_clipboard_text(notes_txt))

    menu.addSeparator()
    first_user = details.usernames[0] if details.usernames else ''
    add_icon_menu_action(
        menu, 'arrow-right.svg', tr('Go to Database'),
        lambda: navigate_to_database_in_manager(db_path, username=first_user, ip_or_range=entry_ip),
        tooltip=tr('Open this database in the UserIP Databases Manager and navigate to this entry.'),
    )
    add_icon_menu_action(menu, 'file-text.svg', tr('Open in Text Editor'), lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(db_path))))
    add_icon_menu_action(menu, 'folder.svg', tr('Open in File Manager'), lambda: open_file_location(db_path))
    menu.addSeparator()
    return single_ip


def populate_resolver_ip_tools_menu(parent: QWidget, menu: QMenu, entry_ip: str, *, single_ip: bool) -> None:
    """Append IP Lookup, Ping, and Scan Ports actions when *single_ip* is `True`."""
    if single_ip:
        menu.addSeparator()
        add_icon_menu_action(menu, 'info.svg', tr('IP Lookup Details\u2026'), lambda: show_detailed_ip_lookup(entry_ip))
        create_ping_menu(parent, menu, [entry_ip])
        add_icon_menu_action(menu, 'radar.svg', tr('Scan Ports\u2026'), lambda: scan_ports_ip(entry_ip))


_MIN_PRINTABLE_ASCII = 32
_INVALID_FILENAME_CHARS: frozenset[str] = frozenset('<>:"/\\|?*')
_WINDOWS_RESERVED_FILENAMES: frozenset[str] = frozenset(
    {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))},
)


def is_valid_tree_item_name(name: str) -> bool:
    """Return `True` when *name* is a safe, cross-platform single file or folder name."""
    return (
        bool(name)
        and name not in ('.', '..')
        and not name.endswith(('.', ' '))
        and not any(ord(character) < _MIN_PRINTABLE_ASCII or character in _INVALID_FILENAME_CHARS for character in name)
        and name.partition('.')[0].upper() not in _WINDOWS_RESERVED_FILENAMES
    )


def validate_tree_item_name(parent: QWidget, name: str) -> bool:
    """Validate a single UserIP tree file/folder name, showing a warning dialog when invalid."""
    is_valid = is_valid_tree_item_name(name)
    if not is_valid:
        QMessageBox.warning(
            parent,
            TITLE,
            tr('Invalid name "{name}". Avoid path separators and invalid filename characters.', name=name),
        )
    return is_valid
