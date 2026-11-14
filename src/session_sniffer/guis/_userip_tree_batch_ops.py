"""Multi-selection batch helpers for the UserIP Databases Manager file tree."""

import html
import logging
import shutil
import zipfile
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QModelIndex, QSignalBlocker
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QDialog, QFileDialog, QMenu, QMessageBox, QTreeView

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.loading_overlay import loading_overlay_scope, run_async_with_loading, run_with_active_loading
from session_sniffer.guis.looky_text import configure_looky_action
from session_sniffer.guis.theming import ICONS_DIR_PATH, themed_qss
from session_sniffer.guis.userip_manager_helpers import (
    load_userip_database_model,
    refresh_userip_and_wake_renderer,
    save_userip_database_model,
)
from session_sniffer.models.userip_settings_model import DEFAULT_USERIP_FILES_SETTINGS, UserIPDatabaseFile
from session_sniffer.player.userip_loader import rebind_in_app_userip_db_path, userip_databases_lock
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from session_sniffer.guis.file_watch import DebouncedFileWatcher

logger = logging.getLogger(__name__)

_BATCH_OVERLAY_DB_THRESHOLD = 5
_BATCH_DELETE_OVERLAY_THRESHOLD = 3
_MAX_LISTED_COLLISIONS = 5


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

    parts: list[str] = []
    if direct_dbs:
        parts.append(f'{direct_dbs} database{pluralize(direct_dbs)}')
    if folders:
        parts.append(f'{folders} folder{pluralize(folders)}')
    breakdown = ', '.join(parts) if parts else f'{len(selected_paths)} items'

    info_html = themed_qss(
        f'<span style="color:#8a9bad;">Selected:</span> <b style="color:#6db3f2;">{len(selected_paths)} items</b> '
        f'<span style="color:#a0b0c0;">({html.escape(breakdown)})</span><br>'
        f'<span style="color:#8a9bad;">Databases in selection:</span> <b style="color:#e0e0e0;">{total_dbs}</b>',
    )
    status_html = themed_qss('<span style="color:#a0b0c0;"><i>Right-click selection for batch actions</i></span>')
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

    action_title = 'Enabling Databases\u2026' if enabled else 'Disabling Databases\u2026'
    use_overlay = hooks.dialog.isVisible() and len(targets) >= _BATCH_OVERLAY_DB_THRESHOLD
    scope = (
        loading_overlay_scope(hooks.dialog, action_title, f'Updating {len(targets)} databases\u2026')
        if use_overlay
        else nullcontext()
    )

    def _apply() -> None:
        with userip_databases_lock():
            for path in targets:
                db_model = load_userip_database_model(path)
                db_model.settings.ENABLED = enabled
                save_userip_database_model(path, db_model)
            refresh_userip_and_wake_renderer()

    with scope, QSignalBlocker(hooks.fs_watcher):
        if use_overlay:
            run_with_active_loading(_apply)
        else:
            _apply()

    verb = 'Enabled' if enabled else 'Disabled'
    hooks.on_mutated(f'{verb} {len(targets)} database{pluralize(len(targets))}')


def move_selected_tree_items(hooks: TreeBatchHooks, selected_paths: Sequence[Path]) -> None:
    """Move all movable top-level items in *selected_paths* into a chosen directory."""
    pruned = prune_nested_tree_paths(selected_paths)
    movable = [path for path in pruned if not is_default_userip_db(path)]
    skipped_defaults = len(pruned) - len(movable)
    if not movable:
        QMessageBox.information(hooks.dialog, TITLE, 'Default factory databases must remain in the root UserIP Databases folder.')
        return

    target_dir = QFileDialog.getExistingDirectory(
        hooks.dialog,
        f'Move {len(movable)} selected item{pluralize(len(movable))} to...',
        str(USERIP_DATABASES_DIR_PATH),
    )
    if not target_dir:
        return

    dest = Path(target_dir)
    try:
        rel_dest = dest.relative_to(USERIP_DATABASES_DIR_PATH)
    except ValueError:
        QMessageBox.warning(hooks.dialog, TITLE, 'Destination must be within the UserIP Databases directory.')
        return

    to_move: list[tuple[Path, Path]] = []
    collisions: list[str] = []
    for path in movable:
        if dest == path or path in dest.parents:
            QMessageBox.warning(hooks.dialog, TITLE, f'Cannot move "{path.name}" into itself.')
            return
        if path.parent == dest:
            continue
        new_path = dest / path.name
        if new_path.exists():
            collisions.append(path.name)
        else:
            to_move.append((path, new_path))

    if collisions:
        names = ', '.join(f'"{name}"' for name in collisions[:_MAX_LISTED_COLLISIONS])
        extra = f' (+{len(collisions) - _MAX_LISTED_COLLISIONS} more)' if len(collisions) > _MAX_LISTED_COLLISIONS else ''
        QMessageBox.warning(hooks.dialog, TITLE, f'Destination already contains {names}{extra}. Nothing was moved.')
        return
    if not to_move:
        hooks.set_status('Selected items are already in that folder.')
        return

    for old_path, _ in to_move:
        hooks.unwatch_path(old_path)

    with userip_databases_lock():
        for old_path, new_path in to_move:
            shutil.move(str(old_path), str(new_path))
            rebind_in_app_userip_db_path(old_path, new_path)
            hooks.rebind_open_path(old_path, new_path)
        refresh_userip_and_wake_renderer()

    dest_label = 'root' if rel_dest == Path() else str(rel_dest)
    note = f' ({skipped_defaults} default database{pluralize(skipped_defaults)} kept in root)' if skipped_defaults else ''
    hooks.on_mutated(f'Moved {len(to_move)} item{pluralize(len(to_move))} \u2192 {dest_label}{note}')


def move_single_tree_item(hooks: TreeBatchHooks, path: Path) -> None:
    """Move a single file or folder to a user-chosen destination inside the UserIP root."""
    target_dir = QFileDialog.getExistingDirectory(hooks.dialog, f'Move "{path.name}" to...', str(USERIP_DATABASES_DIR_PATH))
    if not target_dir:
        return
    dest = Path(target_dir)
    try:
        rel_dest = dest.relative_to(USERIP_DATABASES_DIR_PATH)
    except ValueError:
        QMessageBox.warning(hooks.dialog, TITLE, 'Destination must be within the UserIP Databases directory.')
        return
    if dest == path or path in dest.parents:
        QMessageBox.warning(hooks.dialog, TITLE, f'Cannot move "{path.name}" into itself.')
        return
    new_path = dest / path.name
    if new_path.exists():
        QMessageBox.warning(hooks.dialog, TITLE, f'"{path.name}" already exists in the destination folder.')
        return

    hooks.unwatch_path(path)
    with userip_databases_lock():
        shutil.move(str(path), str(new_path))
        rebind_in_app_userip_db_path(path, new_path)
        hooks.rebind_open_path(path, new_path)
        refresh_userip_and_wake_renderer()

    dest_label = 'root' if rel_dest == Path() else str(rel_dest)
    hooks.on_mutated(f'Moved "{path.name}" \u2192 {dest_label}')


def delete_single_tree_path(hooks: TreeBatchHooks, path: Path) -> None:
    """Delete a single file or folder after user confirmation."""
    if path.is_dir():
        children = list(path.iterdir())
        message = (
            f'Folder "{path.name}" is not empty ({len(children)} item{pluralize(len(children))}).\n\nDelete it and all its contents?'
            if children
            else f'Delete empty folder "{path.name}"?'
        )
    else:
        message = f'Delete database "{path.name}"?'

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
    hooks.clear_if_open_deleted(path)
    with userip_databases_lock():
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        refresh_userip_and_wake_renderer()

    hooks.on_mutated(f'Deleted: {path.name}')


def export_json_databases_to_zip(
    dialog: QDialog,
    json_files: Sequence[Path],
    set_status: Callable[[str], None],
    *,
    selected_only: bool = False,
) -> None:
    """Prompt for a destination ZIP file and asynchronously compress *json_files* into it."""
    dialog_title = 'Export Selected Databases as ZIP' if selected_only else 'Export All Databases as ZIP'
    default_filename = 'UserIP_Selected_Databases.zip' if selected_only else 'UserIP_Databases.zip'
    loading_detail = (
        'Compressing selected UserIP databases into ZIP archive\u2026'
        if selected_only
        else 'Compressing UserIP databases into ZIP archive\u2026'
    )
    status_noun = 'selected database' if selected_only else 'database'
    dest_path, _ = QFileDialog.getSaveFileName(
        dialog,
        dialog_title,
        default_filename,
        'ZIP archives (*.zip);;All Files (*)',
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
            set_status('ZIP export failed.')
            QMessageBox.critical(dialog, TITLE, f'Failed to export ZIP archive:\n\n{error_msg}')
            return
        set_status(f'Exported {len(json_files)} {status_noun}{pluralize(len(json_files))} to {dest_path}')

    run_async_with_loading(
        dialog,
        'Exporting Databases\u2026',
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
        QMessageBox.information(dialog, TITLE, 'No database files found in the current selection.')
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
    parts: list[str] = []
    if db_count:
        parts.append(f'{db_count} database{pluralize(db_count)}')
    if dir_count:
        parts.append(f'{dir_count} folder{pluralize(dir_count)} (and their contents)')
    summary = ' and '.join(parts)
    default_note = (
        f'\n\nNote: {len(default_dbs)} factory-default database{pluralize(len(default_dbs))} in the selection will be kept intact.'
        if default_dbs
        else ''
    )
    prompt = f'Permanently delete {summary}?{default_note}\n\nThis cannot be undone.'
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

    use_overlay = hooks.dialog.isVisible() and (len(deletable) >= _BATCH_DELETE_OVERLAY_THRESHOLD or dir_count > 0)
    with loading_overlay_scope(hooks.dialog, 'Deleting Databases\u2026', 'Removing selected items\u2026') if use_overlay else nullcontext():
        removed_count = run_with_active_loading(_delete_work) if use_overlay else _delete_work()

    kept_suffix = f' ({len(default_dbs)} default kept)' if default_dbs else ''
    hooks.on_mutated(f'Deleted {removed_count} selected item{pluralize(removed_count)}{kept_suffix}')


def reset_selected_default_databases(hooks: TreeBatchHooks, default_paths: Sequence[Path]) -> None:
    """Reset one or more selected factory-default databases after user confirmation."""
    targets = [path for path in default_paths if is_default_userip_db(path)]
    if not targets:
        return

    if len(targets) == 1:
        prompt = f'Reset "{targets[0].name}" to factory content?\n\nAll entries and settings in this file will be lost.'
    else:
        names = ', '.join(f'"{path.name}"' for path in targets)
        prompt = (
            f'Reset {len(targets)} default database{pluralize(len(targets))} ({names}) to factory content?\n\n'
            'All entries and custom settings in these files will be lost.'
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

    with userip_databases_lock():
        for path in targets:
            save_userip_database_model(path, UserIPDatabaseFile(settings=DEFAULT_USERIP_FILES_SETTINGS[path.name]))
        refresh_userip_and_wake_renderer()

    status = (
        f'Reset "{targets[0].name}" to factory defaults.'
        if len(targets) == 1
        else f'Reset {len(targets)} default database{pluralize(len(targets))} to factory defaults.'
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
        enable_act = QAction(QIcon(str(ICONS_DIR_PATH / 'check.svg')), f'Enable Databases ({disabled_count})', hooks.dialog)
        enable_act.triggered.connect(lambda: set_databases_enabled_batch(hooks, all_dbs, enabled=True))
        menu.addAction(enable_act)
    if enabled_count:
        disable_act = QAction(QIcon(str(ICONS_DIR_PATH / 'x.svg')), f'Disable Databases ({enabled_count})', hooks.dialog)
        disable_act.triggered.connect(lambda: set_databases_enabled_batch(hooks, all_dbs, enabled=False))
        menu.addAction(disable_act)
    if disabled_count or enabled_count:
        menu.addSeparator()

    deletable, default_dbs = partition_selected_tree_paths(selected_paths)
    move_act = QAction(QIcon(str(ICONS_DIR_PATH / 'box.svg')), f'Move Selected ({len(deletable)}) to...', hooks.dialog)
    move_act.setEnabled(bool(deletable))
    move_act.triggered.connect(lambda: move_selected_tree_items(hooks, selected_paths))
    menu.addAction(move_act)

    if all_dbs and Settings.is_gta5_feature_set() and CaptureState.is_local_capture():
        menu.addSeparator()
        refresh_act = QAction(
            QIcon(str(ICONS_DIR_PATH / 'eye.svg')),
            f'Refresh Selected ({len(all_dbs)}) (Looky System)',
            hooks.dialog,
        )
        refresh_act.triggered.connect(lambda: hooks.refresh_databases_looky(list(all_dbs)))
        configure_looky_action(
            refresh_act,
            f'Scan all IPs and usernames across the {len(all_dbs)} selected database{pluralize(len(all_dbs))} via Looky System.',
        )
        menu.addAction(refresh_act)

    menu.addSeparator()
    export_act = QAction(QIcon(str(ICONS_DIR_PATH / 'upload.svg')), 'Export Selected as ZIP…', hooks.dialog)
    export_act.setEnabled(bool(all_dbs))
    export_act.triggered.connect(lambda: export_selected_tree_paths_as_zip(hooks.dialog, selected_paths, hooks.set_status))
    menu.addAction(export_act)

    menu.addSeparator()
    if deletable:
        del_act = QAction(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), f'Delete ({len(deletable)})', hooks.dialog)
        del_act.setShortcut('Delete')
        del_act.triggered.connect(lambda: delete_selected_tree_items(hooks, selected_paths))
        menu.addAction(del_act)
    if default_dbs:
        reset_act = QAction(QIcon(str(ICONS_DIR_PATH / 'refresh-cw.svg')), f'Reset Default ({len(default_dbs)})', hooks.dialog)
        if not deletable:
            reset_act.setShortcut('Delete')
        reset_act.triggered.connect(lambda: reset_selected_default_databases(hooks, default_dbs))
        menu.addAction(reset_act)
