"""Tree-panel operations mixin for the UserIP Databases Manager dialog."""

import logging
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, cast, override

from PySide6.QtCore import (
    QEvent,
    QItemSelectionModel,
    QModelIndex,
    QObject,
    QPersistentModelIndex,
    QPoint,
    QRect,
    QRectF,
    QSignalBlocker,
    QSize,
    QSortFilterProxyModel,
    Qt,
    QUrl,
)
from PySide6.QtGui import QAction, QColor, QDesktopServices, QFont, QFontMetrics, QHelpEvent, QIcon, QMouseEvent, QPainter, QPainterPath, QPen, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFileSystemModel,
    QFrame,
    QInputDialog,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QStyle,
    QStyleOptionViewItem,
    QToolTip,
    QTreeView,
)
from shiboken6 import isValid

from session_sniffer.constants.local import RESOURCES_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.delegates import ElidedTextTooltipDelegate
from session_sniffer.guis.looky_text import configure_looky_action
from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.tables_player_actions.looky_system._looky_refresh_userip import looky_refresh_userip_entries
from session_sniffer.guis.userip_manager_helpers import NEW_DATABASE_SETTINGS, load_userip_database_model, refresh_userip_and_wake_renderer, save_userip_database_model
from session_sniffer.guis.utils import open_file_location, scale_by_ui
from session_sniffer.models.userip_settings_model import DEFAULT_USERIP_FILES_SETTINGS, UserIPDatabaseFile
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.guis.color_picker_dialog import ColorPickerButton
    from session_sniffer.guis.file_watch import DebouncedFileWatcher
    from session_sniffer.models.userip_settings_model import UserIPSettingsModel

logger = logging.getLogger(__name__)


class UserIPDatabaseTreeSortProxy(QSortFilterProxyModel):
    """Sort proxy for the UserIP databases tree: folders first, then enabled databases, then disabled databases."""

    def __init__(self, parent: QObject | None, fs_model: QFileSystemModel, is_db_enabled: Callable[[Path], bool]) -> None:
        """Initialize the sort proxy with the source filesystem model and database enabled-state lookup."""
        super().__init__(parent)
        self._fs_model = fs_model
        self._is_db_enabled = is_db_enabled
        self.setSourceModel(fs_model)
        self.setDynamicSortFilter(True)
        self.sort(0, Qt.SortOrder.AscendingOrder)

    def _sort_key(self, source_index: QModelIndex | QPersistentModelIndex) -> tuple[int, str, str]:
        """Return `(group_rank, casefolded_name, raw_name)` for *source_index*."""
        name = self._fs_model.fileName(source_index)
        if self._fs_model.isDir(source_index):
            return 0, name.casefold(), name
        rank = 1
        if name.lower().endswith('.json'):
            file_path = Path(self._fs_model.filePath(source_index))
            if file_path.is_relative_to(USERIP_DATABASES_DIR_PATH):
                rank = 1 if self._is_db_enabled(file_path) else 2
        return rank, name.casefold(), name

    @override
    def lessThan(self, source_left: QModelIndex | QPersistentModelIndex, source_right: QModelIndex | QPersistentModelIndex) -> bool:
        """Order folders first, then enabled databases, then disabled databases, alphabetically within each group."""
        return self._sort_key(source_left) < self._sort_key(source_right)


class UserIPDatabaseTreeDelegate(ElidedTextTooltipDelegate):
    """Item delegate for the UserIP databases tree showing a color dot, strike-through when disabled, and a clickable ON/OFF toggle pill."""

    def __init__(
        self,
        parent: QAbstractItemView,
        get_db_visual: Callable[[QModelIndex | QPersistentModelIndex], tuple[bool, QColor] | None],
        on_toggle_db: Callable[[QModelIndex | QPersistentModelIndex], None],
    ) -> None:
        """Initialize the delegate with callbacks for database visual state and toggling."""
        super().__init__(parent)
        self._view = parent
        self._get_db_visual = get_db_visual
        self._on_toggle_db = on_toggle_db
        self._pressed_index: QPersistentModelIndex | None = None
        viewport = parent.viewport()
        viewport.setMouseTracking(True)
        viewport.installEventFilter(self)

    @staticmethod
    def _pill_rect(row_rect: QRect) -> QRect:
        """Return the rectangle for the right-aligned ON/OFF toggle pill within *row_rect*."""
        pill_w = scale_by_ui(44)
        pill_h = min(scale_by_ui(18), max(scale_by_ui(14), row_rect.height() - scale_by_ui(4)))
        pill_x = row_rect.left() + row_rect.width() - pill_w - scale_by_ui(6)
        pill_y = row_rect.top() + (row_rect.height() - pill_h) // 2
        return QRect(pill_x, pill_y, pill_w, pill_h)

    @override
    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex) -> QSize:
        """Ensure sufficient row height for the ON/OFF toggle pill."""
        size = super().sizeHint(option, index)
        return QSize(size.width(), max(size.height(), scale_by_ui(24)))

    @override
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        """Handle hover cursor and click events on the ON/OFF toggle pill without changing tree selection."""
        if not isValid(self._view) or not isValid(watched):
            return False
        viewport = self._view.viewport()
        if watched is not viewport:
            return super().eventFilter(watched, event)
        if not isinstance(event, QMouseEvent):
            if event.type() == QEvent.Type.Leave:
                viewport.unsetCursor()
            return False

        event_type = event.type()
        pos = event.position().toPoint()
        idx = self._view.indexAt(pos)
        on_pill = idx.isValid() and self._get_db_visual(idx) is not None and self._pill_rect(self._view.visualRect(idx)).contains(pos)

        if event_type == QEvent.Type.MouseMove:
            if on_pill:
                viewport.setCursor(Qt.CursorShape.PointingHandCursor)
            else:
                viewport.unsetCursor()
        elif event.button() == Qt.MouseButton.LeftButton:
            if event_type in (QEvent.Type.MouseButtonPress, QEvent.Type.MouseButtonDblClick) and on_pill:
                self._pressed_index = QPersistentModelIndex(idx)
                return True
            if event_type == QEvent.Type.MouseButtonRelease and self._pressed_index is not None:
                pressed = self._pressed_index
                self._pressed_index = None
                if pressed.isValid() and pressed == QPersistentModelIndex(idx) and on_pill:
                    self._on_toggle_db(idx)
                    new_idx = self._view.indexAt(pos)
                    still_on_pill = new_idx.isValid() and self._get_db_visual(new_idx) is not None and self._pill_rect(self._view.visualRect(new_idx)).contains(pos)
                    if still_on_pill:
                        viewport.setCursor(Qt.CursorShape.PointingHandCursor)
                    else:
                        viewport.unsetCursor()
                    viewport.update()
                return True

        return False

    @override
    def helpEvent(self, event: QHelpEvent, view: QAbstractItemView, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex) -> bool:
        """Show a tooltip when a database row's filename is truncated between its color dot and ON/OFF pill."""
        if not event or event.type() != QEvent.Type.ToolTip or self._get_db_visual(index) is None:
            return super().helpEvent(event, view, option, index)

        rect = cast('QRect', object.__getattribute__(option, 'rect'))
        if not rect.isValid():
            rect = view.visualRect(index)
        pill_rect = self._pill_rect(rect)
        if pill_rect.contains(event.pos()):
            QToolTip.hideText()
            return True

        raw_text = index.data(Qt.ItemDataRole.DisplayRole)
        text = raw_text if isinstance(raw_text, str) else ''
        if not text:
            return super().helpEvent(event, view, option, index)

        text_left = rect.left() + scale_by_ui(6) + scale_by_ui(9) + scale_by_ui(7)
        text_w = max(0, pill_rect.left() - scale_by_ui(6) - text_left)
        base_font = cast('QFont', object.__getattribute__(option, 'font'))
        if QFontMetrics(base_font).horizontalAdvance(text) > text_w:
            QToolTip.showText(event.globalPos(), text, view)
            return True

        QToolTip.hideText()
        return True

    @override
    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex) -> None:
        """Paint database rows with a color dot, strike-through when disabled, and a right-aligned ON/OFF toggle pill."""
        visual = self._get_db_visual(index)
        if visual is None or not painter:
            super().paint(painter, option, index)
            return

        is_enabled, db_color = visual
        self._paint_cell_background(painter, option, index, paint_selection=True)

        rect = cast('QRect', object.__getattribute__(option, 'rect'))
        base_font = cast('QFont', object.__getattribute__(option, 'font'))
        is_selected = bool(option.state & QStyle.StateFlag.State_Selected)

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, on=True)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing, on=True)

        # 1. Left Color Dot
        dot_size = scale_by_ui(9)
        dot_x = rect.left() + scale_by_ui(6)
        dot_y = rect.top() + (rect.height() - dot_size) // 2
        dot_rect = QRectF(float(dot_x), float(dot_y), float(dot_size), float(dot_size))
        painter.setBrush(db_color if is_enabled else QColor('#64748b'))
        painter.setPen(QPen(QColor(255, 255, 255, 75 if is_enabled else 35), 1.0))
        painter.drawEllipse(dot_rect)

        # 2. Right-aligned ON / OFF Toggle Pill
        pill_rect = self._pill_rect(rect)
        pill_radius = float(scale_by_ui(4))
        pill_path = QPainterPath()
        pill_path.addRoundedRect(QRectF(pill_rect), pill_radius, pill_radius)

        if is_enabled:
            pill_bg = QColor(16, 185, 129, 45)
            pill_border = QColor(16, 185, 129, 130)
            pill_fg = QColor('#34d399')
            pill_text = 'ON'
        else:
            pill_bg = QColor(100, 116, 139, 32)
            pill_border = QColor(100, 116, 139, 95)
            pill_fg = QColor('#94a3b8')
            pill_text = 'OFF'

        painter.fillPath(pill_path, pill_bg)
        painter.setPen(QPen(pill_border, 1.0))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(pill_path)

        # Mini toggle switch icon inside pill
        sw_w = float(scale_by_ui(11))
        sw_h = float(scale_by_ui(7))
        sw_x = float(pill_rect.left() + scale_by_ui(5))
        sw_y = float(pill_rect.top()) + (float(pill_rect.height()) - sw_h) / 2.0
        painter.setPen(QPen(pill_fg, 1.3))
        painter.drawRoundedRect(QRectF(sw_x, sw_y, sw_w, sw_h), sw_h / 2.0, sw_h / 2.0)
        knob_d = max(2.0, sw_h - 3.2)
        knob_x = (sw_x + sw_w - knob_d - 1.6) if is_enabled else (sw_x + 1.6)
        knob_y = sw_y + (sw_h - knob_d) / 2.0
        painter.setBrush(pill_fg)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(QRectF(knob_x, knob_y, knob_d, knob_d))

        pill_font = QFont(base_font)
        pill_font.setPointSizeF(7.5)
        pill_font.setBold(True)
        painter.setFont(pill_font)
        painter.setPen(pill_fg)
        pill_text_left = int(sw_x + sw_w) + scale_by_ui(3)
        pill_text_rect = QRect(pill_text_left, pill_rect.top(), max(0, pill_rect.left() + pill_rect.width() - pill_text_left - scale_by_ui(3)), pill_rect.height())
        painter.drawText(pill_text_rect, Qt.AlignmentFlag.AlignCenter, pill_text)

        # 3. Database Filename
        raw_text = index.data(Qt.ItemDataRole.DisplayRole)
        text = raw_text if isinstance(raw_text, str) else ''
        text_left = dot_x + dot_size + scale_by_ui(7)
        text_w = max(0, pill_rect.left() - scale_by_ui(6) - text_left)
        if text and text_w > 0:
            name_font = QFont(base_font)
            name_font.setStrikeOut(not is_enabled)
            painter.setFont(name_font)
            text_color = (QColor('#ffffff') if is_selected else QColor('#e6edf3')) if is_enabled else (QColor('#94a3b8') if is_selected else QColor('#64748b'))
            painter.setPen(text_color)
            elided = QFontMetrics(name_font).elidedText(text, Qt.TextElideMode.ElideRight, text_w)
            painter.drawText(QRect(text_left, rect.top(), text_w, rect.height()), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, elided)

        painter.restore()


class TreeOperationsMixin(QDialog):
    """Mixin providing tree-panel context menu and file-system operations.

    Expects these attributes on the concrete class:
        _tree, _fs_model, _current_path, _dirty, _model, _open_db_button
    And these methods:
        _set_status, _refresh_stats, _load_database, _update_file_info
    """

    # -- Attribute stubs for type checkers --
    _tree: QTreeView
    _fs_model: QFileSystemModel
    _tree_proxy: UserIPDatabaseTreeSortProxy
    _current_path: Path | None
    _dirty: bool
    _settings_dirty: bool
    _disk_snapshot: str
    _model: QStandardItemModel
    _open_db_button: QPushButton
    _export_selected_action: QAction | None
    _settings_container: QFrame
    _setting_enabled: QCheckBox
    _setting_color: ColorPickerButton
    _db_visual_cache: dict[Path, tuple[int, bool, QColor]]
    _add_button: QPushButton
    _edit_ip_button: QPushButton
    _delete_button: QPushButton
    _delete_tree_button: QPushButton
    _fs_watcher: DebouncedFileWatcher
    _global_search_active: bool
    _global_search_checkbox: QCheckBox
    _last_seen_build_version: int

    if TYPE_CHECKING:
        read_settings_from_widgets: Callable[[], UserIPSettingsModel]

        def _clear_dirty_state(self) -> None: ...
        def _capture_settings_snapshot(self) -> None: ...
        def _refresh_protection_visibility(self) -> None: ...
        def _refresh_stats(self) -> None: ...
        def _update_entry_counts(self) -> None: ...
        def _rebuild_fs_watch(self) -> None: ...
        def _load_all_databases(self) -> None: ...
        def _backup_databases_now(self) -> None: ...
        def _import_database_files(self) -> None: ...
        def _open_backups_folder(self) -> None: ...

        def _save_on_close(self) -> bool:
            raise NotImplementedError

        def _set_status(self, text: str) -> None:
            del text

        def _load_database(self, path: Path) -> None:
            del path

        def _update_file_info(self, path: Path | None) -> None:
            del path

        def _export_database_file(self, path: Path) -> None:
            del path

    def _tree_source_index(self, index: QModelIndex | QPersistentModelIndex) -> QModelIndex:
        """Map a tree proxy *index* back to its source `QFileSystemModel` index."""
        return self._tree_proxy.mapToSource(index) if index.isValid() else QModelIndex()

    def _tree_index_path(self, index: QModelIndex | QPersistentModelIndex) -> Path | None:
        """Return the filesystem `Path` for a tree proxy *index*, or `None` if invalid."""
        source_index = self._tree_source_index(index)
        if not source_index.isValid():
            return None
        file_path_str = self._fs_model.filePath(source_index)
        return Path(file_path_str) if file_path_str else None

    def _tree_index_from_path(self, path: Path) -> QModelIndex:
        """Return the tree proxy `QModelIndex` corresponding to *path*."""
        source_index = self._fs_model.index(str(path))
        return self._tree_proxy.mapFromSource(source_index) if source_index.isValid() else QModelIndex()

    def _invalidate_tree_sort(self) -> None:
        """Re-sort the tree proxy model and preserve the root directory index."""
        self._tree_proxy.invalidate()
        root_index = self._tree_index_from_path(USERIP_DATABASES_DIR_PATH)
        if root_index.isValid() and self._tree.rootIndex() != root_index:
            self._tree.setRootIndex(root_index)

    def _refresh_tree_item_visual(self, path: Path | None = None, *, resort: bool = False) -> None:
        """Invalidate cached tree visual state for *path* (or all paths), optionally re-sort, and repaint."""
        if path is None:
            self._db_visual_cache.clear()
        else:
            self._db_visual_cache.pop(path, None)
        if resort:
            self._invalidate_tree_sort()
        if viewport := self._tree.viewport():
            viewport.update()

    def _refresh_tree_visuals(self) -> None:
        """Clear all cached tree visuals, re-sort the tree proxy, and repaint the tree viewport."""
        self._refresh_tree_item_visual(resort=True)

    def _refresh_after_tree_mutation(self) -> None:
        """Clear cached tree visuals, re-sort the tree, rebuild UserIP state, and re-arm the watcher."""
        self._refresh_tree_item_visual(resort=True)
        refresh_userip_and_wake_renderer()
        self._rebuild_fs_watch()

    def _select_tree_path(self, path: Path) -> None:
        """Select and scroll to *path* in the tree without emitting selection signals."""
        tree_index = self._tree_index_from_path(path)
        selection = self._tree.selectionModel()
        if not tree_index.isValid() or not selection:
            return
        with QSignalBlocker(selection):
            selection.select(tree_index, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)
            self._tree.setCurrentIndex(tree_index)
        self._tree.scrollTo(tree_index)

    def _unwatch_path(self, path: Path) -> None:
        """Remove *path* and any of its descendants from the filesystem watcher."""
        self._fs_watcher.remove_paths([path])

    # ------------------------------------------------------------------
    # Tree selection
    # ------------------------------------------------------------------

    def _configure_delete_tree_button(self, *, enabled: bool, is_reset: bool = False) -> None:
        """Configure the tree toolbar Delete/Reset button state, icon, text, tooltip, and click handler."""
        self._delete_tree_button.setEnabled(enabled)
        if is_reset:
            self._delete_tree_button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh-cw.svg')))
            self._delete_tree_button.setText(' Reset')
            self._delete_tree_button.setToolTip('Reset this default database to factory content')
            self._delete_tree_button.clicked.disconnect()
            self._delete_tree_button.clicked.connect(self._reset_tree_item)
        else:
            self._delete_tree_button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')))
            self._delete_tree_button.setText(' Delete')
            self._delete_tree_button.setToolTip('Delete the selected database or folder')
            self._delete_tree_button.clicked.disconnect()
            self._delete_tree_button.clicked.connect(self._delete_tree_item)

    def _on_tree_selection_changed(self) -> None:
        """Load the selected database when a .json file is clicked in the tree."""
        indexes = self._tree.selectedIndexes()

        if not indexes:
            self._configure_delete_tree_button(enabled=False)
            return

        path = self._tree_index_path(indexes[0])
        if path is None:
            self._configure_delete_tree_button(enabled=True)
            return

        is_default_database = path.parent == USERIP_DATABASES_DIR_PATH and path.name in DEFAULT_USERIP_FILES_SETTINGS
        self._configure_delete_tree_button(enabled=True, is_reset=is_default_database)

        if not path.is_file() or path.suffix.lower() != '.json':
            return

        if path == self._current_path and not self._global_search_active:
            return

        if self._dirty and not self._confirm_discard():
            self._reselect_current_path()
            return

        self._current_path = path
        if self._global_search_active:
            self._global_search_checkbox.setChecked(False)
        else:
            self._load_database(path)
            self._open_db_button.setEnabled(True)
            self._add_button.setEnabled(True)
            if self._export_selected_action is not None:
                self._export_selected_action.setEnabled(True)

    def refresh_runtime_capabilities(self) -> None:
        """Refresh capability-gated controls after runtime feature set / interface changes."""
        if self._global_search_active or self._current_path is None:
            return
        self._refresh_protection_visibility()

    def _reselect_current_path(self) -> None:
        """Revert the tree selection back to the currently loaded database file."""
        if self._current_path is None or not (selection := self._tree.selectionModel()):
            return
        current_index = self._tree_index_from_path(self._current_path)
        if current_index.isValid():
            with QSignalBlocker(selection):
                self._tree.setCurrentIndex(current_index)

    # ------------------------------------------------------------------
    # Discard confirmation
    # ------------------------------------------------------------------

    def _confirm_discard(self) -> bool:
        """Prompt the user to save or discard unsaved changes before switching views."""
        result = QMessageBox.warning(
            self,
            TITLE,
            'You have unsaved changes. Save before switching?',
            QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Save,
        )
        if result == QMessageBox.StandardButton.Save:
            return self._save_on_close()
        return result == QMessageBox.StandardButton.Discard

    # ------------------------------------------------------------------
    # Tree: context menu
    # ------------------------------------------------------------------

    def _refresh_databases_looky(self, db_paths: list[Path]) -> None:
        """Collect all entries from the given database files and refresh their IPs and usernames via Looky System."""
        entries: list[tuple[Path, list[str]]] = []
        for db_path in db_paths:
            if not db_path.is_file() or db_path.suffix.lower() != '.json':
                continue
            db_model = load_userip_database_model(db_path)
            if db_model.entries:
                entries.append((db_path, [entry.ip for entry in db_model.entries]))

        if not entries:
            QMessageBox.information(self, TITLE, f'No entries found in the selected database{pluralize(len(db_paths))}.')
            return

        looky_refresh_userip_entries(self, entries)

    def _get_db_visual_for_path(self, file_path: Path) -> tuple[bool, QColor] | None:
        """Return `(is_enabled, color)` for a `.json` database path, or `None` for non-databases."""
        if file_path.suffix.lower() != '.json':
            return None
        if file_path == self._current_path and not self._global_search_active:
            return self._setting_enabled.isChecked(), QColor(self._setting_color.color())
        try:
            mtime_ns = file_path.stat().st_mtime_ns
        except OSError:
            return None
        cached = self._db_visual_cache.get(file_path)
        if cached is not None and cached[0] == mtime_ns:
            return cached[1], cached[2]
        settings = load_userip_database_model(file_path).settings
        color = QColor(settings.COLOR)
        self._db_visual_cache[file_path] = (mtime_ns, settings.ENABLED, color)
        return settings.ENABLED, color

    def _is_database_path_enabled(self, file_path: Path) -> bool:
        """Return whether the `.json` database at *file_path* is enabled."""
        visual = self._get_db_visual_for_path(file_path)
        return visual[0] if visual is not None else True

    def _get_tree_index_db_visual(self, index: QModelIndex | QPersistentModelIndex) -> tuple[bool, QColor] | None:
        """Return `(is_enabled, color)` for a `.json` database tree index, or `None` for folders/non-databases."""
        source_index = self._tree_source_index(index)
        if not source_index.isValid() or self._fs_model.isDir(source_index):
            return None
        file_path_str = self._fs_model.filePath(source_index)
        return self._get_db_visual_for_path(Path(file_path_str)) if file_path_str else None

    def _toggle_tree_index_db(self, index: QModelIndex | QPersistentModelIndex) -> None:
        """Toggle the enabled state of the `.json` database at *index*."""
        visual = self._get_tree_index_db_visual(index)
        path = self._tree_index_path(index)
        if visual is not None and path is not None:
            self._set_database_enabled(path, enabled=not visual[0])

    def _set_database_enabled(self, path: Path, *, enabled: bool) -> None:
        """Enable or disable the UserIP database at *path* and persist the setting."""
        if not path.is_file() or path.suffix.lower() != '.json':
            return
        is_current = path == self._current_path and not self._global_search_active
        if is_current:
            self._setting_enabled.setChecked(enabled)
        if not is_current or self._settings_dirty:
            db_model = load_userip_database_model(path)
            if is_current:
                db_model.settings = self.read_settings_from_widgets()
            else:
                db_model.settings.ENABLED = enabled
            with QSignalBlocker(self._fs_watcher):
                save_userip_database_model(path, db_model)
                refresh_userip_and_wake_renderer()
            self._last_seen_build_version = UserIPDatabases.build_version
            if is_current:
                self._disk_snapshot = path.read_text('utf-8')
                self._capture_settings_snapshot()
            self._rebuild_fs_watch()
        self._refresh_tree_item_visual(path, resort=not is_current)
        self._set_status(f'{"Enabled" if enabled else "Disabled"} database: {path.name}')

    def _show_tree_context_menu(self, position: QPoint) -> None:
        """Show a right-click context menu for the file tree."""
        index = self._tree.indexAt(position)
        file_path = self._tree_index_path(index)
        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)

        if file_path is not None:

            if file_path.is_dir():
                new_db_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'file-plus.svg')), 'New Database Here', self)
                new_db_action.triggered.connect(lambda: self._new_database(parent_dir=file_path))
                menu.addAction(new_db_action)

                new_folder_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'New Folder Here', self)
                new_folder_action.triggered.connect(lambda: self._new_folder(parent_dir=file_path))
                menu.addAction(new_folder_action)

                if Settings.is_gta5_feature_set() and CaptureState.is_local_capture():
                    menu.addSeparator()
                    _dir_path = file_path
                    refresh_dir_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg')), 'Refresh Folder (Looky System)', self)
                    refresh_dir_action.triggered.connect(lambda: self._refresh_databases_looky(list(_dir_path.rglob('*.json'))))
                    configure_looky_action(
                        refresh_dir_action,
                        'Scan all IPs and usernames in this folder via Looky System to confirm existing entries and discover new IPs or usernames.',
                    )
                    menu.addAction(refresh_dir_action)

                menu.addSeparator()

            move_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'box.svg')), 'Move to...', self)
            move_action.triggered.connect(lambda: self._move_tree_item(file_path))
            menu.addAction(move_action)

            rename_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'square-pen.svg')), 'Rename', self)
            rename_action.triggered.connect(lambda: self._rename_tree_item(file_path))
            menu.addAction(rename_action)

            menu.addSeparator()

            explorer_target = file_path
            open_explorer_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'Open in File Manager', self)
            open_explorer_action.triggered.connect(lambda: open_file_location(explorer_target))
            menu.addAction(open_explorer_action)

            if file_path.is_file():
                open_editor_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'file-text.svg')), 'Open in Text Editor', self)
                open_editor_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(file_path))))
                menu.addAction(open_editor_action)

                menu.addSeparator()

                if file_path.suffix.lower() == '.json' and Settings.is_gta5_feature_set() and CaptureState.is_local_capture():
                    _file_path = file_path
                    is_searchlist = file_path.stem.casefold() == 'searchlist'
                    refresh_label = 'Verify && Clean Searchlist (Looky)' if is_searchlist else 'Refresh Database (Looky System)'
                    refresh_tooltip = (
                        'Verify candidate IPs and usernames in Searchlist via Looky System, find real IPs, and remove wrong candidate IPs.'
                        if is_searchlist
                        else 'Scan all IPs and usernames in this database via Looky System to confirm existing entries and discover new IPs or usernames.'
                    )
                    refresh_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg')), refresh_label, self)
                    refresh_action.triggered.connect(lambda: self._refresh_databases_looky([_file_path]))
                    configure_looky_action(refresh_action, refresh_tooltip)
                    menu.addAction(refresh_action)
                    menu.addSeparator()

                export_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'upload.svg')), 'Export Database…', self)
                export_action.triggered.connect(lambda: self._export_database_file(file_path))
                menu.addAction(export_action)

            menu.addSeparator()

            if file_path.parent == USERIP_DATABASES_DIR_PATH and file_path.name in DEFAULT_USERIP_FILES_SETTINGS:
                reset_default_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh-cw.svg')), 'Reset', self)
                reset_default_action.triggered.connect(lambda: self._reset_default_database(file_path))
                menu.addAction(reset_default_action)
            else:
                delete_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), 'Delete', self)
                delete_action.triggered.connect(lambda: self._delete_path(file_path))
                menu.addAction(delete_action)
        else:
            new_db_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'file-plus.svg')), 'New Database', self)
            new_db_action.triggered.connect(self._new_database)
            menu.addAction(new_db_action)

            new_folder_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'New Folder', self)
            new_folder_action.triggered.connect(self._new_folder)
            menu.addAction(new_folder_action)

            if Settings.is_gta5_feature_set() and CaptureState.is_local_capture():
                menu.addSeparator()
                refresh_all_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg')), 'Refresh All Databases (Looky)', self)
                refresh_all_action.triggered.connect(lambda: self._refresh_databases_looky(list(USERIP_DATABASES_DIR_PATH.rglob('*.json'))))
                configure_looky_action(
                    refresh_all_action,
                    'Scan all IPs and usernames across all UserIP databases via Looky System to confirm existing entries and discover new IPs or usernames.',
                )
                menu.addAction(refresh_all_action)

            menu.addSeparator()

            import_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'import.svg')), 'Import Database Files…', self)
            import_action.triggered.connect(self._import_database_files)
            menu.addAction(import_action)

            menu.addSeparator()

            backup_now_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'upload.svg')), 'Backup Databases Now', self)
            backup_now_action.triggered.connect(self._backup_databases_now)
            menu.addAction(backup_now_action)

            open_backups_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'Open Backups Folder', self)
            open_backups_action.triggered.connect(self._open_backups_folder)
            menu.addAction(open_backups_action)

        viewport = self._tree.viewport()
        if viewport:
            menu.popup(viewport.mapToGlobal(position))

    # ------------------------------------------------------------------
    # Tree operations
    # ------------------------------------------------------------------

    def _get_selected_tree_directory(self) -> Path:
        """Return the directory of the currently selected tree item, or the root."""
        indexes = self._tree.selectedIndexes()
        if indexes and (item_path := self._tree_index_path(indexes[0])) is not None:
            return item_path if item_path.is_dir() else item_path.parent
        return USERIP_DATABASES_DIR_PATH

    def _new_database(self, *, parent_dir: Path | None = None) -> None:
        """Create a new UserIP database .json file."""
        target_dir = parent_dir or self._get_selected_tree_directory()

        name, success = QInputDialog.getText(self, TITLE, 'New database name:')
        if not success or not name.strip():
            return

        name = name.strip()
        if name.lower().endswith('.json'):
            name = name[:-5]
        if not name:
            return
        name += '.json'

        new_path = target_dir / name
        if new_path.exists():
            QMessageBox.warning(self, TITLE, f'"{name}" already exists in that location.')
            return

        save_userip_database_model(new_path, UserIPDatabaseFile(settings=NEW_DATABASE_SETTINGS))
        refresh_userip_and_wake_renderer()
        self._rebuild_fs_watch()

        self._set_status(f'Created new database: {name}')
        self._refresh_stats()

    def _new_folder(self, *, parent_dir: Path | None = None) -> None:
        """Create a new folder inside the databases directory."""
        target_dir = parent_dir or self._get_selected_tree_directory()

        name, success = QInputDialog.getText(self, TITLE, 'New folder name:')
        if not success or not name.strip():
            return

        folder_name = name.strip()
        new_path = target_dir / folder_name
        if new_path.exists():
            QMessageBox.warning(self, TITLE, f'"{folder_name}" already exists in that location.')
            return

        new_path.mkdir(parents=True, exist_ok=True)

        self._set_status(f'Created new folder: {folder_name}')

    def _delete_tree_item(self) -> None:
        """Delete the currently selected item in the file tree."""
        indexes = self._tree.selectedIndexes()
        if not indexes or (path := self._tree_index_path(indexes[0])) is None:
            QMessageBox.information(self, TITLE, 'No item selected in the tree.')
            return

        self._delete_path(path)

    def _reset_tree_item(self) -> None:
        """Reset the currently selected default database to factory content."""
        indexes = self._tree.selectedIndexes()
        if not indexes or (path := self._tree_index_path(indexes[0])) is None:
            return

        self._reset_default_database(path)

    def _clear_open_database_view(self) -> None:
        """Clear the currently open single-database view and disable its editing controls."""
        self._current_path = None
        self._clear_dirty_state()
        self._model.removeRows(0, self._model.rowCount())
        self._update_file_info(None)
        self._settings_container.setVisible(False)
        self._add_button.setEnabled(False)
        self._edit_ip_button.setEnabled(False)
        self._delete_button.setEnabled(False)
        self._open_db_button.setEnabled(False)
        if self._export_selected_action is not None:
            self._export_selected_action.setEnabled(False)
        self._update_entry_counts()

    def _rebind_current_path_and_refresh(self, old_path: Path, new_path: Path) -> None:
        """Update `_current_path` when *old_path* (or an ancestor) was renamed/moved to *new_path*, then refresh."""
        if self._current_path is not None:
            if self._current_path == old_path:
                self._current_path = new_path
                if not self._global_search_active:
                    self._update_file_info(self._current_path)
            elif old_path in self._current_path.parents:
                self._current_path = new_path / self._current_path.relative_to(old_path)
                if not self._global_search_active:
                    self._update_file_info(self._current_path)
        self._refresh_after_tree_mutation()
        if self._global_search_active:
            self._load_all_databases()

    def _delete_path(self, path: Path) -> None:
        """Delete a file or folder with user confirmation."""
        if path.is_dir():
            children = list(path.iterdir())
            message = (
                f'Folder "{path.name}" is not empty ({len(children)} item{pluralize(len(children))}).\n\nDelete it and all its contents?'
                if children
                else f'Delete empty folder "{path.name}"?'
            )
        else:
            message = f'Delete database "{path.name}"?'

        result = QMessageBox.warning(self, TITLE, message, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if result != QMessageBox.StandardButton.Yes:
            return

        self._unwatch_path(path)

        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()

        self._db_visual_cache.clear()
        refresh_userip_and_wake_renderer()

        if self._global_search_active:
            if self._current_path is not None and (self._current_path == path or path in self._current_path.parents):
                self._current_path = None
            self._load_all_databases()
        elif self._current_path is not None and (self._current_path == path or path in self._current_path.parents):
            self._clear_open_database_view()

        self._rebuild_fs_watch()
        self._set_status(f'Deleted: {path.name}')
        self._refresh_stats()

    def _reset_default_database(self, path: Path) -> None:
        """Reset a single default database file to its factory content after user confirmation."""
        prompt = f'Reset "{path.name}" to factory content?\n\nAll entries and settings in this file will be lost.'
        result = QMessageBox.warning(self, TITLE, prompt, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if result != QMessageBox.StandardButton.Yes:
            return

        save_userip_database_model(path, UserIPDatabaseFile(settings=DEFAULT_USERIP_FILES_SETTINGS[path.name]))
        self._refresh_tree_item_visual(path, resort=True)
        refresh_userip_and_wake_renderer()

        if self._global_search_active:
            self._load_all_databases()
            self._rebuild_fs_watch()
        elif self._current_path == path:
            self._load_database(path)
        else:
            self._rebuild_fs_watch()

        self._set_status(f'Reset "{path.name}" to factory defaults.')
        self._refresh_stats()

    def _rename_tree_item(self, path: Path) -> None:
        """Rename a file or folder via an input dialog."""
        old_name = path.stem if path.is_file() else path.name
        label = 'New name:' if path.is_file() else 'New folder name:'

        new_name, success = QInputDialog.getText(self, TITLE, label, QLineEdit.EchoMode.Normal, old_name)
        if not success or not new_name.strip():
            return

        new_name = new_name.strip()
        if path.is_file():
            if new_name.lower().endswith('.json'):
                new_name = new_name[:-5]
            if not new_name:
                return
            new_name += '.json'

        new_path = path.parent / new_name
        if new_path.exists():
            QMessageBox.warning(self, TITLE, f'"{new_name}" already exists.')
            return

        # Use the model's rename to avoid file-watcher handle conflicts on Windows
        index = self._fs_model.index(str(path))
        if not index.isValid() or not self._fs_model.setData(index, new_name, Qt.ItemDataRole.EditRole):
            QMessageBox.critical(self, TITLE, f'Failed to rename "{path.name}".')
            return

        self._rebind_current_path_and_refresh(path, new_path)
        self._set_status(f'Renamed "{path.name}" → "{new_name}"')

    def _move_tree_item(self, path: Path) -> None:
        """Move a file or folder to a different directory via a folder picker."""
        target_dir = QFileDialog.getExistingDirectory(self, f'Move "{path.name}" to...', str(USERIP_DATABASES_DIR_PATH))
        if not target_dir:
            return

        dest = Path(target_dir)

        # Ensure the destination is within the databases root
        try:
            rel_dest = dest.relative_to(USERIP_DATABASES_DIR_PATH)
        except ValueError:
            QMessageBox.warning(self, TITLE, 'Destination must be within the UserIP Databases directory.')
            return

        if dest == path or path in dest.parents:
            QMessageBox.warning(self, TITLE, f'Cannot move "{path.name}" into itself.')
            return

        new_path = dest / path.name
        if new_path.exists():
            QMessageBox.warning(self, TITLE, f'"{path.name}" already exists in the destination folder.')
            return

        self._unwatch_path(path)
        shutil.move(str(path), str(new_path))
        self._rebind_current_path_and_refresh(path, new_path)
        dest_label = 'root' if rel_dest == Path() else str(rel_dest)
        self._set_status(f'Moved "{path.name}" → {dest_label}')

    def _reset_all_databases(self) -> None:
        """Delete every .json database file in the databases directory after user confirmation.

        Default databases (Blacklist, Enemylist, etc.) are restored to their factory content
        rather than deleted.  User-created .json files and subdirectories are removed entirely.
        """
        USERIP_DATABASES_DIR_PATH.mkdir(parents=True, exist_ok=True)
        json_files = sorted(USERIP_DATABASES_DIR_PATH.rglob('*.json'))
        if not json_files:
            QMessageBox.information(self, TITLE, 'There are no database files to reset.')
            return

        count = len(json_files)
        prompt = (
            f'This will permanently reset all {count} database file{pluralize(count)}.\n\n'
            'Default databases will be restored to factory content.\nUser-created databases will be deleted.\n\nThis cannot be undone. Are you sure?'
        )
        result = QMessageBox.warning(self, TITLE, prompt, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if result != QMessageBox.StandardButton.Yes:
            return

        default_db_names: set[str] = set(DEFAULT_USERIP_FILES_SETTINGS.keys())

        deleted = 0
        restored = 0
        for json_path in json_files:
            if json_path.parent == USERIP_DATABASES_DIR_PATH and json_path.name in default_db_names:
                save_userip_database_model(json_path, UserIPDatabaseFile(settings=DEFAULT_USERIP_FILES_SETTINGS[json_path.name]))
                restored += 1
            else:
                try:
                    json_path.unlink()
                    deleted += 1
                except OSError as e:
                    logger.warning('Failed to delete user database file %s: %s', json_path, e)

        # Remove user-created subdirectories
        for entry in USERIP_DATABASES_DIR_PATH.iterdir():
            if entry.is_dir():
                self._unwatch_path(entry)
                try:
                    shutil.rmtree(entry)
                except OSError as e:
                    logger.warning('Failed to remove user database directory %s: %s', entry, e)

        self._refresh_tree_item_visual(resort=True)
        refresh_userip_and_wake_renderer()
        self._refresh_stats()

        if self._global_search_active:
            self._load_all_databases()
            self._rebuild_fs_watch()
        elif self._current_path is not None:
            if self._current_path.is_file():
                self._load_database(self._current_path)
            else:
                self._clear_open_database_view()
                self._rebuild_fs_watch()
        else:
            self._rebuild_fs_watch()

        restored_part = f'  |  Restored {restored} default file{pluralize(restored)}' if restored else ''
        deleted_part = f'  |  Deleted {deleted} user file{pluralize(deleted)}' if deleted else ''
        self._set_status(f'Reset complete{restored_part}{deleted_part}')
