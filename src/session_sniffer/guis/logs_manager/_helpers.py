"""Shared constants and helper functions for the Logs Manager dialog."""

import shutil
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast, override

from PySide6.QtCore import QModelIndex, QPersistentModelIndex, QSortFilterProxyModel, QTimer, QUrl
from PySide6.QtGui import (
    QColor,
    QDesktopServices,
    QFont,
    QIcon,
    QStandardItemModel,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextCursor,
    QTextDocument,
)
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import CRASH_LOG_PATH, DEBUG_LOG_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.guis.fonts import get_monospace_font
from session_sniffer.guis.live_language import register_language_refresh, set_i18n_colon_label
from session_sniffer.guis.loading_overlay import run_blocking_with_loading
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET
from session_sniffer.guis.theming import ICONS_DIR_PATH, themed_qcolor, themed_text_qcolor
from session_sniffer.guis.userip_manager_helpers import BYTES_PER_UNIT, human_readable_size
from session_sniffer.guis.utils import (
    animate_button_feedback,
    apply_search_icon,
    open_file_location,
    set_clipboard_text,
)
from session_sniffer.i18n import tr
from session_sniffer.logging_setup import purge_crash_log, purge_debug_log

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path
    from typing import Any

MAX_CSV_ROWS = 50_000
LARGE_TEXT_FILE_LIMIT = 5 * BYTES_PER_UNIT * BYTES_PER_UNIT  # 5 MB
_DAYS_IN_WEEK = 7
_ISO_DATE_LENGTH = 10
_MAX_HIGHLIGHT_SELECTIONS = 2_500

DATE_COLUMN_NAME = 'Date'

_DATE_FILTER_ALL = 'All'
DATE_FILTER_TODAY = 'Today'
DATE_FILTER_7_DAYS = 'Last 7 Days'
DATE_FILTER_30_DAYS = 'Last 30 Days'

DATE_FILTER_CHOICES = (
    _DATE_FILTER_ALL,
    DATE_FILTER_TODAY,
    DATE_FILTER_7_DAYS,
    DATE_FILTER_30_DAYS,
)


def human_readable_timestamp(dt: datetime) -> str:
    """Convert a datetime to a human-friendly relative string like 'Today at 9:23 PM'."""
    now = datetime.now(tz=dt.tzinfo)
    today = now.date()
    dt_date = dt.date()
    time_str = dt.strftime('%I:%M %p').lstrip('0')

    delta_days = (today - dt_date).days
    if not delta_days:
        return tr('Today at {time}', time=time_str)
    if delta_days == 1:
        return tr('Yesterday at {time}', time=time_str)
    if delta_days < _DAYS_IN_WEEK:
        return tr('{weekday} at {time}', weekday=dt.strftime('%A'), time=time_str)
    return tr('{date} at {time}', date=dt.strftime('%b %d, %Y'), time=time_str)


def file_metadata_text(file_path: Path) -> str:
    """Build a metadata summary string for a file."""
    if not file_path.exists():
        return tr('{filename}  —  File not found', filename=file_path.name)
    stat = file_path.stat()
    size = human_readable_size(stat.st_size)
    modified = datetime.fromtimestamp(stat.st_mtime, tz=UTC).astimezone()
    return tr('{filename}  |  {size}  |  Last modified: {timestamp}', filename=file_path.name, size=size, timestamp=human_readable_timestamp(modified))


def backup_file(file_path: Path) -> Path | None:
    """Create a .bak backup of a file. Returns backup path or `None` on failure."""
    if not file_path.exists():
        return None
    backup_path = file_path.with_suffix(file_path.suffix + '.bak')
    try:
        shutil.copy2(file_path, backup_path)
    except OSError:
        return None
    return backup_path


def backup_and_truncate_log_file(file_path: Path) -> Path | None:
    """Create a `.bak` backup of *file_path* and truncate or reset its contents."""
    backup_path = backup_file(file_path)
    if file_path == DEBUG_LOG_PATH:
        purge_debug_log()
    elif file_path == CRASH_LOG_PATH:
        purge_crash_log()
    else:
        file_path.write_text('', encoding='utf-8')
    return backup_path


# ---------------------------------------------------------------------------
# Log-level syntax highlighter for plain-text log viewers
# ---------------------------------------------------------------------------


class LogLevelHighlighter(QSyntaxHighlighter):
    """Highlight WARNING / ERROR / CRITICAL lines in a plain-text log."""

    def __init__(self, document: QTextDocument) -> None:
        super().__init__(document)

        self._log_level_formats: list[tuple[str, QTextCharFormat]] = []

        warning_format = QTextCharFormat()
        warning_format.setForeground(themed_text_qcolor('#e5c07b', '#1e1e1e'))
        self._log_level_formats.append(('WARNING', warning_format))

        error_format = QTextCharFormat()
        error_format.setForeground(themed_text_qcolor('#e06c75', '#1e1e1e'))
        error_format.setFontWeight(QFont.Weight.Bold)
        self._log_level_formats.append(('ERROR', error_format))

        critical_format = QTextCharFormat()
        critical_format.setForeground(themed_text_qcolor('#ff6b6b', '#501414'))
        critical_format.setFontWeight(QFont.Weight.Bold)
        critical_format.setBackground(themed_qcolor(QColor(80, 20, 20)))
        self._log_level_formats.append(('CRITICAL', critical_format))

    @override
    def highlightBlock(self, text: str | None) -> None:
        """Apply log-level coloring to a single text block."""
        if text is None:
            return

        for keyword, text_format in self._log_level_formats:
            if keyword in text:
                self.setFormat(0, len(text), text_format)
                return


# ---------------------------------------------------------------------------
# Multi-column filter proxy for CSV tables
# ---------------------------------------------------------------------------


class MultiColumnFilterProxy(QSortFilterProxyModel):
    """Proxy model that filters rows by text match across a specific column or all columns."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._filter_column: int = -1  # -1 means all columns
        self._date_column: int = -1
        self._date_cutoff: datetime | None = None
        self._date_cutoff_iso: str | None = None
        self._filter_text_lower: str = ''
        self._rows_raw: list[tuple[str, ...]] = []
        self._rows_lower: list[tuple[str, ...]] = []
        self._rows_joined_lower: list[str] = []
        self._accepted_rows: set[int] | None = None

    def set_source_rows(self, rows: Sequence[Sequence[str]]) -> None:
        """Populate pre-indexed row cells so filtering runs in pure Python without per-cell Qt calls."""
        self._rows_raw = [tuple(row) for row in rows]
        self._rows_lower = [tuple(cell.lower() for cell in row) for row in rows]
        self._rows_joined_lower = ['\x00'.join(row_lower) for row_lower in self._rows_lower]
        self._recompute_accepted_rows()

    def remove_source_rows(self, sorted_descending_rows: Sequence[int]) -> None:
        """Remove deleted source row indices (in descending order) from the pre-indexed row cache."""
        for row_idx in sorted_descending_rows:
            if 0 <= row_idx < len(self._rows_raw):
                del self._rows_raw[row_idx]
                del self._rows_lower[row_idx]
                del self._rows_joined_lower[row_idx]
        self._recompute_accepted_rows()

    def _ensure_rows_indexed(self) -> None:
        source_model = self.sourceModel()
        if not isinstance(source_model, QStandardItemModel):
            return
        row_count = source_model.rowCount()
        if len(self._rows_raw) == row_count:
            return
        col_count = source_model.columnCount()
        raw_rows = [
            tuple((item.text() if (item := source_model.item(r, c)) else '') for c in range(col_count))
            for r in range(row_count)
        ]
        self.set_source_rows(raw_rows)

    def _row_passes_date_filter(self, date_text: str) -> bool:
        if self._date_cutoff is None:
            return True
        if self._date_cutoff_iso is not None and len(date_text) == _ISO_DATE_LENGTH and date_text[4] == '-' and date_text[7] == '-':
            return date_text >= self._date_cutoff_iso
        try:
            row_date = datetime.strptime(date_text, '%Y-%m-%d').replace(tzinfo=LOCAL_TZ)
        except ValueError:
            return True
        return row_date >= self._date_cutoff

    def _recompute_accepted_rows(self) -> None:
        has_date_filter = self._date_cutoff is not None and self._date_column >= 0
        query = self._filter_text_lower
        if not has_date_filter and not query:
            self._accepted_rows = None
            return

        self._ensure_rows_indexed()
        filter_col = self._filter_column
        date_col = self._date_column
        rows_raw = self._rows_raw
        rows_lower = self._rows_lower
        rows_joined = self._rows_joined_lower
        accepted: set[int] = set()

        for row_idx, lower_row in enumerate(rows_lower):
            if has_date_filter:
                raw_row = rows_raw[row_idx]
                if date_col < len(raw_row) and not self._row_passes_date_filter(raw_row[date_col]):
                    continue
            if query:
                if filter_col >= 0:
                    if filter_col >= len(lower_row) or query not in lower_row[filter_col]:
                        continue
                elif query not in rows_joined[row_idx]:
                    continue
            accepted.add(row_idx)

        self._accepted_rows = accepted

    @override
    def setFilterFixedString(self, pattern: str) -> None:
        """Update the case-insensitive substring filter and recompute accepted rows."""
        lowered = pattern.lower()
        if lowered == self._filter_text_lower:
            return
        self._filter_text_lower = lowered
        self._recompute_accepted_rows()
        self.invalidateFilter()

    def set_filter_column(self, column: int) -> None:
        """Set which column to filter on (-1 for all)."""
        if column == self._filter_column:
            return
        self._filter_column = column
        self._recompute_accepted_rows()
        self.invalidateFilter()

    def set_date_filter(self, date_column: int, cutoff: datetime | None) -> None:
        """Set an optional date-range cutoff on a specific column."""
        self._date_column = date_column
        self._date_cutoff = cutoff
        self._date_cutoff_iso = cutoff.strftime('%Y-%m-%d') if cutoff is not None else None
        self._recompute_accepted_rows()
        self.invalidateFilter()

    @override
    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex | QPersistentModelIndex) -> bool:
        """Determine whether a source row passes the current text and date filters."""
        _ = source_parent
        if self._accepted_rows is None:
            return True
        return source_row in self._accepted_rows


# ---------------------------------------------------------------------------
# Reusable widget / action helpers shared across log-tab types
# ---------------------------------------------------------------------------


def create_log_viewer() -> QPlainTextEdit:
    """Return a read-only, monospace QPlainTextEdit configured for log display."""
    viewer = QPlainTextEdit()
    viewer.setReadOnly(True)
    mono_font = get_monospace_font(9)
    mono_font.setFixedPitch(True)
    viewer.setFont(mono_font)
    viewer.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    return viewer


def create_search_input(
    top_bar: QHBoxLayout,
    placeholder: str,
    on_changed: Callable[[str], None],
    *,
    debounce_ms: int = 0,
) -> QLineEdit:
    """Add a labelled search QLineEdit to *top_bar* and return it."""
    search_label = QLabel()
    set_i18n_colon_label(search_label, 'Search')
    top_bar.addWidget(search_label)
    search_input = QLineEdit()
    search_input.setPlaceholderText(placeholder)
    if debounce_ms > 0:
        debounce_timer = QTimer(search_input)
        debounce_timer.setSingleShot(True)
        debounce_timer.setInterval(debounce_ms)
        debounce_timer.timeout.connect(lambda: on_changed(search_input.text()))

        def _handle_text_changed(text: str) -> None:
            if not text:
                debounce_timer.stop()
                on_changed('')
            else:
                debounce_timer.start()

        search_input.textChanged.connect(_handle_text_changed)
    else:
        search_input.textChanged.connect(on_changed)
    apply_search_icon(search_input)
    top_bar.addWidget(search_input, stretch=1)
    return search_input


def add_purge_and_location_buttons(
    layout: QHBoxLayout,
    purge_fn: Callable[[], None],
    file_path: Path,
    *,
    add_stretch: bool = True,
) -> tuple[QPushButton, QPushButton]:
    """Append Purge File → Open File Location → Open File buttons to *layout*."""
    if add_stretch:
        layout.addStretch()

    purge_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), '')
    purge_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
    purge_button.setEnabled(file_path.is_file() and file_path.stat().st_size > 0)
    purge_button.clicked.connect(purge_fn)
    layout.addWidget(purge_button)

    open_location_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'folder.svg')), '')
    open_location_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    open_location_button.clicked.connect(lambda: open_file_location(file_path))
    layout.addWidget(open_location_button)

    open_file_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'file-text.svg')), '')
    open_file_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    open_file_button.setEnabled(file_path.is_file())
    open_file_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(file_path))))
    layout.addWidget(open_file_button)

    def _apply_button_texts() -> None:
        purge_button.setText(f" {tr('Purge File')}")
        purge_button.setToolTip(tr('Clear all contents from this log file (creates a backup first)'))
        open_location_button.setText(f" {tr('Open Folder Location')}" if file_path.is_dir() else f" {tr('Open File Location')}")
        open_location_button.setToolTip(tr('Open the containing folder in your file manager'))
        open_file_button.setText(f" {tr('Open File')}")
        open_file_button.setToolTip(tr('Open the log file in the default text editor'))

    _apply_button_texts()
    register_language_refresh(open_location_button, _apply_button_texts)

    return purge_button, open_file_button


def purge_log_file(
    parent: QWidget,
    file_path: Path,
    *,
    item_label: str = 'contents',
) -> str | None:
    """Confirm and purge *file_path*; return a status message or None if cancelled/missing."""
    if not file_path.exists():
        QMessageBox.information(parent, TITLE, tr('{filename} does not exist.', filename=file_path.name))
        return None
    if file_path.is_file() and not file_path.stat().st_size:
        return None
    confirm_text = (
        tr('Purge ALL entries from {filename}?\n\nA backup (.bak) will be created first.\nThis cannot be undone.', filename=file_path.name)
        if item_label == 'entries'
        else tr('Purge ALL contents from {filename}?\n\nA backup (.bak) will be created first.\nThis cannot be undone.', filename=file_path.name)
    )
    reply = QMessageBox.warning(
        parent,
        TITLE,
        confirm_text,
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
    )
    if reply != QMessageBox.StandardButton.Yes:
        return None
    try:
        bak = (
            run_blocking_with_loading(
                parent.window(),
                tr('Purging Log\u2026'),
                tr('Creating backup and clearing {filename}\u2026', filename=file_path.name),
                lambda: backup_and_truncate_log_file(file_path),
            )
            if parent.isVisible()
            else backup_and_truncate_log_file(file_path)
        )
    except OSError as e:
        QMessageBox.warning(parent, TITLE, tr('Failed to purge {filename}:\n{error}', filename=file_path.name, error=e))
        return None
    if bak:
        return tr('Purged {filename}.\nBackup saved to {backup}', filename=file_path.name, backup=bak.name)
    return tr('Purged {filename}.', filename=file_path.name)


def copy_viewer_text_to_clipboard(viewer: QPlainTextEdit) -> bool:
    """Copy the plain text from *viewer* to the clipboard and return whether text was copied."""
    text = viewer.toPlainText()
    if not text:
        return False
    set_clipboard_text(text)
    return True


def setup_metadata_label(layout: QVBoxLayout) -> QLabel:
    """Add an empty metadata QLabel to *layout* and return it."""
    label = QLabel('')
    layout.addWidget(label)
    return label


def setup_copy_save_button_row(
    layout: QVBoxLayout,
    copy_fn: Callable[[], bool],
    save_fn: Callable[[], None],
    *,
    copy_tooltip: str | None = None,
    save_tooltip: str | None = None,
) -> tuple[QHBoxLayout, QPushButton, QPushButton]:
    """Create a button row with Copy All and Save As buttons, add it to *layout*, and return it with the buttons."""
    button_row = QHBoxLayout()
    resolved_copy_tip = tr('Copy all displayed text to clipboard') if copy_tooltip is None else copy_tooltip
    resolved_save_tip = tr('Save the displayed content to a new file') if save_tooltip is None else save_tooltip

    copy_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'copy.svg')), f" {tr('Copy All')}")
    copy_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    copy_button.setToolTip(resolved_copy_tip)
    copy_button.setEnabled(False)

    def _on_copy_clicked() -> None:
        if copy_fn():
            animate_button_feedback(copy_button, feedback_text=f" {tr('Copied!')}", feedback_tooltip=tr('Copied to clipboard!'))

    copy_button.clicked.connect(_on_copy_clicked)
    button_row.addWidget(copy_button)

    save_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'save.svg')), f" {tr('Save As...')}")
    save_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    save_button.setToolTip(resolved_save_tip)
    save_button.setEnabled(False)
    save_button.clicked.connect(save_fn)
    button_row.addWidget(save_button)

    layout.addLayout(button_row)
    return button_row, copy_button, save_button


def prepare_search(text: str, match_label: QLabel, viewer: QPlainTextEdit) -> QTextDocument | None:
    """Clear highlights if *text* is empty and return the viewer document (or None to abort).

    Returns the document when *text* is non-empty and the document is available;
    returns None in all other cases (caller should return early).
    """
    if not text:
        match_label.setText('')
        viewer.setExtraSelections([])
        return None
    document = viewer.document()
    return document or None


def find_and_highlight_matches(document: QTextDocument, text: str, viewer: QPlainTextEdit) -> list[QTextCursor]:
    """Find all occurrences of *text* in *document*, apply yellow highlight selections to *viewer*, and return the match cursors."""
    matched_cursors: list[QTextCursor] = []
    cursor = document.find(text)
    while not cursor.isNull():
        matched_cursors.append(QTextCursor(cursor))
        cursor = document.find(text, cursor)

    highlight_format = QTextCharFormat()
    highlight_format.setBackground(themed_qcolor('#e3b341'))
    highlight_format.setForeground(themed_text_qcolor('#000000', '#e3b341'))

    selections: list[Any] = []
    for match_cursor in matched_cursors[:_MAX_HIGHLIGHT_SELECTIONS]:
        selection = cast('Any', QTextEdit.ExtraSelection())
        selection.cursor = match_cursor
        selection.format = highlight_format
        selections.append(selection)
    viewer.setExtraSelections(selections)
    return matched_cursors
