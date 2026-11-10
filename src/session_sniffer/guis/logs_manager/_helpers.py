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

from session_sniffer.constants.local import CRASH_LOG_PATH, DEBUG_LOG_PATH, RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.guis.fonts import get_monospace_font
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET
from session_sniffer.guis.userip_manager_helpers import BYTES_PER_UNIT, human_readable_size
from session_sniffer.guis.utils import (
    animate_button_feedback,
    apply_search_icon,
    open_file_location,
    set_clipboard_text,
)
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
        return f'Today at {time_str}'
    if delta_days == 1:
        return f'Yesterday at {time_str}'
    if delta_days < _DAYS_IN_WEEK:
        return f'{dt.strftime("%A")} at {time_str}'
    return f'{dt.strftime("%b %d, %Y")} at {time_str}'


def file_metadata_text(file_path: Path) -> str:
    """Build a metadata summary string for a file."""
    if not file_path.exists():
        return f'{file_path.name}  —  File not found'
    stat = file_path.stat()
    size = human_readable_size(stat.st_size)
    modified = datetime.fromtimestamp(stat.st_mtime, tz=UTC).astimezone()
    return f'{file_path.name}  |  {size}  |  Last modified: {human_readable_timestamp(modified)}'


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
        warning_format.setForeground(QColor('#e5c07b'))
        self._log_level_formats.append(('WARNING', warning_format))

        error_format = QTextCharFormat()
        error_format.setForeground(QColor('#e06c75'))
        error_format.setFontWeight(QFont.Weight.Bold)
        self._log_level_formats.append(('ERROR', error_format))

        critical_format = QTextCharFormat()
        critical_format.setForeground(QColor('#ff6b6b'))
        critical_format.setFontWeight(QFont.Weight.Bold)
        critical_format.setBackground(QColor(80, 20, 20))
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
    top_bar.addWidget(QLabel('Search:'))
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

    purge_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), ' Purge File')
    purge_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
    purge_button.setToolTip('Clear all contents from this log file (creates a backup first)')
    purge_button.setEnabled(file_path.is_file() and file_path.stat().st_size > 0)
    purge_button.clicked.connect(purge_fn)
    layout.addWidget(purge_button)

    label = ' Open Folder Location' if file_path.is_dir() else ' Open File Location'
    open_location_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), label)
    open_location_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    open_location_button.setToolTip('Open the containing folder in your file manager')
    open_location_button.clicked.connect(lambda: open_file_location(file_path))
    layout.addWidget(open_location_button)

    open_file_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'file-text.svg')), ' Open File')
    open_file_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    open_file_button.setToolTip('Open the log file in the default text editor')
    open_file_button.setEnabled(file_path.is_file())
    open_file_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(file_path))))
    layout.addWidget(open_file_button)

    return purge_button, open_file_button


def purge_log_file(
    parent: QWidget,
    file_path: Path,
    *,
    item_label: str = 'contents',
) -> str | None:
    """Confirm and purge *file_path*; return a status message or None if cancelled/missing."""
    if not file_path.exists():
        QMessageBox.information(parent, TITLE, f'{file_path.name} does not exist.')
        return None
    if file_path.is_file() and not file_path.stat().st_size:
        return None
    reply = QMessageBox.warning(
        parent,
        TITLE,
        f'Purge ALL {item_label} from {file_path.name}?\n\nA backup (.bak) will be created first.\nThis cannot be undone.',
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
    )
    if reply != QMessageBox.StandardButton.Yes:
        return None
    try:
        bak = backup_and_truncate_log_file(file_path)
    except OSError as e:
        QMessageBox.warning(parent, TITLE, f'Failed to purge {file_path.name}:\n{e}')
        return None
    message = f'Purged {file_path.name}.'
    if bak:
        message += f'\nBackup saved to {bak.name}'
    return message


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
    copy_tooltip: str = 'Copy all displayed text to clipboard',
    save_tooltip: str = 'Save the displayed content to a new file',
) -> tuple[QHBoxLayout, QPushButton, QPushButton]:
    """Create a button row with Copy All and Save As buttons, add it to *layout*, and return it with the buttons."""
    button_row = QHBoxLayout()

    copy_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), ' Copy All')
    copy_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    copy_button.setToolTip(copy_tooltip)
    copy_button.setEnabled(False)

    def _on_copy_clicked() -> None:
        if copy_fn():
            animate_button_feedback(copy_button)

    copy_button.clicked.connect(_on_copy_clicked)
    button_row.addWidget(copy_button)

    save_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'save.svg')), ' Save As...')
    save_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    save_button.setToolTip(save_tooltip)
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
    highlight_format.setBackground(QColor('#e3b341'))
    highlight_format.setForeground(QColor('#000000'))

    selections: list[Any] = []
    for match_cursor in matched_cursors[:_MAX_HIGHLIGHT_SELECTIONS]:
        selection = cast('Any', QTextEdit.ExtraSelection())
        selection.cursor = match_cursor
        selection.format = highlight_format
        selections.append(selection)
    viewer.setExtraSelections(selections)
    return matched_cursors
