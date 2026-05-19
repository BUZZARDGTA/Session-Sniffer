"""Shared constants and helper functions for the Logs Manager dialog."""
import os
import shutil
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from PyQt6.QtCore import QModelIndex, QSortFilterProxyModel, QUrl
from PyQt6.QtGui import QColor, QDesktopServices, QFont, QStandardItemModel, QSyntaxHighlighter, QTextCharFormat, QTextDocument
from PyQt6.QtWidgets import QApplication, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET
from session_sniffer.guis.userip_manager_helpers import BYTES_PER_UNIT, human_readable_size

MAX_CSV_ROWS = 50_000
AUTO_REFRESH_INTERVAL_MS = 2000
LARGE_TEXT_FILE_LIMIT = 5 * BYTES_PER_UNIT * BYTES_PER_UNIT  # 5 MB
_DAYS_IN_WEEK = 7

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
    size = human_readable_size(int(stat.st_size))
    modified = datetime.fromtimestamp(stat.st_mtime, tz=UTC).astimezone()
    return f'{file_path.name}  |  {size}  |  Last modified: {human_readable_timestamp(modified)}'


def open_file_location(file_path: Path) -> None:
    """Open the containing folder and select the file in Windows Explorer."""
    if file_path.is_file():
        explorer_exe = Path(os.getenv('WINDIR', r'C:\Windows')) / 'explorer.exe'
        subprocess.Popen(f'"{explorer_exe}" /select,"{file_path}"')
    elif file_path.is_dir():
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(file_path)))
    elif file_path.parent.exists():
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(file_path.parent)))


def backup_file(file_path: Path) -> Path | None:
    """Create a .bak backup of a file. Returns backup path or `None` on failure."""
    if not file_path.exists():
        return None
    backup_path = file_path.with_suffix(file_path.suffix + '.bak')
    shutil.copy2(file_path, backup_path)
    return backup_path


# ---------------------------------------------------------------------------
# Log-level syntax highlighter for plain-text log viewers
# ---------------------------------------------------------------------------

class LogLevelHighlighter(QSyntaxHighlighter):
    """Highlight WARNING / ERROR / CRITICAL lines in a plain-text log."""

    def __init__(self, document: QTextDocument) -> None:
        super().__init__(document)

        self._formats: list[tuple[str, QTextCharFormat]] = []

        fmt_warning = QTextCharFormat()
        fmt_warning.setForeground(QColor('#e5c07b'))
        self._formats.append(('WARNING', fmt_warning))

        fmt_error = QTextCharFormat()
        fmt_error.setForeground(QColor('#e06c75'))
        fmt_error.setFontWeight(QFont.Weight.Bold)
        self._formats.append(('ERROR', fmt_error))

        fmt_critical = QTextCharFormat()
        fmt_critical.setForeground(QColor('#ff6b6b'))
        fmt_critical.setFontWeight(QFont.Weight.Bold)
        fmt_critical.setBackground(QColor(80, 20, 20))
        self._formats.append(('CRITICAL', fmt_critical))

    def highlightBlock(self, text: str | None) -> None:
        """Apply log-level coloring to a single text block."""
        if text is None:
            return
        for keyword, fmt in self._formats:
            if keyword in text:
                self.setFormat(0, len(text), fmt)
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

    def set_filter_column(self, column: int) -> None:
        """Set which column to filter on (-1 for all)."""
        self._filter_column = column
        self.invalidateFilter()

    def set_date_filter(self, date_column: int, cutoff: datetime | None) -> None:
        """Set an optional date-range cutoff on a specific column."""
        self._date_column = date_column
        self._date_cutoff = cutoff
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        """Determine whether a source row passes the current text and date filters."""
        _ = source_parent
        source_model = self.sourceModel()
        if not isinstance(source_model, QStandardItemModel):
            return True
        model = source_model

        # Date filter
        if self._date_cutoff is not None and self._date_column >= 0:
            date_item = model.item(source_row, self._date_column)
            if date_item is not None:
                try:
                    row_date = datetime.strptime(date_item.text(), '%Y-%m-%d').replace(tzinfo=UTC)
                    if row_date < self._date_cutoff:
                        return False
                except ValueError:
                    pass

        # Text filter
        pattern = self.filterRegularExpression()
        if not pattern.pattern():
            return True

        if self._filter_column >= 0:
            item = model.item(source_row, self._filter_column)
            return item is not None and pattern.match(item.text()).hasMatch()

        return any(
            (item := model.item(source_row, col)) is not None and pattern.match(item.text()).hasMatch()
            for col in range(model.columnCount())
        )


# ---------------------------------------------------------------------------
# Reusable widget / action helpers shared across log-tab types
# ---------------------------------------------------------------------------

def create_log_viewer() -> QPlainTextEdit:
    """Return a read-only, monospace QPlainTextEdit configured for log display."""
    viewer = QPlainTextEdit()
    viewer.setReadOnly(True)
    mono_font = QFont('Consolas', 9)
    mono_font.setStyleHint(QFont.StyleHint.Monospace)
    viewer.setFont(mono_font)
    viewer.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    return viewer


def create_refresh_button(load_fn: Callable[[], None]) -> QPushButton:
    """Return a standard Refresh button connected to *load_fn*."""
    button = QPushButton('🔄 Refresh')
    button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    button.setToolTip('Reload file contents')
    button.clicked.connect(load_fn)
    return button


def create_search_input(
    top_bar: QHBoxLayout,
    placeholder: str,
    on_changed: Callable[[str], None],
) -> QLineEdit:
    """Add a labelled search QLineEdit to *top_bar* and return it."""
    top_bar.addWidget(QLabel('Search:'))
    search_input = QLineEdit()
    search_input.setPlaceholderText(placeholder)
    search_input.textChanged.connect(on_changed)
    top_bar.addWidget(search_input, stretch=1)
    return search_input


def add_purge_and_location_buttons(
    layout: QHBoxLayout,
    purge_fn: Callable[[], None],
    file_path: Path,
    *,
    purge_tooltip: str = 'Clear all contents from this log file (creates a backup first)',
) -> None:
    """Append addStretch → Purge File → Open File Location buttons to *layout*."""
    layout.addStretch()

    purge_button = QPushButton('🗑️ Purge File')
    purge_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
    purge_button.setToolTip(purge_tooltip)
    purge_button.clicked.connect(purge_fn)
    layout.addWidget(purge_button)

    open_location_button = QPushButton('📂 Open File Location')
    open_location_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    open_location_button.setToolTip('Open the containing folder in Windows Explorer')
    open_location_button.clicked.connect(lambda: open_file_location(file_path))
    layout.addWidget(open_location_button)


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
    reply = QMessageBox.warning(
        parent, TITLE,
        f'Purge ALL {item_label} from {file_path.name}?\n\nA backup (.bak) will be created first.\nThis cannot be undone.',
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
    )
    if reply != QMessageBox.StandardButton.Yes:
        return None
    bak = backup_file(file_path)
    file_path.write_text('', encoding='utf-8')
    msg = f'Purged {file_path.name}.'
    if bak:
        msg += f'\nBackup saved to {bak.name}'
    return msg


def copy_viewer_text_to_clipboard(parent: QWidget, viewer: QPlainTextEdit, *, success_label: str = 'text') -> None:
    """Copy the plain text from *viewer* to the clipboard and show a result dialog."""
    text = viewer.toPlainText()
    if not text:
        QMessageBox.information(parent, TITLE, 'Nothing to copy.')
        return
    clipboard = QApplication.clipboard()
    if clipboard is not None:
        clipboard.setText(text)
    QMessageBox.information(parent, TITLE, f'All {success_label} copied to clipboard.')


def setup_metadata_label(layout: QVBoxLayout) -> QLabel:
    """Add an empty metadata QLabel to *layout* and return it."""
    label = QLabel('')
    layout.addWidget(label)
    return label


def setup_copy_save_button_row(
    layout: QVBoxLayout,
    copy_fn: Callable[[], None],
    save_fn: Callable[[], None],
    *,
    copy_tooltip: str = 'Copy all displayed text to clipboard',
    save_tooltip: str = 'Save the displayed content to a new file',
) -> QHBoxLayout:
    """Create a button row with Copy All and Save As buttons, add it to *layout*, and return it."""
    button_row = QHBoxLayout()

    copy_button = QPushButton('\U0001f4cb Copy All')
    copy_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    copy_button.setToolTip(copy_tooltip)
    copy_button.clicked.connect(copy_fn)
    button_row.addWidget(copy_button)

    save_button = QPushButton('\U0001f4be Save As...')
    save_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    save_button.setToolTip(save_tooltip)
    save_button.clicked.connect(save_fn)
    button_row.addWidget(save_button)

    layout.addLayout(button_row)
    return button_row


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
    return document if document is not None else None
