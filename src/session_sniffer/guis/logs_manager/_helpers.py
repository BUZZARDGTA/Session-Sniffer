"""Shared constants and helper functions for the Logs Manager dialog."""
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

from PyQt6.QtCore import QModelIndex, QSortFilterProxyModel, QUrl
from PyQt6.QtGui import QColor, QDesktopServices, QFont, QSyntaxHighlighter, QTextCharFormat, QTextDocument

from session_sniffer.guis.userip_manager_helpers import BYTES_PER_UNIT, human_readable_size

if TYPE_CHECKING:
    from PyQt6.QtGui import QStandardItemModel
    from PyQt6.QtWidgets import QWidget

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
    if file_path.exists():
        explorer_exe = Path(os.getenv('WINDIR', r'C:\Windows')) / 'explorer.exe'
        subprocess.run([str(explorer_exe), '/select,', str(file_path)], check=False)
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
        if source_model is None:
            return True
        model = cast('QStandardItemModel', source_model)

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
