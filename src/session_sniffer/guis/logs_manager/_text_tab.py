"""Plain-text log tab — for debug.log and crash.log."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast, override

from PySide6.QtGui import QColor, QIcon, QShowEvent, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.file_watch import DebouncedFileWatcher
from session_sniffer.guis.logs_manager._helpers import (
    LARGE_TEXT_FILE_LIMIT,
    LogLevelHighlighter,
    add_purge_and_location_buttons,
    copy_viewer_text_to_clipboard,
    create_log_viewer,
    file_metadata_text,
    prepare_search,
    purge_log_file,
    setup_copy_save_button_row,
    setup_metadata_label,
)
from session_sniffer.guis.userip_manager_helpers import human_readable_size
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from typing import Any

_LOG_ENTRY_HEADER_REGEX = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} - ([A-Z]+) - ')

SEVERITY_FILTER_CHOICES: tuple[tuple[str, frozenset[str] | None], ...] = (
    ('All Severities', None),
    ('DEBUG', frozenset({'DEBUG'})),
    ('INFO', frozenset({'INFO'})),
    ('WARNING', frozenset({'WARNING'})),
    ('ERROR', frozenset({'ERROR'})),
    ('CRITICAL', frozenset({'CRITICAL'})),
    ('WARNING+', frozenset({'WARNING', 'ERROR', 'CRITICAL'})),
    ('ERROR+', frozenset({'ERROR', 'CRITICAL'})),
)


@dataclass(slots=True)
class _LogEntry:
    level: str | None
    text: str
    line_count: int


class TextLogTab(QWidget):
    """Plain-text log viewer with search highlighting, severity filtering, auto-refresh, and log-level coloring."""

    def __init__(
        self,
        file_path: Path,
        *,
        enable_severity_filter: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._file_path = file_path
        self._enable_severity_filter = enable_severity_filter
        self._search_matches: list[QTextCursor] = []
        self._current_match_index = -1
        self._initial_shown = False
        self._raw_text = ''
        self._prefix = ''
        self._entries: list[_LogEntry] = []
        self._total_line_count = 0
        self._truncated = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        # --- Top bar ---
        top_bar = QHBoxLayout()

        top_bar.addWidget(QLabel('Search:'))
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText('Search in log…')
        self._search_input.returnPressed.connect(self._find_next)
        self._search_input.textChanged.connect(self._on_search_changed)
        top_bar.addWidget(self._search_input, stretch=1)

        prev_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'menu_arrow_left.svg')), '')
        prev_button.setToolTip('Previous match')
        prev_button.setFixedWidth(30)
        prev_button.clicked.connect(self._find_prev)
        top_bar.addWidget(prev_button)

        next_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'menu_arrow_right.svg')), '')
        next_button.setToolTip('Next match')
        next_button.setFixedWidth(30)
        next_button.clicked.connect(self._find_next)
        top_bar.addWidget(next_button)

        self._match_label = QLabel('')
        top_bar.addWidget(self._match_label)

        if self._enable_severity_filter:
            top_bar.addWidget(QLabel('Severity:'))
            self._severity_combo: QComboBox | None = QComboBox()
            self._severity_combo.setToolTip('Filter log entries by severity level')
            for label, data in SEVERITY_FILTER_CHOICES:
                self._severity_combo.addItem(label, data)
            self._severity_combo.currentIndexChanged.connect(self._on_severity_changed)
            top_bar.addWidget(self._severity_combo)
        else:
            self._severity_combo = None

        self._line_count_label = QLabel('')
        top_bar.addWidget(self._line_count_label)

        layout.addLayout(top_bar)

        # --- Text viewer ---
        self._viewer = create_log_viewer()

        document = self._viewer.document()
        self._highlighter = LogLevelHighlighter(document) if document else None

        layout.addWidget(self._viewer, stretch=1)

        # --- Metadata ---
        self._metadata_label = setup_metadata_label(layout)

        # --- Bottom buttons ---
        button_row = setup_copy_save_button_row(
            layout,
            self._copy_all,
            self._save_as,
            copy_tooltip='Copy all log text to clipboard',
            save_tooltip='Save the log to a new file',
        )

        add_purge_and_location_buttons(button_row, self._purge_file, self._file_path)

        # --- Auto-refresh from disk ---
        self._watcher = DebouncedFileWatcher(self, self.load_data)

        # Initial load
        self.load_data()

    def set_severity(self, severity: str) -> None:
        """Set the active severity filter by name (e.g. 'WARNING+', 'ERROR', 'All Severities')."""
        if self._severity_combo is None:
            return
        index = self._severity_combo.findText(severity)
        if index >= 0:
            self._severity_combo.setCurrentIndex(index)

    def current_severity(self) -> str:
        """Return the currently selected severity filter name, or empty string if disabled."""
        if self._severity_combo is None:
            return ''
        return self._severity_combo.currentText()

    def _on_severity_changed(self) -> None:
        """Handle severity filter selection change by applying the filter and scrolling to the bottom."""
        self._apply_filter(preserve_scroll=False)
        scrollbar = self._viewer.verticalScrollBar()
        if scrollbar:
            scrollbar.setValue(scrollbar.maximum())

    @staticmethod
    def _parse_entries(text: str) -> list[_LogEntry]:
        """Parse raw log text into individual entries by log header timestamp and severity level."""
        if not text:
            return []
        entries: list[_LogEntry] = []
        current_level: str | None = None
        current_lines: list[str] = []

        for line in text.splitlines():
            match = _LOG_ENTRY_HEADER_REGEX.match(line)
            if match is not None:
                if current_lines:
                    entries.append(
                        _LogEntry(
                            level=current_level,
                            text='\n'.join(current_lines),
                            line_count=len(current_lines),
                        ),
                    )
                raw_level = cast('str', match.group(1))
                if raw_level == 'WARN':
                    current_level = 'WARNING'
                elif raw_level == 'FATAL':
                    current_level = 'CRITICAL'
                else:
                    current_level = raw_level
                current_lines = [line]
            else:
                current_lines.append(line)

        if current_lines:
            entries.append(
                _LogEntry(
                    level=current_level,
                    text='\n'.join(current_lines),
                    line_count=len(current_lines),
                ),
            )

        return entries

    def start_watching(self) -> None:
        """Start auto-refresh watcher from disk."""
        self._watcher.watch(files=[self._file_path], directories=[self._file_path.parent])
        self.load_data()

    def stop_watching(self) -> None:
        """Stop auto-refresh watcher from disk."""
        self._watcher.stop()

    @override
    def showEvent(self, a0: QShowEvent) -> None:
        """Scroll to the bottom on first display if no manual scroll occurred."""
        super().showEvent(a0)
        if not self._initial_shown:
            self._initial_shown = True
            scrollbar = self._viewer.verticalScrollBar()
            if scrollbar:
                scrollbar.setValue(scrollbar.maximum())

    # ------------------------------------------------------------------
    # Data loading and filtering
    # ------------------------------------------------------------------

    def load_data(self) -> None:
        """Read the text file and display its contents."""
        if not self._file_path.exists():
            self._raw_text = ''
            self._prefix = ''
            self._entries = []
            self._total_line_count = 0
            self._truncated = False
            self._viewer.setPlainText(f'[{self._file_path.name} not found]')
            self._line_count_label.setText('0 lines')
            self._metadata_label.setText(file_metadata_text(self._file_path))
            return

        try:
            file_size = self._file_path.stat().st_size
            self._truncated = file_size > LARGE_TEXT_FILE_LIMIT

            with self._file_path.open(encoding='utf-8', errors='replace') as file:
                if self._truncated:
                    file.seek(max(0, file_size - LARGE_TEXT_FILE_LIMIT))
                    file.readline()  # Skip partial first line
                text = file.read()

            self._raw_text = text
            self._prefix = f'[…truncated — showing last {human_readable_size(LARGE_TEXT_FILE_LIMIT)} of {human_readable_size(file_size)}…]\n\n' if self._truncated else ''
            self._total_line_count = text.count('\n') + (1 if text and not text.endswith('\n') else 0)

            if self._enable_severity_filter:
                self._entries = self._parse_entries(text)
            else:
                self._entries = []

            self._apply_filter(preserve_scroll=True)

        except PermissionError:
            self._viewer.setPlainText(f'[Cannot read {self._file_path.name}: file is locked]')
            self._line_count_label.setText('')

        self._metadata_label.setText(file_metadata_text(self._file_path))

    def _apply_filter(self, *, preserve_scroll: bool = True) -> None:
        """Filter log entries by current severity and update the viewer."""
        scrollbar = self._viewer.verticalScrollBar()
        old_scroll = scrollbar.value() if scrollbar else 0
        old_max = scrollbar.maximum() if scrollbar else 0

        allowed_levels: frozenset[str] | None = None
        if self._enable_severity_filter and self._severity_combo is not None:
            allowed_levels = cast('frozenset[str] | None', self._severity_combo.currentData())

        if not self._enable_severity_filter or allowed_levels is None:
            filtered_text = self._raw_text
            filtered_lines = self._total_line_count
        else:
            matching_chunks = [entry.text for entry in self._entries if entry.level in allowed_levels]
            filtered_text = '\n'.join(matching_chunks)
            filtered_lines = sum(entry.line_count for entry in self._entries if entry.level in allowed_levels)

        full_display_text = (self._prefix + filtered_text) if self._prefix else filtered_text
        self._viewer.setPlainText(full_display_text)

        if scrollbar and preserve_scroll:
            if not self._initial_shown or (old_max > 0 and old_scroll >= old_max - 5):
                scrollbar.setValue(scrollbar.maximum())
            else:
                scrollbar.setValue(min(old_scroll, scrollbar.maximum()))

        suffix = ' (truncated)' if self._truncated else ''
        if not self._enable_severity_filter or allowed_levels is None or filtered_lines == self._total_line_count:
            self._line_count_label.setText(f'{self._total_line_count:,} line{pluralize(self._total_line_count)}{suffix}')
        else:
            self._line_count_label.setText(f'{filtered_lines:,} of {self._total_line_count:,} line{pluralize(self._total_line_count)}{suffix}')

        if self._search_input.text():
            self._on_search_changed(self._search_input.text())
        else:
            self._match_label.setText('')

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def _on_search_changed(self, text: str) -> None:
        self._search_matches.clear()
        self._current_match_index = -1

        document = prepare_search(text, self._match_label, self._viewer)
        if document is None:
            return
        cursor = document.find(text)
        while not cursor.isNull():
            self._search_matches.append(QTextCursor(cursor))
            cursor = document.find(text, cursor)

        self._highlight_all_matches()
        if self._search_matches:
            self._current_match_index = 0
            self._go_to_match(0)
        self._update_match_label()

    def _highlight_all_matches(self) -> None:
        selections: list[Any] = []
        highlight_format = QTextCharFormat()
        highlight_format.setBackground(QColor('#e3b341'))
        highlight_format.setForeground(QColor('#000000'))

        for cursor in self._search_matches:
            selection = cast('Any', QTextEdit.ExtraSelection())
            selection.cursor = cursor
            selection.format = highlight_format
            selections.append(selection)

        self._viewer.setExtraSelections(selections)

    def _go_to_match(self, index: int) -> None:
        if 0 <= index < len(self._search_matches):
            self._viewer.setTextCursor(self._search_matches[index])
            self._viewer.centerCursor()

    def _find_next(self) -> None:
        if not self._search_matches:
            return
        self._current_match_index = (self._current_match_index + 1) % len(self._search_matches)
        self._go_to_match(self._current_match_index)
        self._update_match_label()

    def _find_prev(self) -> None:
        if not self._search_matches:
            return
        self._current_match_index = (self._current_match_index - 1) % len(self._search_matches)
        self._go_to_match(self._current_match_index)
        self._update_match_label()

    def _update_match_label(self) -> None:
        count = len(self._search_matches)
        if not count:
            self._match_label.setText('No matches')
        else:
            self._match_label.setText(f'{self._current_match_index + 1} / {count}')

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _copy_all(self) -> None:
        copy_viewer_text_to_clipboard(self._viewer)

    def _save_as(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            'Save Log As',
            str(self._file_path.with_suffix('.export.log')),
            'Log Files (*.log);;Text Files (*.txt);;All Files (*)',
        )
        if not path:
            return
        Path(path).write_text(self._viewer.toPlainText(), encoding='utf-8')
        QMessageBox.information(self, TITLE, f'Saved to {path}')

    def _purge_file(self) -> None:
        message = purge_log_file(self, self._file_path, item_label='contents')
        if message is not None:
            QMessageBox.information(self, TITLE, message)
            self.load_data()
