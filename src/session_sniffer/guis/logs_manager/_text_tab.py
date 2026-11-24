"""Plain-text log tab — for debug.log and crash.log."""

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast, override

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QIcon, QShowEvent
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.file_watch import DebouncedFileWatcher
from session_sniffer.guis.live_language import register_language_refresh, set_i18n_colon_label
from session_sniffer.guis.logs_manager._helpers import (
    LARGE_TEXT_FILE_LIMIT,
    LogLevelHighlighter,
    add_purge_and_location_buttons,
    copy_viewer_text_to_clipboard,
    create_log_viewer,
    create_search_input,
    file_metadata_text,
    find_and_highlight_matches,
    prepare_search,
    purge_log_file,
    setup_copy_save_button_row,
    setup_metadata_label,
)
from session_sniffer.guis.theming import ICONS_DIR_PATH
from session_sniffer.guis.userip_manager_helpers import human_readable_size
from session_sniffer.i18n import tr, tr_plural

if TYPE_CHECKING:
    from PySide6.QtGui import QTextCursor

_LOG_ENTRY_HEADER_REGEX = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} - ([A-Z]+) - ')
logger = logging.getLogger(__name__)

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

    purge_state_changed = Signal()

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
        self._truncated_file_size: int | None = None
        self._file_missing = False
        self._file_locked = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        # --- Top bar ---
        top_bar = QHBoxLayout()

        self._search_input = create_search_input(top_bar, tr('Search in log\u2026'), self._on_search_changed, debounce_ms=100)
        self._search_input.returnPressed.connect(self._find_next)

        self._prev_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'arrow-left.svg')), '')
        self._prev_button.setToolTip(tr('Previous match'))
        self._prev_button.setFixedWidth(30)
        self._prev_button.clicked.connect(self._find_prev)
        top_bar.addWidget(self._prev_button)

        self._next_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'arrow-right.svg')), '')
        self._next_button.setToolTip(tr('Next match'))
        self._next_button.setFixedWidth(30)
        self._next_button.clicked.connect(self._find_next)
        top_bar.addWidget(self._next_button)

        self._match_label = QLabel('')
        top_bar.addWidget(self._match_label)

        if self._enable_severity_filter:
            severity_label = QLabel()
            set_i18n_colon_label(severity_label, 'Severity')
            top_bar.addWidget(severity_label)
            self._severity_combo: QComboBox | None = QComboBox()
            self._severity_combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
            self._severity_combo.setToolTip(tr('Filter log entries by severity level'))
            for label, data in SEVERITY_FILTER_CHOICES:
                display_label = tr('All Severities') if data is None else label
                self._severity_combo.addItem(display_label, data)
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
        button_row, self._copy_button, self._save_button = setup_copy_save_button_row(
            layout,
            self._copy_all,
            self._save_as,
            copy_tooltip=tr('Copy all log text to clipboard'),
            save_tooltip=tr('Save the log to a new file'),
        )

        self._purge_button, self._open_file_button = add_purge_and_location_buttons(button_row, self._purge_file, self._file_path)

        # --- Auto-refresh from disk ---
        self._watching_stopped: bool = False
        self._watcher = DebouncedFileWatcher(self, self.load_data)

        # Initial load
        self.load_data()
        register_language_refresh(self, self._retranslate)

    def _build_truncated_prefix(self, file_size: int) -> str:
        """Build the localized truncation notice shown above truncated log contents."""
        limit_str = human_readable_size(LARGE_TEXT_FILE_LIMIT)
        size_str = human_readable_size(file_size)
        return tr('[\u2026truncated \u2014 showing last {limit} of {size}\u2026]', limit=limit_str, size=size_str) + '\n\n'

    def _retranslate(self) -> None:
        """Refresh all UI strings after a live language change."""
        self._search_input.setPlaceholderText(tr('Search in log\u2026'))
        self._prev_button.setToolTip(tr('Previous match'))
        self._next_button.setToolTip(tr('Next match'))
        if self._severity_combo is not None:
            self._severity_combo.setItemText(0, tr('All Severities'))
            self._severity_combo.setToolTip(tr('Filter log entries by severity level'))
        self._copy_button.setText(f" {tr('Copy All')}")
        self._copy_button.setToolTip(tr('Copy all log text to clipboard'))
        self._save_button.setText(f" {tr('Save As...')}")
        self._save_button.setToolTip(tr('Save the log to a new file'))
        self._metadata_label.setText(file_metadata_text(self._file_path))
        if self._file_missing:
            self._viewer.setPlaceholderText(tr('[{filename} not found]', filename=self._file_path.name))
            self._line_count_label.setText(tr_plural('{count:,} line', '{count:,} lines', 0))
            return
        if self._file_locked:
            self._viewer.setPlaceholderText(tr('[Cannot read {filename}: file is locked]', filename=self._file_path.name))
            return
        self._prefix = self._build_truncated_prefix(self._truncated_file_size) if self._truncated and self._truncated_file_size is not None else ''
        self._apply_filter(preserve_scroll=True)

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

    @override
    def showEvent(self, a0: QShowEvent) -> None:
        """Scroll to the bottom on first display if no manual scroll occurred."""
        super().showEvent(a0)
        if not self._initial_shown:
            self._initial_shown = True
            scrollbar = self._viewer.verticalScrollBar()
            if scrollbar:
                scrollbar.setValue(scrollbar.maximum())

    @property
    def can_purge(self) -> bool:
        """Return whether this log currently contains content to purge."""
        return self._purge_button.isEnabled()

    def stop_watching(self) -> None:
        """Stop auto-refresh watcher from disk."""
        self._watching_stopped = True
        self._watcher.stop()

    def start_watching(self) -> None:
        """Start auto-refresh watcher from disk."""
        self._watcher.watch(files=[self._file_path], directories=[self._file_path.parent])
        if self._watching_stopped:
            self._watching_stopped = False
            self.load_data()

    # ------------------------------------------------------------------
    # Data loading and filtering
    # ------------------------------------------------------------------

    def _clear_viewer_state(self, placeholder_text: str) -> None:
        """Reset the loaded text, search state, and viewer contents with *placeholder_text*."""
        self._raw_text = ''
        self._prefix = ''
        self._entries = []
        self._total_line_count = 0
        self._truncated = False
        self._search_matches.clear()
        self._current_match_index = -1
        self._match_label.setText('')
        self._viewer.setExtraSelections([])
        self._viewer.setPlainText('')
        self._viewer.setPlaceholderText(placeholder_text)
        self._copy_button.setEnabled(False)
        self._save_button.setEnabled(False)

    def load_data(self) -> None:
        """Read the text file and display its contents."""
        file_exists = self._file_path.is_file()
        self._open_file_button.setEnabled(file_exists)
        self._purge_button.setEnabled(file_exists and self._file_path.stat().st_size > 0)
        self.purge_state_changed.emit()
        if not self._file_path.exists():
            self._file_missing = True
            self._file_locked = False
            self._truncated_file_size = None
            self._clear_viewer_state(tr('[{filename} not found]', filename=self._file_path.name))
            self._line_count_label.setText(tr_plural('{count:,} line', '{count:,} lines', 0))
            self._metadata_label.setText(file_metadata_text(self._file_path))
            return

        try:
            file_size = self._file_path.stat().st_size
            self._file_missing = False
            self._file_locked = False
            self._truncated = file_size > LARGE_TEXT_FILE_LIMIT
            self._truncated_file_size = file_size if self._truncated else None

            with self._file_path.open(encoding='utf-8', errors='replace') as file:
                if self._truncated:
                    file.seek(max(0, file_size - LARGE_TEXT_FILE_LIMIT))
                    file.readline()  # Skip partial first line
                text = file.read()

            self._raw_text = text
            self._prefix = self._build_truncated_prefix(file_size) if self._truncated else ''
            self._total_line_count = text.count('\n') + (1 if text and not text.endswith('\n') else 0)

            if self._enable_severity_filter:
                self._entries = self._parse_entries(text)
            else:
                self._entries = []

            self._viewer.setPlaceholderText('')
            self._apply_filter(preserve_scroll=True)

        except PermissionError:
            self._file_missing = False
            self._file_locked = True
            self._truncated_file_size = None
            self._clear_viewer_state(tr('[Cannot read {filename}: file is locked]', filename=self._file_path.name))
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
        has_display_text = bool(full_display_text)
        self._copy_button.setEnabled(has_display_text)
        self._save_button.setEnabled(has_display_text)

        if scrollbar and preserve_scroll:
            if not self._initial_shown or (old_max > 0 and old_scroll >= old_max - 5):
                scrollbar.setValue(scrollbar.maximum())
            else:
                scrollbar.setValue(min(old_scroll, scrollbar.maximum()))

        if not self._enable_severity_filter or allowed_levels is None or filtered_lines == self._total_line_count:
            line_text = (
                tr_plural('{count:,} line (truncated)', '{count:,} lines (truncated)', self._total_line_count)
                if self._truncated
                else tr_plural('{count:,} line', '{count:,} lines', self._total_line_count)
            )
        else:
            line_text = (
                tr_plural('{filtered:,} of {count:,} line (truncated)', '{filtered:,} of {count:,} lines (truncated)', self._total_line_count, filtered=filtered_lines)
                if self._truncated
                else tr_plural('{filtered:,} of {count:,} line', '{filtered:,} of {count:,} lines', self._total_line_count, filtered=filtered_lines)
            )
        self._line_count_label.setText(line_text)

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
        self._search_matches = find_and_highlight_matches(document, text, self._viewer)
        if self._search_matches:
            self._current_match_index = 0
            self._go_to_match(0)
        self._update_match_label()

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
            self._match_label.setText(tr('No matches'))
        else:
            self._match_label.setText(f'{self._current_match_index + 1} / {count}')

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _copy_all(self) -> bool:
        return copy_viewer_text_to_clipboard(self._viewer)

    def _save_as(self) -> None:
        text = self._viewer.toPlainText()
        if not text:
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            tr('Save Log As'),
            str(self._file_path.with_suffix('.export.log')),
            f"{tr('Log Files')} (*.log);;{tr('Text Files')} (*.txt);;{tr('All Files')} (*)",
        )
        if not path:
            return
        try:
            Path(path).write_text(text, encoding='utf-8')
        except OSError as e:
            logger.warning('Failed to export log "%s" to "%s": %s', self._file_path, path, e)
            QMessageBox.critical(self, tr('Export Error'), tr('Failed to export "{name}":\n{error}', name=self._file_path.name, error=e))
            return
        QMessageBox.information(self, TITLE, tr('Saved to {path}', path=path))

    def _purge_file(self) -> None:
        message = purge_log_file(self, self._file_path, item_label='contents')
        if message is not None:
            QMessageBox.information(self, TITLE, message)
            self.load_data()
