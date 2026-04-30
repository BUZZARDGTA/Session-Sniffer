"""Plain-text log tab — for warnings.log and errors.log."""
from pathlib import Path

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
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

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.logs_manager._helpers import (
    AUTO_REFRESH_INTERVAL_MS,
    LARGE_TEXT_FILE_LIMIT,
    LogLevelHighlighter,
    backup_file,
    file_metadata_text,
    open_file_location,
)
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET
from session_sniffer.guis.userip_manager_helpers import human_readable_size


class TextLogTab(QWidget):  # pylint: disable=too-many-instance-attributes
    """Plain-text log viewer with search highlighting, auto-refresh, and log-level coloring."""

    def __init__(self, file_path: Path, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._file_path = file_path
        self._search_matches: list[QTextCursor] = []
        self._current_match_index = -1

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        # --- Top bar ---
        top_bar = QHBoxLayout()

        top_bar.addWidget(QLabel('Search:'))
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText('Search in log ...')
        self._search_input.returnPressed.connect(self._find_next)
        self._search_input.textChanged.connect(self._on_search_changed)
        top_bar.addWidget(self._search_input, stretch=1)

        prev_button = QPushButton('◀')
        prev_button.setToolTip('Previous match')
        prev_button.setFixedWidth(30)
        prev_button.clicked.connect(self._find_prev)
        top_bar.addWidget(prev_button)

        next_button = QPushButton('▶')
        next_button.setToolTip('Next match')
        next_button.setFixedWidth(30)
        next_button.clicked.connect(self._find_next)
        top_bar.addWidget(next_button)

        self._match_label = QLabel('')
        top_bar.addWidget(self._match_label)

        refresh_button = QPushButton('🔄 Refresh')
        refresh_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        refresh_button.setToolTip('Reload file contents')
        refresh_button.clicked.connect(self.load_data)
        top_bar.addWidget(refresh_button)

        self._auto_refresh_check = QCheckBox('Auto-refresh')
        self._auto_refresh_check.setToolTip('Automatically reload the log every 2 seconds')
        self._auto_refresh_check.toggled.connect(self._on_auto_refresh_toggled)
        top_bar.addWidget(self._auto_refresh_check)

        self._line_count_label = QLabel('')
        top_bar.addWidget(self._line_count_label)

        layout.addLayout(top_bar)

        # --- Text viewer ---
        self._viewer = QPlainTextEdit()
        self._viewer.setReadOnly(True)
        mono_font = QFont('Consolas', 9)
        mono_font.setStyleHint(QFont.StyleHint.Monospace)
        self._viewer.setFont(mono_font)
        self._viewer.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        document = self._viewer.document()
        self._highlighter = LogLevelHighlighter(document) if document is not None else None

        layout.addWidget(self._viewer, stretch=1)

        # --- Metadata ---
        self._metadata_label = QLabel('')
        layout.addWidget(self._metadata_label)

        # --- Bottom buttons ---
        button_row = QHBoxLayout()

        copy_button = QPushButton('📋 Copy All')
        copy_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        copy_button.setToolTip('Copy all log text to clipboard')
        copy_button.clicked.connect(self._copy_all)
        button_row.addWidget(copy_button)

        save_button = QPushButton('💾 Save As...')
        save_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        save_button.setToolTip('Save the log to a new file')
        save_button.clicked.connect(self._save_as)
        button_row.addWidget(save_button)

        button_row.addStretch()

        purge_button = QPushButton('🗑️ Purge File')
        purge_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        purge_button.setToolTip('Clear all contents from this log file (creates a backup first)')
        purge_button.clicked.connect(self._purge_file)
        button_row.addWidget(purge_button)

        open_location_button = QPushButton('📂 Open File Location')
        open_location_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        open_location_button.setToolTip('Open the containing folder in Windows Explorer')
        open_location_button.clicked.connect(lambda: open_file_location(self._file_path))
        button_row.addWidget(open_location_button)

        layout.addLayout(button_row)

        # --- Auto-refresh timer ---
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self.load_data)

        # Initial load
        self.load_data()

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def load_data(self) -> None:
        """Read the text file and display its contents."""
        if not self._file_path.exists():
            self._viewer.setPlainText(f'[{self._file_path.name} not found]')
            self._line_count_label.setText('0 lines')
            self._metadata_label.setText(file_metadata_text(self._file_path))
            return

        try:
            file_size = self._file_path.stat().st_size
            truncated = file_size > LARGE_TEXT_FILE_LIMIT

            with self._file_path.open(encoding='utf-8', errors='replace') as f:
                if truncated:
                    f.seek(max(0, file_size - LARGE_TEXT_FILE_LIMIT))
                    f.readline()  # Skip partial first line
                text = f.read()

            # Preserve scroll position
            scrollbar = self._viewer.verticalScrollBar()
            old_scroll = scrollbar.value() if scrollbar else 0
            old_max = scrollbar.maximum() if scrollbar else 0

            prefix = f'[... truncated \u2014 showing last {human_readable_size(LARGE_TEXT_FILE_LIMIT)} of {human_readable_size(file_size)} ...]\n\n' if truncated else ''
            self._viewer.setPlainText(prefix + text)

            if scrollbar is not None:
                if old_max > 0 and old_scroll >= old_max - 5:
                    scrollbar.setValue(scrollbar.maximum())
                else:
                    scrollbar.setValue(old_scroll)

            line_count = text.count('\n') + (1 if text and not text.endswith('\n') else 0)
            suffix = ' (truncated)' if truncated else ''
            self._line_count_label.setText(f'{line_count:,} lines{suffix}')

        except PermissionError:
            self._viewer.setPlainText(f'[Cannot read {self._file_path.name}: file is locked]')
            self._line_count_label.setText('')

        self._metadata_label.setText(file_metadata_text(self._file_path))

        if self._search_input.text():
            self._on_search_changed(self._search_input.text())

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def _on_search_changed(self, text: str) -> None:
        self._search_matches.clear()
        self._current_match_index = -1

        if not text:
            self._match_label.setText('')
            self._viewer.setExtraSelections([])
            return

        document = self._viewer.document()
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
        selections = []
        highlight_fmt = QTextCharFormat()
        highlight_fmt.setBackground(QColor('#665c00'))
        highlight_fmt.setForeground(QColor('#ffffff'))

        for cursor in self._search_matches:
            selection = QTextEdit.ExtraSelection()
            selection.cursor = cursor
            selection.format = highlight_fmt
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
    # Auto-refresh
    # ------------------------------------------------------------------

    def _on_auto_refresh_toggled(self, checked: bool) -> None:
        if checked:
            self._refresh_timer.start(AUTO_REFRESH_INTERVAL_MS)
        else:
            self._refresh_timer.stop()

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _copy_all(self) -> None:
        text = self._viewer.toPlainText()
        if not text:
            QMessageBox.information(self, TITLE, 'Nothing to copy.')
            return
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(text)
        QMessageBox.information(self, TITLE, 'Log contents copied to clipboard.')

    def _save_as(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, 'Save Log As', str(self._file_path.with_suffix('.export.log')), 'Log Files (*.log);;Text Files (*.txt);;All Files (*)',
        )
        if not path:
            return
        Path(path).write_text(self._viewer.toPlainText(), encoding='utf-8')
        QMessageBox.information(self, TITLE, f'Saved to {path}')

    def _purge_file(self) -> None:
        if not self._file_path.exists():
            QMessageBox.information(self, TITLE, f'{self._file_path.name} does not exist.')
            return
        reply = QMessageBox.warning(
            self, TITLE,
            f'Purge ALL contents from {self._file_path.name}?\n\nA backup (.bak) will be created first.\nThis cannot be undone.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        backup = backup_file(self._file_path)
        self._file_path.write_text('', encoding='utf-8')

        msg = f'Purged {self._file_path.name}.'
        if backup:
            msg += f'\nBackup saved to {backup.name}'
        QMessageBox.information(self, TITLE, msg)
        self.load_data()
