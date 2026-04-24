"""Sessions logging tab — folder tree + file viewer."""
import shutil
from pathlib import Path

from PyQt6.QtCore import QModelIndex, Qt, QUrl
from PyQt6.QtGui import QColor, QDesktopServices, QFileSystemModel, QFont, QTextCharFormat, QTextCursor
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
    QSplitter,
    QTextEdit,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.logs_manager._helpers import _open_file_location
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET
from session_sniffer.guis.userip_manager_helpers import human_readable_size


class _SessionsLogTab(QWidget):  # pylint: disable=too-few-public-methods, too-many-instance-attributes
    """Browse and view session log files in a YYYY/MM/DD folder hierarchy."""

    def __init__(self, sessions_dir: Path, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._sessions_dir = sessions_dir
        self._current_file: Path | None = None
        self._selected_path: Path | None = None
        self._global_search_active = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        # --- Top bar ---
        top_bar = QHBoxLayout()

        top_bar.addWidget(QLabel('Search:'))
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText('Search in displayed file ...')
        self._search_input.setClearButtonEnabled(True)
        self._search_input.textChanged.connect(self._on_search_changed)
        self._search_input.returnPressed.connect(self._on_search_return_pressed)
        top_bar.addWidget(self._search_input, stretch=1)

        self._global_search_checkbox = QCheckBox('Search All Files')
        self._global_search_checkbox.setToolTip('Search across all session log files (read-only)')
        self._global_search_checkbox.toggled.connect(self._on_global_search_toggled)
        top_bar.addWidget(self._global_search_checkbox)

        self._match_label = QLabel('')
        top_bar.addWidget(self._match_label)

        self._file_info_label = QLabel('')
        top_bar.addWidget(self._file_info_label)

        layout.addLayout(top_bar)

        # --- Splitter: tree (left) | viewer (right) ---
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: file tree
        self._sessions_dir.mkdir(parents=True, exist_ok=True)

        self._fs_model = QFileSystemModel()
        self._fs_model.setRootPath(str(self._sessions_dir))
        self._fs_model.setNameFilters(['*.log'])
        self._fs_model.setNameFilterDisables(False)

        self._tree = QTreeView()
        self._tree.setModel(self._fs_model)
        self._tree.setRootIndex(self._fs_model.index(str(self._sessions_dir)))
        self._tree.setHeaderHidden(True)
        for col in (1, 2, 3):
            self._tree.setColumnHidden(col, True)
        self._tree.clicked.connect(self._on_tree_clicked)
        self._tree.setMinimumWidth(200)

        splitter.addWidget(self._tree)

        # Right: text viewer
        self._viewer = QPlainTextEdit()
        self._viewer.setReadOnly(True)
        mono_font = QFont('Consolas', 9)
        mono_font.setStyleHint(QFont.StyleHint.Monospace)
        self._viewer.setFont(mono_font)
        self._viewer.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._viewer.setPlaceholderText('Select a session log file from the tree to view its contents.')

        splitter.addWidget(self._viewer)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)

        layout.addWidget(splitter, stretch=1)

        # --- Directory metadata ---
        self._metadata_label = QLabel('')
        layout.addWidget(self._metadata_label)

        # --- Bottom buttons ---
        button_row = QHBoxLayout()

        copy_button = QPushButton('📋 Copy All')
        copy_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        copy_button.setToolTip('Copy all displayed text to clipboard')
        copy_button.clicked.connect(self._copy_all)
        button_row.addWidget(copy_button)

        save_button = QPushButton('💾 Save As...')
        save_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        save_button.setToolTip('Save the displayed file to a new location')
        save_button.clicked.connect(self._save_as)
        button_row.addWidget(save_button)

        button_row.addStretch()

        self._delete_button = QPushButton('🗑️ Delete')
        self._delete_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        self._delete_button.setToolTip('Delete the currently selected file or folder')
        self._delete_button.clicked.connect(self._delete_selected)
        button_row.addWidget(self._delete_button)

        open_location_button = QPushButton('📂 Open File Location')
        open_location_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        open_location_button.setToolTip('Open the containing folder in Windows Explorer')
        open_location_button.clicked.connect(self._open_location)
        button_row.addWidget(open_location_button)

        layout.addLayout(button_row)

        # Initial metadata
        self._update_dir_metadata()

    # ------------------------------------------------------------------
    # Directory metadata
    # ------------------------------------------------------------------

    def _update_dir_metadata(self) -> None:
        """Update the metadata label with total size and file count of the sessions directory."""
        if not self._sessions_dir.exists():
            self._metadata_label.setText(f'{self._sessions_dir.name}  —  Directory not found')
            return
        total_size = 0
        file_count = 0
        for f in self._sessions_dir.rglob('*.log'):
            if f.is_file():
                total_size += f.stat().st_size
                file_count += 1
        self._metadata_label.setText(
            f'{self._sessions_dir.name}  |  {human_readable_size(total_size)}  |  {file_count} log file(s)',
        )

    # ------------------------------------------------------------------
    # Tree interaction
    # ------------------------------------------------------------------

    def _on_tree_clicked(self, index: QModelIndex) -> None:
        selected = Path(self._fs_model.filePath(index))
        self._selected_path = selected
        if selected.is_file():
            self._load_file(selected)
            self._delete_button.setText('🗑️ Delete File')
            self._delete_button.setToolTip('Delete the currently selected session log file')
        elif selected.is_dir():
            self._current_file = None
            self._viewer.setPlainText('')
            total_size = 0
            file_count = 0
            for f in selected.rglob('*.log'):
                if f.is_file():
                    total_size += f.stat().st_size
                    file_count += 1
            self._file_info_label.setText(
                f'{selected.name}  (folder)  |  {human_readable_size(total_size)}  |  {file_count} log file(s)',
            )
            self._match_label.setText('')
            self._viewer.setExtraSelections([])
            self._delete_button.setText('🗑️ Delete Folder')
            self._delete_button.setToolTip('Delete the currently selected folder and all its contents')

    def _load_file(self, file_path: Path) -> None:
        self._current_file = file_path
        text = file_path.read_text(encoding='utf-8', errors='replace')
        self._viewer.setPlainText(text)
        line_count = text.count('\n') + (1 if text and not text.endswith('\n') else 0)
        self._file_info_label.setText(
            f'{file_path.name}  |  {human_readable_size(int(file_path.stat().st_size))}  |  {line_count:,} lines',
        )

        if self._search_input.text():
            self._on_search_changed(self._search_input.text())

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def _on_search_changed(self, text: str) -> None:
        if self._global_search_active:
            # Global search is expensive; only triggered on Enter, not per-keystroke.
            return

        if not text:
            self._match_label.setText('')
            self._viewer.setExtraSelections([])
            return

        document = self._viewer.document()
        if document is None:
            return
        matches: list[QTextCursor] = []
        cursor = document.find(text)
        while not cursor.isNull():
            matches.append(QTextCursor(cursor))
            cursor = document.find(text, cursor)

        highlight_fmt = QTextCharFormat()
        highlight_fmt.setBackground(QColor('#665c00'))
        highlight_fmt.setForeground(QColor('#ffffff'))

        selections = []
        for c in matches:
            selection = QTextEdit.ExtraSelection()
            selection.cursor = c
            selection.format = highlight_fmt
            selections.append(selection)
        self._viewer.setExtraSelections(selections)

        if matches:
            self._viewer.setTextCursor(matches[0])
            self._viewer.centerCursor()

        self._match_label.setText(f'{len(matches)} match(es)' if matches else 'No matches')

    def _on_search_return_pressed(self) -> None:
        """Run global search on Enter. Activates global mode if not already active."""
        if self._global_search_active:
            self._run_global_search(self._search_input.text())
        else:
            self._global_search_checkbox.setChecked(True)

    def _on_global_search_toggled(self, checked: bool) -> None:
        """Switch between single-file view mode and global search mode."""
        if checked:
            self._global_search_active = True
            self._search_input.setPlaceholderText('Search across all session log files (press Enter) ...')
            self._tree.setEnabled(False)
            self._run_global_search(self._search_input.text())
        else:
            self._global_search_active = False
            self._search_input.setPlaceholderText('Search in displayed file ...')
            self._tree.setEnabled(True)
            self._viewer.setExtraSelections([])
            if self._current_file is not None:
                self._load_file(self._current_file)
            else:
                self._viewer.setPlainText('')
                self._match_label.setText('')
                self._file_info_label.setText('')

    def _run_global_search(self, text: str) -> None:
        """Scan all session log files for lines matching *text* and display results in the viewer."""
        self._viewer.setExtraSelections([])

        if not text:
            self._viewer.setPlainText('')
            self._match_label.setText('')
            self._file_info_label.setText('')
            return

        if not self._sessions_dir.exists():
            self._viewer.setPlainText('[Sessions directory not found]')
            self._match_label.setText('No matches')
            return

        search_lower = text.lower()
        result_lines: list[str] = []
        total_matches = 0
        files_with_matches = 0

        for log_path in sorted(self._sessions_dir.rglob('*.log')):
            if not log_path.is_file():
                continue
            lines = log_path.read_text(encoding='utf-8', errors='replace').splitlines()

            relative = log_path.relative_to(self._sessions_dir)
            file_matches = 0
            for line_num, line in enumerate(lines, start=1):
                if search_lower in line.lower():
                    if not file_matches:
                        if result_lines:
                            result_lines.append('')
                        result_lines.append(f'── {relative} ──')
                    result_lines.append(f'  {line_num}: {line}')
                    file_matches += 1
                    total_matches += 1

            if file_matches:
                files_with_matches += 1

        if result_lines:
            self._viewer.setPlainText('\n'.join(result_lines))
        else:
            self._viewer.setPlainText(f'No matches found for "{text}" in any session log file.')

        self._match_label.setText(f'{total_matches} match(es)' if total_matches else 'No matches')
        self._file_info_label.setText(
            f'Global search  |  {files_with_matches} file(s) matched' if total_matches else '',
        )

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
        QMessageBox.information(self, TITLE, 'Contents copied to clipboard.')

    def _save_as(self) -> None:
        if self._current_file is None:
            QMessageBox.information(self, TITLE, 'No file selected.')
            return
        default_name = str(self._current_file.with_suffix('.export.log'))
        path, _ = QFileDialog.getSaveFileName(
            self, 'Save Session Log As', default_name, 'Log Files (*.log);;Text Files (*.txt);;All Files (*)',
        )
        if not path:
            return
        Path(path).write_text(self._viewer.toPlainText(), encoding='utf-8')
        QMessageBox.information(self, TITLE, f'Saved to {path}')

    def _delete_selected(self) -> None:
        target = self._selected_path
        if target is None or not target.exists():
            QMessageBox.information(self, TITLE, 'No file or folder selected.')
            return

        is_dir = target.is_dir()
        kind = 'folder' if is_dir else 'file'
        extra = '\n\nAll contents within the folder will be removed.' if is_dir else ''
        reply = QMessageBox.warning(
            self, TITLE,
            f'Delete {kind} "{target.name}"?{extra}\n\nThis cannot be undone.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        if is_dir:
            shutil.rmtree(target)
        else:
            target.unlink()
        self._viewer.clear()
        self._file_info_label.setText('')
        self._current_file = None
        self._selected_path = None
        self._update_dir_metadata()

    def _open_location(self) -> None:
        if self._selected_path and self._selected_path.exists():
            if self._selected_path.is_dir():
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._selected_path)))
            else:
                _open_file_location(self._selected_path)
        elif self._sessions_dir.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._sessions_dir)))
