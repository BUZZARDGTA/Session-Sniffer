"""Qt dialog for downloading a Session Sniffer update with a live progress bar."""

import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING, override

import requests
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import CURRENT_VERSION
from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.stylesheets import (
    UPDATE_DOWNLOAD_CANCEL_BUTTON_STYLESHEET,
    UPDATE_DOWNLOAD_DIALOG_STYLESHEET,
    UPDATE_DOWNLOAD_DIVIDER_STYLESHEET,
    UPDATE_DOWNLOAD_FRAME_STYLESHEET,
    UPDATE_DOWNLOAD_PROGRESS_BAR_STYLESHEET,
    UPDATE_DOWNLOAD_SIZE_LABEL_STYLESHEET,
    UPDATE_DOWNLOAD_SIZE_PILL_STYLESHEET,
    UPDATE_DOWNLOAD_STATUS_LABEL_STYLESHEET,
    UPDATE_DOWNLOAD_TITLE_LABEL_STYLESHEET,
    UPDATE_DOWNLOAD_VERSION_ARROW_STYLESHEET,
    UPDATE_DOWNLOAD_VERSION_CARD_CURRENT_STYLESHEET,
    UPDATE_DOWNLOAD_VERSION_CARD_DATE_STYLESHEET,
    UPDATE_DOWNLOAD_VERSION_CARD_LABEL_ACCENT_STYLESHEET,
    UPDATE_DOWNLOAD_VERSION_CARD_LABEL_MUTED_STYLESHEET,
    UPDATE_DOWNLOAD_VERSION_CARD_NEW_STYLESHEET,
    UPDATE_DOWNLOAD_VERSION_CARD_VALUE_ACCENT_STYLESHEET,
    UPDATE_DOWNLOAD_VERSION_CARD_VALUE_MUTED_STYLESHEET,
)
from session_sniffer.guis.utils import center_window_on_screen, render_svg_pixmap_from_resource
from session_sniffer.networking.http_session import session
from session_sniffer.utils import format_project_version, is_pyinstaller_compiled

if TYPE_CHECKING:
    from PyQt6.QtGui import QCloseEvent, QMouseEvent


class _DownloadWorker(CrashingQThread):
    """Background thread that streams an HTTP download and reports progress."""

    progress_signal: pyqtSignal = pyqtSignal(int, int)  # bytes_done, total_bytes
    finished_signal: pyqtSignal = pyqtSignal(bool, str)  # success, error_msg

    def __init__(self, download_url: str, dest_path: Path) -> None:
        super().__init__()
        self._download_url = download_url
        self._dest_path = dest_path
        self._cancel_event = threading.Event()

    def cancel(self) -> None:
        """Signal the download thread to abort."""
        self._cancel_event.set()

    @override
    def _run(self) -> None:
        """Stream download, emitting progress updates until complete or cancelled."""
        try:
            response = session.get(self._download_url, stream=True, timeout=30)
            response.raise_for_status()

            total = int(response.headers.get('Content-Length', 0))
            done = 0
            chunk_size = 65_536  # 64 KiB

            self._dest_path.parent.mkdir(parents=True, exist_ok=True)

            with self._dest_path.open('wb') as f:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if self._cancel_event.is_set():
                        self.finished_signal.emit(False, 'Cancelled')  # noqa: FBT003
                        return
                    f.write(chunk)
                    done += len(chunk)
                    self.progress_signal.emit(done, total)

        except requests.exceptions.RequestException as e:
            self.finished_signal.emit(False, str(e))  # noqa: FBT003
            return

        self.finished_signal.emit(True, '')  # noqa: FBT003


class UpdateDownloadDialog(QDialog):
    """Modal dialog that downloads a file and shows live progress.

    Usage:
        dialog = UpdateDownloadDialog(download_url, dest_path, version_label, parent)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # dest_path now contains the downloaded file
    """

    def __init__(self, download_url: str, dest_path: Path, version_label: str, parent: None = None) -> None:
        """Initialise the dialog and start the background download worker."""
        super().__init__(parent)
        self._dest_path = dest_path
        self._success = False
        self._drag_offset: tuple[int, int] | None = None
        self._new_version_label = version_label
        self._current_version_label = format_project_version(CURRENT_VERSION)
        self._current_size_text = self._compute_current_build_size_text()
        self._new_size_label: QLabel | None = None
        self._progress_bar = QProgressBar()
        self._status_label = QLabel('Preparing download\u2026')
        self._size_label = QLabel(
            '0.0 MB<span style="color: #5a6878;">&nbsp;&nbsp;/&nbsp;&nbsp;</span>xx.x MB',
        )

        self.setWindowTitle('Downloading Update')
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Dialog)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, on=True)
        self.setFixedSize(620, 460)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setStyleSheet(UPDATE_DOWNLOAD_DIALOG_STYLESHEET)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 18, 18, 18)
        outer.setSpacing(0)

        frame = QFrame(self)
        frame.setObjectName('updateDownloadFrame')
        frame.setStyleSheet(UPDATE_DOWNLOAD_FRAME_STYLESHEET)

        shadow = QGraphicsDropShadowEffect(frame)
        shadow.setBlurRadius(40)
        shadow.setOffset(0, 6)
        shadow.setColor(QColor(0, 0, 0, 180))
        frame.setGraphicsEffect(shadow)

        outer.addWidget(frame)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(26, 8, 26, 20)
        layout.setSpacing(14)

        layout.addLayout(self._build_header())
        layout.addSpacing(-6)
        layout.addWidget(self._build_divider())
        layout.addLayout(self._build_version_section())
        layout.addLayout(self._build_progress_section())
        layout.addStretch(1)
        layout.addWidget(self._build_divider())
        layout.addLayout(self._build_footer())

        self._center_on_screen()

        self._worker = _DownloadWorker(download_url, dest_path)
        self._worker.progress_signal.connect(self._on_progress)
        self._worker.finished_signal.connect(self._on_finished)
        self._worker.start()

    def _build_header(self) -> QHBoxLayout:
        """Build the icon + title block at the top of the dialog."""
        header = QHBoxLayout()
        header.setSpacing(14)
        header.setContentsMargins(0, 0, 0, 0)

        header.addWidget(self._create_download_icon(), 0, Qt.AlignmentFlag.AlignVCenter)

        title_label = QLabel('Downloading Update')
        title_label.setFont(QFont('Segoe UI', 17, QFont.Weight.Bold))
        title_label.setStyleSheet(UPDATE_DOWNLOAD_TITLE_LABEL_STYLESHEET)
        header.addWidget(title_label, 0, Qt.AlignmentFlag.AlignVCenter)

        header.addStretch(1)
        return header

    def _build_version_section(self) -> QHBoxLayout:
        """Build the Current → Downloading version comparison row."""
        row = QHBoxLayout()
        row.setSpacing(10)
        row.setContentsMargins(0, 2, 0, 2)

        row.addWidget(self._create_version_card('CURRENT', self._current_version_label, self._current_size_text, accent=False), 1)

        arrow_label = QLabel('\u2192')
        arrow_label.setFont(QFont('Segoe UI', 22, QFont.Weight.Bold))
        arrow_label.setStyleSheet(UPDATE_DOWNLOAD_VERSION_ARROW_STYLESHEET)
        arrow_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        arrow_label.setFixedWidth(28)
        row.addWidget(arrow_label, 0, Qt.AlignmentFlag.AlignVCenter)

        row.addWidget(self._create_version_card('DOWNLOADING', self._new_version_label, '', accent=True), 1)

        return row

    def _create_version_card(self, label: str, version_label: str, size_text: str, *, accent: bool) -> QFrame:
        """Build a single version comparison card.

        `accent=True` styles the card as the highlighted "downloading" target.
        """
        version_text, date_text = self._split_version_label(version_label)

        card = QFrame()
        if accent:
            card.setObjectName('updateDownloadVersionCardNew')
            card.setStyleSheet(UPDATE_DOWNLOAD_VERSION_CARD_NEW_STYLESHEET)
            label_qss = UPDATE_DOWNLOAD_VERSION_CARD_LABEL_ACCENT_STYLESHEET
            value_qss = UPDATE_DOWNLOAD_VERSION_CARD_VALUE_ACCENT_STYLESHEET
        else:
            card.setObjectName('updateDownloadVersionCardCurrent')
            card.setStyleSheet(UPDATE_DOWNLOAD_VERSION_CARD_CURRENT_STYLESHEET)
            label_qss = UPDATE_DOWNLOAD_VERSION_CARD_LABEL_MUTED_STYLESHEET
            value_qss = UPDATE_DOWNLOAD_VERSION_CARD_VALUE_MUTED_STYLESHEET

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 10, 16, 8)
        card_layout.setSpacing(0)

        # Top row: optional accent dot + label
        label_row = QHBoxLayout()
        label_row.setSpacing(8)
        label_row.setContentsMargins(0, 0, 0, 0)

        if accent:
            dot = QLabel()
            dot.setFixedSize(8, 8)
            dot.setStyleSheet(
                'background-color: #5fb4f5;border-radius: 4px;',
            )
            label_row.addWidget(dot, 0, Qt.AlignmentFlag.AlignVCenter)

        label_widget = QLabel(label)
        label_widget.setFont(QFont('Segoe UI', 8, QFont.Weight.Bold))
        label_widget.setStyleSheet(label_qss)
        label_row.addWidget(label_widget, 0, Qt.AlignmentFlag.AlignVCenter)
        label_row.addStretch(1)
        card_layout.addLayout(label_row)

        version_widget = QLabel(version_text)
        version_widget.setFont(QFont('Segoe UI', 12, QFont.Weight.Bold))
        version_widget.setStyleSheet(value_qss)
        version_widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(version_widget)

        if date_text:
            date_row = QHBoxLayout()
            date_row.setSpacing(6)
            date_row.setContentsMargins(0, 2, 0, 0)

            date_row.addWidget(self._svg_label('calendar.svg', 20, 20), 0, Qt.AlignmentFlag.AlignVCenter)

            date_widget = QLabel(date_text)
            date_widget.setFont(QFont('Consolas', 9))
            date_widget.setStyleSheet(UPDATE_DOWNLOAD_VERSION_CARD_DATE_STYLESHEET)
            date_row.addWidget(date_widget, 0, Qt.AlignmentFlag.AlignVCenter)
            date_row.addStretch(1)

            card_layout.addLayout(date_row)

        size_row = QHBoxLayout()
        size_row.setSpacing(6)
        size_row.setContentsMargins(0, 0, 0, 0)

        size_row.addWidget(self._svg_label('size.svg', 20, 20), 0, Qt.AlignmentFlag.AlignVCenter)

        size_widget = QLabel(size_text or 'xx.x MB')
        size_widget.setFont(QFont('Consolas', 9))
        size_widget.setStyleSheet(UPDATE_DOWNLOAD_VERSION_CARD_DATE_STYLESHEET)
        size_row.addWidget(size_widget, 0, Qt.AlignmentFlag.AlignVCenter)
        size_row.addStretch(1)

        card_layout.addLayout(size_row)

        if accent:
            self._new_size_label = size_widget

        return card

    @staticmethod
    def _split_version_label(label: str) -> tuple[str, str]:
        """Split a `format_project_version` output into (version, date) parts.

        Format is either "vX.Y.Z" or "vX.Y.Z - YYYY/MM/DD (HH:MM)".
        """
        if ' - ' in label:
            version, _, date = label.partition(' - ')
            return version.strip(), date.strip()
        return label.strip(), ''

    @staticmethod
    def _format_size_mb(num_bytes: int) -> str:
        """Format a byte count as a `X.Y MB` string."""
        return f'{num_bytes / 1_048_576:.1f} MB'

    @staticmethod
    def _is_generated_build_metadata(path: Path) -> bool:
        """Return whether a path is generated Python packaging/cache metadata."""
        return any(part == '__pycache__' or part.endswith(('.egg-info', '.dist-info')) for part in path.parts)

    @classmethod
    def _compute_current_build_size_text(cls) -> str:
        """Return the size of the current build/source payload."""
        if is_pyinstaller_compiled():
            return cls._format_size_mb(Path(sys.executable).stat().st_size)

        project_root = Path(__file__).resolve().parents[3]
        included_paths = (
            project_root / 'pyproject.toml',
            project_root / 'bin',
            project_root / 'resources',
            project_root / 'scripts',
            project_root / 'src' / 'session_sniffer',
        )

        total = 0
        for path in included_paths:
            if path.is_file():
                total += path.stat().st_size
                continue

            if path.is_dir():
                total += sum(
                    file.stat().st_size
                    for file in path.rglob('*')
                    if file.is_file() and not cls._is_generated_build_metadata(file) and file.suffix.lower() not in {'.pyc', '.pyo'}
                )

        return cls._format_size_mb(total)

    def _build_divider(self) -> QFrame:
        """Build a thin horizontal divider line."""
        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.NoFrame)
        divider.setStyleSheet(UPDATE_DOWNLOAD_DIVIDER_STYLESHEET)
        divider.setFixedHeight(1)
        return divider

    def _build_progress_section(self) -> QVBoxLayout:
        """Build the progress bar, status label, and size pill."""
        section = QVBoxLayout()
        section.setSpacing(12)
        section.setContentsMargins(0, 4, 0, 0)

        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setTextVisible(True)
        self._progress_bar.setFixedHeight(30)
        self._progress_bar.setStyleSheet(UPDATE_DOWNLOAD_PROGRESS_BAR_STYLESHEET)
        section.addWidget(self._progress_bar)

        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setFont(QFont('Segoe UI', 9))
        self._status_label.setStyleSheet(UPDATE_DOWNLOAD_STATUS_LABEL_STYLESHEET)
        section.addWidget(self._status_label)

        pill_row = QHBoxLayout()
        pill_row.addStretch(1)
        pill_row.addWidget(self._build_size_pill())
        pill_row.addStretch(1)
        section.addLayout(pill_row)

        return section

    def _build_size_pill(self) -> QFrame:
        """Build a small rounded pill that displays download size info."""
        pill = QFrame()
        pill.setObjectName('updateDownloadSizePill')
        pill.setStyleSheet(UPDATE_DOWNLOAD_SIZE_PILL_STYLESHEET)

        pill_layout = QHBoxLayout(pill)
        pill_layout.setContentsMargins(20, 10, 20, 10)
        pill_layout.setSpacing(10)

        pill_layout.addWidget(self._create_cloud_download_icon(), 0, Qt.AlignmentFlag.AlignVCenter)

        self._size_label.setFont(QFont('Consolas', 10))
        self._size_label.setStyleSheet(UPDATE_DOWNLOAD_SIZE_LABEL_STYLESHEET)
        self._size_label.setTextFormat(Qt.TextFormat.RichText)
        pill_layout.addWidget(self._size_label)

        return pill

    def _build_footer(self) -> QHBoxLayout:
        """Build the footer row containing the Cancel button."""
        footer = QHBoxLayout()
        footer.setContentsMargins(0, 0, 0, 0)
        footer.addStretch(1)

        cancel_button = QPushButton('Cancel')
        cancel_button.setCursor(Qt.CursorShape.PointingHandCursor)
        cancel_button.setStyleSheet(UPDATE_DOWNLOAD_CANCEL_BUTTON_STYLESHEET)
        cancel_button.clicked.connect(self._on_cancel)
        footer.addWidget(cancel_button)

        return footer

    def _create_download_icon(self) -> QWidget:
        """Create the small circular download badge from an SVG asset."""
        return self._svg_label('update_download_badge.svg', 64, 64)

    def _create_cloud_download_icon(self) -> QWidget:
        """Create the small cloud-with-down-arrow icon from an SVG asset."""
        return self._svg_label('cloud_download.svg', 32, 22)

    @staticmethod
    def _svg_label(filename: str, width: int, height: int) -> QLabel:
        """Render an SVG file to a transparent QLabel pixmap, preserving aspect ratio."""
        pixmap = render_svg_pixmap_from_resource(filename, width, height)

        label = QLabel()
        label.setPixmap(pixmap)
        label.setFixedSize(width, height)
        label.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        label.setStyleSheet('background: transparent;')
        return label

    def _center_on_screen(self) -> None:
        """Center the dialog on its screen."""
        center_window_on_screen(self)

    @override
    def mousePressEvent(self, a0: QMouseEvent | None) -> None:
        """Begin dragging the frameless dialog."""
        if a0 is not None and a0.button() == Qt.MouseButton.LeftButton:
            pos = a0.position().toPoint()
            self._drag_offset = (pos.x(), pos.y())
        super().mousePressEvent(a0)

    @override
    def mouseMoveEvent(self, a0: QMouseEvent | None) -> None:
        """Drag the frameless dialog."""
        if a0 is not None and self._drag_offset is not None and a0.buttons() & Qt.MouseButton.LeftButton:
            global_pos = a0.globalPosition().toPoint()
            self.move(global_pos.x() - self._drag_offset[0], global_pos.y() - self._drag_offset[1])
        super().mouseMoveEvent(a0)

    @override
    def mouseReleaseEvent(self, a0: QMouseEvent | None) -> None:
        """Stop dragging the frameless dialog."""
        self._drag_offset = None
        super().mouseReleaseEvent(a0)

    @property
    def success(self) -> bool:
        """Whether the download completed successfully."""
        return self._success

    def _on_progress(self, done: int, total: int) -> None:
        """Update the progress bar and size labels."""
        if total > 0:
            self._progress_bar.setValue(int(done / total * 100))
            self._size_label.setText(
                f'{self._format_size_mb(done)}<span style="color: #5a6878;">&nbsp;&nbsp;/&nbsp;&nbsp;</span>{self._format_size_mb(total)}',
            )
            if self._new_size_label is not None:
                self._new_size_label.setText(self._format_size_mb(total))
        else:
            self._size_label.setText(f'{self._format_size_mb(done)} downloaded')
        self._status_label.setText('Streaming update from GitHub\u2026')

    def _on_finished(self, success: bool, error_msg: str) -> None:  # noqa: FBT001
        """Handle download completion or failure."""
        self._success = success
        if success:
            self.accept()
        else:
            if error_msg and error_msg != 'Cancelled':
                self._status_label.setText(f'Download failed: {error_msg}')
            self.reject()

    def _on_cancel(self) -> None:
        """Cancel the in-progress download."""
        self._worker.cancel()
        self._worker.wait()
        if self._dest_path.exists():
            self._dest_path.unlink(missing_ok=True)
        self.reject()

    @override
    def closeEvent(self, a0: QCloseEvent | None) -> None:
        """Cancel the download if the dialog is closed via the window chrome."""
        self._worker.cancel()
        self._worker.wait()
        if self._dest_path.exists():
            self._dest_path.unlink(missing_ok=True)
        super().closeEvent(a0)
