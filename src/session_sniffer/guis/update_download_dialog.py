"""Qt dialog for downloading a Session Sniffer update with a live progress bar."""

import threading
from typing import TYPE_CHECKING, override

import requests
from PyQt6.QtCore import QRectF, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPainter, QPixmap
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtWidgets import (
    QApplication,
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

from session_sniffer.constants.local import RESOURCES_DIR_PATH
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
    UPDATE_DOWNLOAD_VERSION_LABEL_STYLESHEET,
)
from session_sniffer.networking.http_session import session

if TYPE_CHECKING:
    from pathlib import Path

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

            with self._dest_path.open('wb') as fh:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if self._cancel_event.is_set():
                        self.finished_signal.emit(False, 'Cancelled')  # noqa: FBT003
                        return
                    fh.write(chunk)
                    done += len(chunk)
                    self.progress_signal.emit(done, total)

        except requests.exceptions.RequestException as exc:
            self.finished_signal.emit(False, str(exc))  # noqa: FBT003
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
        self._version_label_text = version_label
        self._progress_bar = QProgressBar()
        self._status_label = QLabel('Preparing download\u2026')
        self._size_label = QLabel('—')

        self.setWindowTitle('Downloading Update')
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Dialog)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, on=True)
        self.setFixedSize(560, 380)
        self.setModal(True)
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
        layout.setContentsMargins(28, 24, 28, 22)
        layout.setSpacing(14)

        layout.addLayout(self._build_header())
        layout.addWidget(self._build_divider())
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
        header.setSpacing(16)
        header.setContentsMargins(0, 0, 0, 0)

        header.addWidget(self._create_download_icon(), 0, Qt.AlignmentFlag.AlignVCenter)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        text_col.setContentsMargins(0, 0, 0, 0)

        title_label = QLabel('Downloading Update')
        title_label.setFont(QFont('Segoe UI', 19, QFont.Weight.Bold))
        title_label.setStyleSheet(UPDATE_DOWNLOAD_TITLE_LABEL_STYLESHEET)
        text_col.addWidget(title_label)

        version_lbl = QLabel(self._version_label_text)
        version_lbl.setFont(QFont('Segoe UI', 10))
        version_lbl.setStyleSheet(UPDATE_DOWNLOAD_VERSION_LABEL_STYLESHEET)
        text_col.addWidget(version_lbl)

        header.addLayout(text_col, 1)
        return header

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
        """Create the large circular download badge from an SVG asset."""
        return self._svg_label('update_download_badge.svg', 64, 64)

    def _create_cloud_download_icon(self) -> QWidget:
        """Create the small cloud-with-down-arrow icon from an SVG asset."""
        return self._svg_label('cloud_download.svg', 32, 22)

    @staticmethod
    def _svg_label(filename: str, width: int, height: int) -> QLabel:
        """Render an SVG file to a transparent QLabel pixmap, preserving aspect ratio."""
        renderer = QSvgRenderer(str(RESOURCES_DIR_PATH / 'icons' / filename))
        # Render at 2x for hi-DPI crispness.
        pw, ph = width * 2, height * 2
        pixmap = QPixmap(pw, ph)
        pixmap.fill(QColor(0, 0, 0, 0))
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)

        # Letterbox the SVG inside the pixmap so its native aspect is preserved
        # and content can never be clipped on either axis.
        svg_size = renderer.defaultSize()
        if svg_size.width() > 0 and svg_size.height() > 0:
            svg_aspect = svg_size.width() / svg_size.height()
            pix_aspect = pw / ph
            if pix_aspect > svg_aspect:
                target_h = float(ph)
                target_w = target_h * svg_aspect
            else:
                target_w = float(pw)
                target_h = target_w / svg_aspect
            target = QRectF((pw - target_w) / 2, (ph - target_h) / 2, target_w, target_h)
            renderer.render(painter, target)
        else:
            renderer.render(painter)

        painter.end()
        pixmap.setDevicePixelRatio(2.0)

        label = QLabel()
        label.setPixmap(pixmap)
        label.setFixedSize(width, height)
        label.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        label.setStyleSheet('background: transparent;')
        return label

    def _center_on_screen(self) -> None:
        """Center the dialog on its screen."""
        screen = self.screen() or QApplication.primaryScreen()
        if screen is not None:
            geo = screen.availableGeometry()
            x = geo.x() + (geo.width() - self.width()) // 2
            y = geo.y() + (geo.height() - self.height()) // 2
            self.move(x, y)

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
        """Update the progress bar and size label."""
        if total > 0:
            self._progress_bar.setValue(int(done / total * 100))
            self._size_label.setText(
                f'{done / 1_048_576:.1f} MB'
                '<span style="color: #5a6878;">&nbsp;&nbsp;/&nbsp;&nbsp;</span>'
                f'{total / 1_048_576:.1f} MB',
            )
        else:
            self._size_label.setText(f'{done / 1_048_576:.1f} MB downloaded')
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
