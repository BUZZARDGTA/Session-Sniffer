"""Qt dialog for downloading a Session Sniffer update with a live progress bar."""

import threading
from typing import TYPE_CHECKING

import requests
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QDialog, QDialogButtonBox, QLabel, QProgressBar, QVBoxLayout

from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.networking.http_session import session

if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtGui import QCloseEvent


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

    def run(self) -> None:
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

        self.setWindowTitle('Downloading Update')
        self.setMinimumWidth(420)
        self.setModal(True)

        layout = QVBoxLayout(self)

        self._status_label = QLabel(f'Downloading Session Sniffer {version_label}...')
        layout.addWidget(self._status_label)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        layout.addWidget(self._progress_bar)

        self._size_label = QLabel('')
        layout.addWidget(self._size_label)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        button_box.rejected.connect(self._on_cancel)
        layout.addWidget(button_box)

        self._worker = _DownloadWorker(download_url, dest_path)
        self._worker.progress_signal.connect(self._on_progress)
        self._worker.finished_signal.connect(self._on_finished)
        self._worker.start()

    @property
    def success(self) -> bool:
        """Whether the download completed successfully."""
        return self._success

    def _on_progress(self, done: int, total: int) -> None:
        """Update the progress bar and size label."""
        if total > 0:
            self._progress_bar.setValue(int(done / total * 100))
            self._size_label.setText(f'{done / 1_048_576:.1f} MB / {total / 1_048_576:.1f} MB')
        else:
            self._size_label.setText(f'{done / 1_048_576:.1f} MB downloaded')

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

    def closeEvent(self, a0: QCloseEvent | None) -> None:  # noqa: N802
        """Cancel the download if the dialog is closed via the window chrome."""
        self._worker.cancel()
        self._worker.wait()
        if self._dest_path.exists():
            self._dest_path.unlink(missing_ok=True)
        super().closeEvent(a0)
