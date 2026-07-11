"""Loading dialog for the player leaderboard."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QLabel,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)


class LeaderboardLoadingDialog(QDialog):
    """Modal dialog shown while the leaderboard is being built in the background."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the leaderboard loading dialog."""
        super().__init__(parent)
        self.setWindowTitle('Most Seen Players')
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Dialog)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, on=True)
        self.setFixedSize(400, 180)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 18, 18, 18)

        frame = QFrame(self)
        frame.setObjectName('loadingFrame')
        frame.setStyleSheet("""
            QFrame#loadingFrame {
                background-color: #1e1e1e;
                border: 1px solid #3E3E42;
                border-radius: 8px;
            }
        """)

        shadow = QGraphicsDropShadowEffect(frame)
        shadow.setBlurRadius(30)
        shadow.setOffset(0, 4)
        shadow.setColor(QColor(0, 0, 0, 150))
        frame.setGraphicsEffect(shadow)

        outer.addWidget(frame)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        self._header = QLabel('🏆 Building Leaderboard')
        self._header.setFont(QFont('Segoe UI', 15, QFont.Weight.Bold))
        self._header.setStyleSheet('color: #88c0d0;')
        self._header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._header)

        layout.addStretch()

        self._status_label = QLabel('Scanning session logs, please wait...')
        self._status_label.setFont(QFont('Segoe UI', 10))
        self._status_label.setStyleSheet('color: #a0a0a0;')
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setWordWrap(True)
        layout.addWidget(self._status_label)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)
        self._progress_bar.setFixedHeight(6)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #2d2d30;
                border: none;
                border-radius: 3px;
            }
            QProgressBar::chunk {
                background-color: #007ACC;
                border-radius: 3px;
            }
        """)
        layout.addWidget(self._progress_bar)

        layout.addSpacing(4)

    def update_progress(self, current: int, total: int) -> None:
        """Update the progress bar and status text."""
        self._progress_bar.setRange(0, total)
        self._progress_bar.setValue(current)
        if total > 0:
            percentage = int((current / total) * 100)
            self._status_label.setText(f'Scanning session logs... {percentage}% ({current:,} / {total:,})')
        else:
            self._status_label.setText(f'Scanning session logs... ({current:,} found)')
