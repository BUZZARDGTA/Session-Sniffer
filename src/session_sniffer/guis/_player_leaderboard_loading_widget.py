"""Loading widget for the player leaderboard."""

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET
from session_sniffer.guis.utils import scale_by_ui


class LeaderboardLoadingWidget(QWidget):
    """In-window loading widget displayed while the leaderboard baseline is being built in the background."""

    cancelled: Signal = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the leaderboard loading widget."""
        super().__init__(parent)

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addStretch()

        center_row = QHBoxLayout()
        center_row.addStretch()

        loading_frame = QFrame(self)
        loading_frame.setObjectName('loadingFrame')
        loading_frame.setStyleSheet("""
            QFrame#loadingFrame {
                background-color: #1e1e1e;
                border: 1px solid #3e3e42;
                border-radius: 8px;
            }
        """)
        loading_frame.setFixedSize(scale_by_ui(420), scale_by_ui(210))

        shadow_effect = QGraphicsDropShadowEffect(loading_frame)
        shadow_effect.setBlurRadius(30)
        shadow_effect.setOffset(0, 4)
        shadow_effect.setColor(QColor(0, 0, 0, 150))
        loading_frame.setGraphicsEffect(shadow_effect)

        frame_layout = QVBoxLayout(loading_frame)
        frame_layout.setContentsMargins(24, 20, 24, 20)
        frame_layout.setSpacing(10)

        self._header_label = QLabel('🏆 Building Leaderboard')
        self._header_label.setFont(QFont('Segoe UI', 15, QFont.Weight.Bold))
        self._header_label.setStyleSheet('color: #88c0d0;')
        self._header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        frame_layout.addWidget(self._header_label)

        frame_layout.addStretch()

        self._status_label = QLabel('Scanning session logs...\nPlease wait...')
        self._status_label.setFont(QFont('Segoe UI', 10))
        self._status_label.setStyleSheet('color: #a0a0a0;')
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setWordWrap(True)
        frame_layout.addWidget(self._status_label)

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
                background-color: #007acc;
                border-radius: 3px;
            }
        """)
        frame_layout.addWidget(self._progress_bar)

        frame_layout.addSpacing(6)

        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self._cancel_button = QPushButton('Cancel')
        self._cancel_button.setToolTip('Cancel loading and close the leaderboard window')
        self._cancel_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._cancel_button.setFixedWidth(scale_by_ui(90))
        self._cancel_button.clicked.connect(self.cancelled.emit)
        button_layout.addWidget(self._cancel_button)

        button_layout.addStretch()
        frame_layout.addLayout(button_layout)

        center_row.addWidget(loading_frame)
        center_row.addStretch()

        outer_layout.addLayout(center_row)
        outer_layout.addStretch()

    def reset_progress(self) -> None:
        """Reset the progress bar to indeterminate and revert the status text to initial prompt."""
        self._progress_bar.setRange(0, 0)
        self._status_label.setText('Scanning session logs...\nPlease wait...')

    def update_progress(self, current: int, total: int) -> None:
        """Update the progress bar and status text."""
        self._progress_bar.setRange(0, total)
        self._progress_bar.setValue(current)
        if total > 0:
            percentage = int((current / total) * 100)
            self._status_label.setText(f'Scanning session logs...\n{percentage}% ({current:,} / {total:,})')
        else:
            self._status_label.setText(f'Scanning session logs...\n({current:,} found)')
