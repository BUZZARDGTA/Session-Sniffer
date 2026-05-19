"""Capture health and performance statistics window."""

from session_sniffer.guis.capture_statistics_window import CaptureStatisticsWindow


class CaptureHealthWindow(CaptureStatisticsWindow):
    """Capture statistics window variant with the legacy health title."""

    WINDOW_TITLE = 'Capture Health'
