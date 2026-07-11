"""Central QApplication instance for the entire application.

This module ensures there's only one QApplication instance throughout the application.
"""

from PySide6.QtWidgets import QApplication

from session_sniffer.guis.theme import get_stylesheet

# Create the single QApplication instance for the entire application
app = QApplication([])  # Passing an empty list for application arguments
app.setStyleSheet(get_stylesheet())
