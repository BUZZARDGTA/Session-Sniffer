"""Central QApplication instance for the entire application.

This module ensures there's only one QApplication instance throughout the application.
"""

import qdarkstyle
from PyQt6.QtWidgets import QApplication

# Create the single QApplication instance for the entire application
app = QApplication([])  # Passing an empty list for application arguments
app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt6())
