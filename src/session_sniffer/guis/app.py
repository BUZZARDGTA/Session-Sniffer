"""Central QApplication instance for the entire application.

This module ensures there's only one QApplication instance throughout the application.
"""

from PySide6.QtWidgets import QApplication

# Create the single QApplication instance for the entire application.
# The stylesheet is applied later in main() after the screen size and UI scale
# factor are resolved, so fonts and sizes are correct for every display tier.
app = QApplication([])  # Passing an empty list for application arguments
