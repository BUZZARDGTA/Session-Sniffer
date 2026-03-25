"""Color palette and semantic color definitions for GUI rendering.

This module provides a modular color system organized into layers:
1. ColorPalette - Base Nordic-inspired color definitions
2. StatusBarColors - Semantic colors for status bar HTML formatting
3. ThresholdColors - Status/health indicator colors for metrics and thresholds
4. TableColors - Row coloring for connected/disconnected player tables
"""


class ColorPalette:  # pylint: disable=too-few-public-methods
    """Base Nordic-inspired color palette for the entire application.

    Provides a centralized set of primary colors used across all UI components.
    """

    # Primary accent colors
    ACCENT_BLUE = 'lightblue'
    ACCENT_ORANGE = 'darkorange'
    ACCENT_PURPLE = 'plum'
    ACCENT_GRAY = 'steelblue'

    # Status indicator colors
    GOOD_GREEN = 'lightgreen'
    WARNING_YELLOW = 'khaki'
    CRITICAL_RED = 'indianred'


class StatusBarColors:  # pylint: disable=too-few-public-methods
    """Color scheme specifically for status bar text rendering.

    Maps semantic meanings (enabled, disabled, divider, etc.) to specific colors
    from the base palette for use in status bar HTML formatting.
    """

    # Semantic dividers and separators
    DIVIDER = ColorPalette.ACCENT_GRAY

    # Status indicators
    ENABLED = ColorPalette.GOOD_GREEN
    DISABLED = ColorPalette.CRITICAL_RED
    DEFAULT_TEXT = ColorPalette.GOOD_GREEN

    # Section labels and accents
    LABEL_ACCENT = ColorPalette.ACCENT_ORANGE
    TITLE_ACCENT = ColorPalette.ACCENT_BLUE
    SECONDARY_ACCENT = ColorPalette.ACCENT_PURPLE


class ThresholdColors:  # pylint: disable=too-few-public-methods
    """Color scheme for metrics and threshold-based status indication.

    Maps performance thresholds and status conditions to visual indicators
    used in status displays and performance monitoring.
    """

    # Threshold status colors
    CRITICAL = ColorPalette.CRITICAL_RED
    WARNING = ColorPalette.WARNING_YELLOW
    HEALTHY = ColorPalette.GOOD_GREEN


class TableColors:  # pylint: disable=too-few-public-methods
    """Color scheme for player table rows and cell rendering.

    Defines colors for connected and disconnected player rows in the session tables.
    """

    # Connected player row colors
    CONNECTED_TEXT = 'lime'
    CONNECTED_USERIP_TEXT = 'white'

    # Disconnected player row colors
    DISCONNECTED_TEXT = 'red'
    DISCONNECTED_USERIP_TEXT = 'white'
