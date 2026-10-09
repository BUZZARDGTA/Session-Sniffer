"""Table composite and status icons caching and pre-warming."""

from itertools import combinations

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.settings import Settings

CROWN_ICON_PATH = str(RESOURCES_DIR_PATH / 'icons' / 'crown.svg')
SPEEDOMETER_ICON_PATH = str(RESOURCES_DIR_PATH / 'icons' / 'speedometer.svg')
TARGET_ICON_PATH = str(RESOURCES_DIR_PATH / 'icons' / 'target.svg')


def _create_composite_icon(icon_paths: tuple[str, ...]) -> QIcon:
    """Create a high-DPI composite QIcon containing the specified SVG icons horizontally arranged."""
    loaded_icons = [QIcon(path) for path in icon_paths]
    total_width = len(loaded_icons) * 18
    composite = QIcon()
    for scale in (1, 2):
        pixmap = QPixmap(total_width * scale, 16 * scale)
        pixmap.setDevicePixelRatio(scale)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter()
        if painter.begin(pixmap):
            try:
                for i, icon in enumerate(loaded_icons):
                    icon.paint(painter, i * 18, 0, 16, 16)
            finally:
                painter.end()
            composite.addPixmap(pixmap)
    return composite


_IP_COMPOSITE_ICONS_CACHE: dict[tuple[str, ...], QIcon] = {}


def get_composite_ip_icon(icon_paths: tuple[str, ...]) -> QIcon:
    """Return a composite QIcon for the given SVG icon paths, using a shared cache."""
    cached = _IP_COMPOSITE_ICONS_CACHE.get(icon_paths)
    if cached is not None:
        return cached
    icon = _create_composite_icon(icon_paths)
    _IP_COMPOSITE_ICONS_CACHE[icon_paths] = icon
    return icon


def get_ip_column_composite_icon(
    *,
    is_host: bool,
    is_high_rate: bool,
    is_identified: bool,
) -> QIcon | None:
    """Return a composite QIcon for active IP status indicators, or None if no indicators apply."""
    effective_host = is_host and Settings.is_gta5_feature_set()
    if not (effective_host or is_high_rate or is_identified):
        return None
    paths: list[str] = []
    if effective_host:
        paths.append(CROWN_ICON_PATH)
    if is_high_rate:
        paths.append(SPEEDOMETER_ICON_PATH)
    if is_identified:
        paths.append(TARGET_ICON_PATH)
    return get_composite_ip_icon(tuple(paths))


def preload_table_icons() -> None:
    """Pre-warm composite SVG icon variations for the IP column based on active feature sets and settings."""
    active_paths: list[str] = []
    if Settings.is_gta5_feature_set() and Settings.gui_session_host_icon:
        active_paths.append(CROWN_ICON_PATH)
    if Settings.high_rate_monitor_icon:
        active_paths.append(SPEEDOMETER_ICON_PATH)
    if Settings.player_identifier_icon:
        active_paths.append(TARGET_ICON_PATH)

    for r in range(1, len(active_paths) + 1):
        for combo in combinations(active_paths, r):
            get_composite_ip_icon(combo)
