"""Themed copies of the bundled SVG icons, generated on demand into the Local AppData theme cache."""

import hashlib
import json
import shutil
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, NamedTuple

from PySide6.QtGui import QColor, QPixmap

from session_sniffer.constants.local import RESOURCES_DIR_PATH, THEME_CACHE_DIR_PATH, VERSION
from session_sniffer.models.themes import DARK_THEME_COLORS, ThemeColors

if TYPE_CHECKING:
    from pathlib import Path

    from session_sniffer.guis.theming._engine import ThemeTransform

BUNDLED_ICONS_DIR_PATH: Final = RESOURCES_DIR_PATH / 'icons'
ACTIVE_ICONS_DIR_PATH: Final = THEME_CACHE_DIR_PATH / 'active_icons'
CHECKBOX_CHECK_FILENAME: Final = 'checkbox_check.svg'

# Brand artwork keeps its original colors in every theme.
_UNTHEMED_ICON_NAMES: Final = frozenset({'app_icon.svg', 'update_download_badge.svg'})
_CACHE_KEY_FILE_NAME: Final = '.cache_key'
_CACHE_KEY_LENGTH: Final = 16
_MAX_THEMED_SVG_CACHE: Final = 16
_ICONS_LOCK = threading.Lock()


@dataclass(slots=True)
class _BundledInventory:
    svg_texts: dict[str, str]
    unthemed_rel_paths: tuple[Path, ...]
    signature: list[tuple[str, int, int]]


@dataclass(slots=True)
class _IconsCacheState:
    inventory: _BundledInventory | None = None
    last_written_key: str | None = None


_CACHE_STATE = _IconsCacheState()
_THEMED_SVG_TEXTS_CACHE: dict[ThemeColors, dict[str, str]] = {}


def _get_bundled_inventory() -> _BundledInventory:
    """Load and cache bundled SVG source texts and file metadata once per process."""
    if _CACHE_STATE.inventory is not None:
        return _CACHE_STATE.inventory

    svg_texts: dict[str, str] = {}
    unthemed_rel_paths: list[Path] = []
    signature: list[tuple[str, int, int]] = []

    for source_path in sorted(BUNDLED_ICONS_DIR_PATH.rglob('*')):
        if not source_path.is_file():
            continue
        stat_result = source_path.stat()
        rel_path = source_path.relative_to(BUNDLED_ICONS_DIR_PATH)
        rel_posix = rel_path.as_posix()
        signature.append((rel_posix, stat_result.st_size, stat_result.st_mtime_ns))
        if source_path.suffix.lower() == '.svg' and source_path.name not in _UNTHEMED_ICON_NAMES:
            svg_texts[rel_posix] = source_path.read_text(encoding='utf-8')
        else:
            unthemed_rel_paths.append(rel_path)

    inventory = _BundledInventory(
        svg_texts=svg_texts,
        unthemed_rel_paths=tuple(unthemed_rel_paths),
        signature=signature,
    )
    _CACHE_STATE.inventory = inventory
    return inventory


def _build_themed_svg_texts(transform: ThemeTransform, inventory: _BundledInventory) -> dict[str, str]:
    """Return a cached mapping of relative POSIX icon path -> themed SVG XML string for *transform*."""
    cached = _THEMED_SVG_TEXTS_CACHE.get(transform.colors)
    if cached is not None:
        return cached

    themed_map = dict(inventory.svg_texts) if transform.is_identity else {rel_posix: transform.svg(raw_svg) for rel_posix, raw_svg in inventory.svg_texts.items()}

    raw_check = inventory.svg_texts.get('check.svg')
    if raw_check is not None:
        accent_check_color = (
            '#ffffff'
            if transform.is_identity
            else transform.text_on(QColor(DARK_THEME_COLORS.text_strong), QColor(DARK_THEME_COLORS.accent)).name(QColor.NameFormat.HexRgb)
        )
        themed_map[CHECKBOX_CHECK_FILENAME] = raw_check.replace('#ffffff', accent_check_color)

    if len(_THEMED_SVG_TEXTS_CACHE) >= _MAX_THEMED_SVG_CACHE:
        _THEMED_SVG_TEXTS_CACHE.clear()
    _THEMED_SVG_TEXTS_CACHE[transform.colors] = themed_map
    return themed_map


def _cache_key(transform: ThemeTransform, inventory: _BundledInventory) -> str:
    """Return a key that changes whenever the theme colors, app version, or bundled icon files change."""
    fingerprint = {
        'schema': 5,
        'version': VERSION,
        'colors': transform.colors.as_dict(),
        'icons': inventory.signature,
    }
    return hashlib.sha256(json.dumps(fingerprint, sort_keys=True).encode('utf-8')).hexdigest()[:_CACHE_KEY_LENGTH]


def prepare_themed_icons_dir(transform: ThemeTransform) -> Path:
    """Populate `ACTIVE_ICONS_DIR_PATH` with the icon set for *transform* when out of date and return it.

    Thread-safe: may be called from a background worker thread prior to applying a theme on the GUI thread.

    Raises:
        OSError: If the theme cache directory cannot be written.
    """
    with _ICONS_LOCK:
        inventory = _get_bundled_inventory()
        desired_key = _cache_key(transform, inventory)
        key_file = ACTIVE_ICONS_DIR_PATH / _CACHE_KEY_FILE_NAME
        if _CACHE_STATE.last_written_key == desired_key and key_file.is_file():
            return ACTIVE_ICONS_DIR_PATH
        if (
            key_file.is_file()
            and (ACTIVE_ICONS_DIR_PATH / CHECKBOX_CHECK_FILENAME).is_file()
            and key_file.read_text(encoding='utf-8').strip() == desired_key
        ):
            _CACHE_STATE.last_written_key = desired_key
            return ACTIVE_ICONS_DIR_PATH

        if THEME_CACHE_DIR_PATH.is_dir():
            for entry in THEME_CACHE_DIR_PATH.iterdir():
                if entry.is_dir() and entry != ACTIVE_ICONS_DIR_PATH:
                    shutil.rmtree(entry)

        ACTIVE_ICONS_DIR_PATH.mkdir(parents=True, exist_ok=True)
        for rel_path in inventory.unthemed_rel_paths:
            source_path = BUNDLED_ICONS_DIR_PATH / rel_path
            target_path = ACTIVE_ICONS_DIR_PATH / rel_path
            if not target_path.is_file() or target_path.stat().st_size != source_path.stat().st_size:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_path, target_path)

        themed_svgs = _build_themed_svg_texts(transform, inventory)
        for rel_posix, svg_content in themed_svgs.items():
            target_path = ACTIVE_ICONS_DIR_PATH / rel_posix
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(svg_content, encoding='utf-8')

        key_file.write_text(desired_key, encoding='utf-8')
        _CACHE_STATE.last_written_key = desired_key
        return ACTIVE_ICONS_DIR_PATH


_MAX_TRACKED_SVG_SPECS: Final = 512


class RenderedSvgSpec(NamedTuple):
    """Canonical recipe for re-rendering an SVG pixmap/icon after a live theme change."""

    filename: str
    width: int
    height: int
    tint_pair: tuple[str, str] | None
    right_padding: int = 0


_RENDERED_SVG_SPECS: dict[tuple[int, int, bytes], RenderedSvgSpec] = {}


def pixmap_fingerprint(pixmap: QPixmap) -> tuple[int, int, bytes]:
    """Return `(width, height, raw_bytes)` uniquely identifying *pixmap*'s rendered pixels."""
    return (pixmap.width(), pixmap.height(), bytes(pixmap.toImage().bits()))


def record_rendered_svg_spec(pixmap: QPixmap, spec: RenderedSvgSpec) -> None:
    """Record *spec* for *pixmap* so runtime theme switches can re-render it."""
    if len(_RENDERED_SVG_SPECS) >= _MAX_TRACKED_SVG_SPECS:
        _RENDERED_SVG_SPECS.clear()
    _RENDERED_SVG_SPECS[pixmap_fingerprint(pixmap)] = spec


def lookup_rendered_svg_spec(pixmap: QPixmap) -> RenderedSvgSpec | None:
    """Return the recorded `RenderedSvgSpec` matching *pixmap*, or `None`."""
    return None if pixmap.isNull() else _RENDERED_SVG_SPECS.get(pixmap_fingerprint(pixmap))
