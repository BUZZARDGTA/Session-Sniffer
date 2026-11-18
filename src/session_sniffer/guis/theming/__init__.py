"""Application theming: active theme resolution, live switching state, and color mapping helpers.

The GUI is authored against the canonical Dark palette. Every design color must be passed through one of
the `themed_*` helpers at the point where the final stylesheet, rich-text HTML, SVG, or `QColor` is
produced, so it follows the active theme:

* `themed_qss` - QSS stylesheets, inline CSS declaration lists, and Qt rich-text HTML.
* `themed_color` - a single color string (e.g. a value interpolated into an HTML template).
* `themed_qcolor` / `themed_text_qcolor` - `QColor` objects used for painting.
* `themed_svg` - inline SVG documents.
* `ICONS_DIR_PATH` - the stable directory of active (themed) SVG icons.

The active theme is initialized at import time from `settings.json` (`GUI_THEME_FOLLOW_SYSTEM` / `GUI_THEME`)
and `themes.json`, and can be switched live at runtime via `guis.live_theme.apply_runtime_theme` without restarting the app.
Colors chosen by the user (settings, UserIP database colors) are user data and must not be themed.
"""

import logging
import os
import subprocess
import sys
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QGuiApplication

from session_sniffer.guis.theming._engine import ThemeTransform, parse_color
from session_sniffer.guis.theming._icons import BUNDLED_ICONS_DIR_PATH, CHECKBOX_CHECK_FILENAME, prepare_themed_icons_dir
from session_sniffer.models.themes import (
    BUILTIN_THEME_NAMES,
    BUILTIN_THEMES,
    DARK_THEME_COLORS,
    DEFAULT_THEME_NAME,
    LIGHT_THEME_NAME,
    THEME_COLOR_TOKENS,
    THEME_NAME_MAX_LENGTH,
    THEME_TOKEN_CATEGORIES,
    CustomThemeModel,
    Theme,
    ThemeColors,
    ThemeColorsModel,
    ThemeColorToken,
    ThemesFile,
    load_themes_file,
    peek_theme_config,
    save_themes_file,
)

if sys.platform == 'win32':
    import winreg

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

_WIN_PERSONALIZE_REG_KEY: Final = r'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
_MIN_COMPOSITE_CHUNK_LEN: Final = 16
_MAX_TRANSFORM_CACHE: Final = 24
_TRANSFORM_LOCK = threading.Lock()
_TRANSFORM_CACHE: dict[ThemeColors, ThemeTransform] = {}


@dataclass(slots=True)
class _RuntimeThemeState:
    theme: Theme
    transform: ThemeTransform
    generation: int = 0


def _detect_platform_theme_fallback() -> str:
    if sys.platform == 'win32':
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WIN_PERSONALIZE_REG_KEY) as key:
                raw_val, _ = winreg.QueryValueEx(key, 'AppsUseLightTheme')
        except OSError:
            return DEFAULT_THEME_NAME
        return LIGHT_THEME_NAME if isinstance(raw_val, int) and raw_val else DEFAULT_THEME_NAME
    if sys.platform == 'darwin':
        try:
            proc = subprocess.run(
                ['/usr/bin/defaults', 'read', '-g', 'AppleInterfaceStyle'],
                capture_output=True,
                text=True,
                timeout=1,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return DEFAULT_THEME_NAME
        return DEFAULT_THEME_NAME if not proc.returncode and 'dark' in proc.stdout.lower() else LIGHT_THEME_NAME
    gtk_theme = os.environ.get('GTK_THEME', '').strip().lower()
    return LIGHT_THEME_NAME if gtk_theme and 'light' in gtk_theme and 'dark' not in gtk_theme else DEFAULT_THEME_NAME


def detect_system_theme_name() -> str:
    """Return `LIGHT_THEME_NAME` when the OS color scheme is light, otherwise `DEFAULT_THEME_NAME`."""
    app_instance = QGuiApplication.instance()
    if isinstance(app_instance, QGuiApplication):
        scheme = app_instance.styleHints().colorScheme()
        if scheme == Qt.ColorScheme.Light:
            return LIGHT_THEME_NAME
        if scheme == Qt.ColorScheme.Dark:
            return DEFAULT_THEME_NAME
    return _detect_platform_theme_fallback()


def _resolve_initial_theme() -> tuple[Theme, list[str]]:
    warnings: list[str] = []
    configured_name, follow_system, settings_warning = peek_theme_config()
    if settings_warning is not None:
        warnings.append(settings_warning)
    themes_file, load_error = load_themes_file()
    if load_error is not None:
        warnings.append(load_error)
    effective_name = detect_system_theme_name() if follow_system else configured_name
    theme = themes_file.find_theme(effective_name)
    if theme is None:
        warnings.append(f'Configured theme {effective_name!r} does not exist; using the {DEFAULT_THEME_NAME!r} theme.')
        theme = BUILTIN_THEMES[0]
    return theme, warnings


_initial_theme, _startup_warnings = _resolve_initial_theme()
_STATE = _RuntimeThemeState(theme=_initial_theme, transform=ThemeTransform(_initial_theme.colors))
_THEME_CHANGE_CALLBACKS: list[Callable[[], None]] = []
_CANONICAL_QSS_SET: set[str] = set()
_CANONICAL_BY_OUTPUT: dict[str, str] = {}
_COLOR_ORIGINS: dict[str, str] = {}
_TEXT_CONTRAST_ORIGINS: dict[str, tuple[str, str]] = {}

try:
    _icons_dir_path = prepare_themed_icons_dir(_STATE.transform)
except OSError as _icons_error:
    _startup_warnings.append(f'Failed to generate themed icons, using the bundled icons: {_icons_error}')
    _icons_dir_path = BUNDLED_ICONS_DIR_PATH

ICONS_DIR_PATH: Final = _icons_dir_path
"""Stable directory containing the SVG icons for the active theme."""

CHECKBOX_CHECK_ICON_PATH: Final = (
    ICONS_DIR_PATH / CHECKBOX_CHECK_FILENAME if (ICONS_DIR_PATH / CHECKBOX_CHECK_FILENAME).is_file() else BUNDLED_ICONS_DIR_PATH / 'check.svg'
)
"""SVG checkmark icon guaranteed to contrast against the active theme's accent checkbox indicator."""

THEME_STARTUP_WARNINGS: Final[tuple[str, ...]] = tuple(_startup_warnings)
"""Problems encountered while resolving the active theme, logged by the application once logging is set up."""


def log_theme_startup_warnings() -> None:
    """Log any problems encountered while resolving the active theme at import time."""
    for warning in THEME_STARTUP_WARNINGS:
        logger.warning('%s', warning)


def get_active_theme() -> Theme:
    """Return the currently active runtime `Theme`."""
    return _STATE.theme


def get_theme_generation() -> int:
    """Return a monotonically increasing counter incremented on each runtime theme change."""
    return _STATE.generation


def register_theme_change_callback(callback: Callable[[], None]) -> None:
    """Register *callback* to run whenever the active theme changes at runtime."""
    _THEME_CHANGE_CALLBACKS.append(callback)


def get_theme_transform(colors: ThemeColors) -> ThemeTransform:
    """Return a cached `ThemeTransform` for *colors* (thread-safe)."""
    with _TRANSFORM_LOCK:
        cached = _TRANSFORM_CACHE.get(colors)
        if cached is not None:
            return cached
        transform = ThemeTransform(colors)
        if len(_TRANSFORM_CACHE) >= _MAX_TRANSFORM_CACHE:
            _TRANSFORM_CACHE.clear()
        _TRANSFORM_CACHE[colors] = transform
        return transform


def commit_prepared_theme(theme: Theme, transform: ThemeTransform) -> None:
    """Activate a pre-built *theme* and *transform* on the GUI thread and notify listeners."""
    _STATE.theme = theme
    _STATE.transform = transform
    _STATE.generation += 1
    for callback in _THEME_CHANGE_CALLBACKS:
        callback()


def stage_theme_transform_and_icons(theme: Theme) -> ThemeTransform:
    """Build or look up *theme*'s `ThemeTransform` and regenerate active SVG icons in place (thread-safe)."""
    transform = get_theme_transform(theme.colors)
    try:
        prepare_themed_icons_dir(transform)
    except OSError:
        logger.exception('Failed to update themed icons in %s', ICONS_DIR_PATH)
    return transform


def try_recover_canonical_qss(text: str) -> str | None:
    """Return the canonical Dark QSS/HTML string if *text* was emitted by `themed_qss`, else `None`."""
    if not text:
        return None
    exact = _CANONICAL_BY_OUTPUT.get(text)
    if exact is not None:
        return exact
    if text in _CANONICAL_QSS_SET:
        return text
    candidates = [item for item in _CANONICAL_BY_OUTPUT.items() if len(item[0]) >= _MIN_COMPOSITE_CHUNK_LEN and item[0] in text]
    if not candidates:
        return None
    candidates.sort(key=lambda pair: len(pair[0]), reverse=True)
    recovered = text
    matched = False
    for mapped_chunk, canonical_chunk in candidates:
        if mapped_chunk in recovered:
            recovered = recovered.replace(mapped_chunk, canonical_chunk)
            matched = True
    return recovered if matched else None


def themed_qss(text: str) -> str:
    """Map every design color in a QSS stylesheet, inline CSS declaration list, or rich-text HTML onto the active theme."""
    canonical = try_recover_canonical_qss(text) or text
    _CANONICAL_QSS_SET.add(canonical)
    mapped = _STATE.transform.qss(canonical)
    _CANONICAL_BY_OUTPUT[mapped] = canonical
    return mapped


def themed_color(color: str) -> str:
    """Map a single design color string onto the active theme."""
    canonical = _COLOR_ORIGINS.get(color.lower(), color)
    mapped = _STATE.transform.color(canonical)
    _COLOR_ORIGINS[mapped.lower()] = canonical
    return mapped


def themed_qcolor(color: str | QColor | Qt.GlobalColor) -> QColor:
    """Return a design color or `@token` expression mapped onto the active theme as a `QColor` (alpha preserved)."""
    resolved = _STATE.transform.resolve_target(color)
    return resolved if resolved is not None else QColor()


def _spec_origin_key(value: str | QColor | Qt.GlobalColor) -> str:
    if isinstance(value, str) and value.lstrip().startswith('@'):
        return value.strip()
    return QColor(value).name(QColor.NameFormat.HexArgb)


def themed_text_qcolor(foreground: str | QColor | Qt.GlobalColor, background: str | QColor | Qt.GlobalColor) -> QColor:
    """Return the design text color *foreground* mapped onto the active theme, kept readable on the mapped *background*."""
    result = _STATE.transform.text_on(foreground, background)
    origin = (_spec_origin_key(foreground), _spec_origin_key(background))
    _TEXT_CONTRAST_ORIGINS[result.name(QColor.NameFormat.HexArgb).lower()] = origin
    _TEXT_CONTRAST_ORIGINS[result.name(QColor.NameFormat.HexRgb).lower()] = origin
    return result


def proprietary_text_qcolor(hex_color: str, background: str | QColor | Qt.GlobalColor) -> QColor:
    """Return a brand-locked color (e.g. Looky System purple) with fixed hue, adjusted only in lightness if needed for contrast on *background*."""
    return themed_text_qcolor(f'@lock[{hex_color}]', background)


def resolve_canonical_tint_pair(tint_color: str) -> tuple[str, str]:
    """Resolve *tint_color* back to its canonical `(foreground, background)` design color pair."""
    if tint_color.lstrip().startswith('@'):
        return tint_color.strip(), '@surface'
    origin = _TEXT_CONTRAST_ORIGINS.get(tint_color.lower())
    if origin is not None:
        return origin
    return _COLOR_ORIGINS.get(tint_color.lower(), tint_color), '@surface'


def themed_svg(svg: str) -> str:
    """Map every color in an inline SVG document onto the active theme."""
    return _STATE.transform.svg(svg)


__all__ = [
    'BUILTIN_THEMES',
    'BUILTIN_THEME_NAMES',
    'CHECKBOX_CHECK_ICON_PATH',
    'DARK_THEME_COLORS',
    'DEFAULT_THEME_NAME',
    'ICONS_DIR_PATH',
    'LIGHT_THEME_NAME',
    'THEME_COLOR_TOKENS',
    'THEME_NAME_MAX_LENGTH',
    'THEME_STARTUP_WARNINGS',
    'THEME_TOKEN_CATEGORIES',
    'CustomThemeModel',
    'Theme',
    'ThemeColorToken',
    'ThemeColors',
    'ThemeColorsModel',
    'ThemeTransform',
    'ThemesFile',
    'commit_prepared_theme',
    'detect_system_theme_name',
    'get_active_theme',
    'get_theme_generation',
    'get_theme_transform',
    'load_themes_file',
    'log_theme_startup_warnings',
    'parse_color',
    'proprietary_text_qcolor',
    'register_theme_change_callback',
    'resolve_canonical_tint_pair',
    'save_themes_file',
    'stage_theme_transform_and_icons',
    'themed_color',
    'themed_qcolor',
    'themed_qss',
    'themed_svg',
    'themed_text_qcolor',
    'try_recover_canonical_qss',
]
