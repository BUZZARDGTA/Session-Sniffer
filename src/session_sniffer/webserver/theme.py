"""Web-safe theme serialization and Qt-to-CSS color conversion for the embedded web server."""

from functools import lru_cache
from typing import TYPE_CHECKING, Final

from PySide6.QtGui import QColor

from session_sniffer.guis.theming import DARK_THEME_COLORS, Theme, get_active_theme, get_theme_generation, get_theme_transform
from session_sniffer.guis.theming._color_math import Rgb, contrast_ratio, rgb_to_oklab

if TYPE_CHECKING:
    from session_sniffer.guis.theming import ThemeTransform

_OPAQUE_ALPHA: Final = 255
_WHITE_RGB: Final[Rgb] = (1.0, 1.0, 1.0)
_DARK_INK_RGB: Final[Rgb] = (11 / 255.0, 13 / 255.0, 16 / 255.0)

_DERIVED_COLOR_SPECS: Final[tuple[tuple[str, str, str], ...]] = (
    ('--ss-header-badge-bg', '@surface[rgba(255, 255, 255, 0.06)]', 'rgba(255, 255, 255, 0.06)'),
    ('--ss-header-badge-border', '@border[rgba(255, 255, 255, 0.10)]', 'rgba(255, 255, 255, 0.10)'),
    ('--ss-header-card-bg', '@surface[rgba(255, 255, 255, 0.03)]', 'rgba(255, 255, 255, 0.03)'),
    ('--ss-header-card-border', '@border[rgba(255, 255, 255, 0.08)]', 'rgba(255, 255, 255, 0.08)'),
    ('--ss-status-pill-bg', '@surface[rgba(255, 255, 255, 0.04)]', 'rgba(255, 255, 255, 0.04)'),
    ('--ss-status-pill-border', '@border[rgba(255, 255, 255, 0.09)]', 'rgba(255, 255, 255, 0.09)'),
    ('--ss-stopped-bg', '@danger[rgba(239, 68, 68, 0.12)]', 'rgba(239, 68, 68, 0.12)'),
    ('--ss-stopped-border', '@danger[rgba(239, 68, 68, 0.35)]', 'rgba(239, 68, 68, 0.35)'),
    ('--ss-search-bg', '@input[rgba(255, 255, 255, 0.04)]', 'rgba(255, 255, 255, 0.04)'),
    ('--ss-search-bg-hover', '@input[rgba(255, 255, 255, 0.06)]', 'rgba(255, 255, 255, 0.06)'),
    ('--ss-search-bg-focus', '@input[rgba(0, 0, 0, 0.45)]', 'rgba(0, 0, 0, 0.45)'),
    ('--ss-search-border', '@border[rgba(255, 255, 255, 0.10)]', 'rgba(255, 255, 255, 0.10)'),
    ('--ss-search-border-hover', '@border[rgba(255, 255, 255, 0.18)]', 'rgba(255, 255, 255, 0.18)'),
    ('--ss-control-hover', '@control:hover', '#3e3e42'),
    ('--ss-control-pressed', '@control:pressed', '#1e1e1e'),
    ('--ss-connected-bar-top', '@table_header~success[#12271d]', '#12271d'),
    ('--ss-connected-bar-bottom', '@table_header~success[#0c1612]', '#0c1612'),
    ('--ss-connected-border', '@border~success[#1c4f32]', '#1c4f32'),
    ('--ss-connected-table-bg', '@table~success[#101412]', '#101412'),
    ('--ss-connected-table-alt', '@table_alt~success[#131915]', '#131915'),
    ('--ss-connected-grid', '@border~success[#18241d]', '#18241d'),
    ('--ss-connected-selection', '@selection~success[#1a3826]', '#1a3826'),
    ('--ss-connected-col-header-bg', '@table_header~success[#141d17]', '#141d17'),
    ('--ss-connected-badge-bg', '@success[rgba(34, 197, 94, 0.14)]', 'rgba(34, 197, 94, 0.14)'),
    ('--ss-connected-badge-border', '@success[rgba(34, 197, 94, 0.36)]', 'rgba(34, 197, 94, 0.36)'),
    ('--ss-disconnected-bar-top', '@table_header~danger[#2a181a]', '#2a181a'),
    ('--ss-disconnected-bar-bottom', '@table_header~danger[#180f11]', '#180f11'),
    ('--ss-disconnected-border', '@border~danger[#59282a]', '#59282a'),
    ('--ss-disconnected-table-bg', '@table~danger[#180e11]', '#180e11'),
    ('--ss-disconnected-table-alt', '@table_alt~danger[#241317]', '#241317'),
    ('--ss-disconnected-grid', '@border~danger[#2d181c]', '#2d181c'),
    ('--ss-disconnected-selection', '@selection~danger[#3d1a1e]', '#3d1a1e'),
    ('--ss-disconnected-col-header-bg', '@table_header~danger[#1d1315]', '#1d1315'),
    ('--ss-disconnected-badge-bg', '@danger[rgba(239, 68, 68, 0.14)]', 'rgba(239, 68, 68, 0.14)'),
    ('--ss-disconnected-badge-border', '@danger[rgba(239, 68, 68, 0.36)]', 'rgba(239, 68, 68, 0.36)'),
    ('--ss-scrollbar-track', '@table[#111215]', '#111215'),
    ('--ss-scrollbar-thumb', '@scrollbar[#2a2d36]', '#2a2d36'),
    ('--ss-scrollbar-thumb-hover', '@scrollbar[#3d4250]', '#3d4250'),
)

_DERIVED_TEXT_SPECS: Final[tuple[tuple[str, str, str, str], ...]] = (
    ('--ss-header-subtitle', '@text_muted[#64748b]', '@background', '#64748b'),
    ('--ss-header-subtitle-hi', '@success[#22c55e]', '@background', '#22c55e'),
    ('--ss-header-stat-value', '@success[#22c55e]', '@surface', '#22c55e'),
    ('--ss-stopped-fg', '@danger[#ef4444]', '@background', '#ef4444'),
    ('--ss-accent-text', '@accent[#88c0d0]', '@surface', '#88c0d0'),
    ('--ss-status-accent', '@accent[#88c0d0]', '@statusbar', '#88c0d0'),
    ('--ss-status-success', '@success[#22c55e]', '@statusbar', '#22c55e'),
    ('--ss-status-warning', '@warning[#f59e0b]', '@statusbar', '#f59e0b'),
    ('--ss-status-danger', '@danger[#ef4444]', '@statusbar', '#ef4444'),
    ('--ss-connected-accent-text', '@success[#22c55e]', '@table_header~success[#12271d]', '#22c55e'),
    ('--ss-disconnected-accent-text', '@danger[#ef4444]', '@table_header~danger[#2a181a]', '#ef4444'),
    ('--ss-connected-col-header-text', '@text_muted[#94a3b8]', '@table_header~success[#141d17]', '#94a3b8'),
    ('--ss-disconnected-col-header-text', '@text_muted[#94a3b8]', '@table_header~danger[#1d1315]', '#94a3b8'),
    ('--ss-connected-empty-title', '@text[#e2e8f0]', '@table~success[#101412]', '#e2e8f0'),
    ('--ss-connected-empty-subtitle', '@text_muted[#64748b]', '@table~success[#101412]', '#64748b'),
    ('--ss-disconnected-empty-title', '@text[#e2e8f0]', '@table~danger[#180e11]', '#e2e8f0'),
    ('--ss-disconnected-empty-subtitle', '@text_muted[#64748b]', '@table~danger[#180e11]', '#64748b'),
    ('--ss-looky-text', '@lock[#c084fc]', '@table[#121212]', '#c084fc'),
    ('--ss-disconnected-looky-text', '@lock[#a855f7]', '@table[#121212]', '#a855f7'),
)


def qcolor_to_css(color: QColor) -> str:
    """Convert a `QColor` into a standard CSS `#rrggbb` or `rgba(...)` color string."""
    if color.alpha() >= _OPAQUE_ALPHA:
        return color.name(QColor.NameFormat.HexRgb)
    return f'rgba({color.red()}, {color.green()}, {color.blue()}, {color.alphaF():.3f})'


def _hex_to_rgb_ints(hex_color: str) -> tuple[int, int, int]:
    cleaned = hex_color.lstrip('#')
    return int(cleaned[0:2], 16), int(cleaned[2:4], 16), int(cleaned[4:6], 16)


def _hex_to_unit_rgb(hex_color: str) -> Rgb:
    red, green, blue = _hex_to_rgb_ints(hex_color)
    return red / 255.0, green / 255.0, blue / 255.0


def _contrast_ink_hex(fill_hex: str) -> str:
    fill_rgb = _hex_to_unit_rgb(fill_hex)
    return '#ffffff' if contrast_ratio(_WHITE_RGB, fill_rgb) >= contrast_ratio(_DARK_INK_RGB, fill_rgb) else '#0b0d10'


def _resolve_css(transform: ThemeTransform, spec: str, fallback: str) -> str:
    resolved = transform.resolve_target(spec)
    return qcolor_to_css(resolved) if resolved is not None and resolved.isValid() else fallback


def _resolve_text_css(transform: ThemeTransform, foreground: str, background: str, fallback: str) -> str:
    resolved = transform.text_on(foreground, background)
    return qcolor_to_css(resolved) if resolved.isValid() else fallback


@lru_cache(maxsize=24)
def _compute_theme_variables(theme: Theme) -> tuple[bool, tuple[tuple[str, str], ...]]:
    """Compute the dark/light classification and all CSS custom properties for *theme*."""
    colors = theme.colors
    is_dark = rgb_to_oklab(_hex_to_unit_rgb(colors.text))[0] >= rgb_to_oklab(_hex_to_unit_rgb(colors.background))[0]
    transform = get_theme_transform(colors)

    css_vars: list[tuple[str, str]] = []
    for token_name, hex_value in colors.as_dict().items():
        css_key = token_name.replace('_', '-')
        red, green, blue = _hex_to_rgb_ints(hex_value)
        css_vars.append((f'--ss-{css_key}', hex_value))
        css_vars.append((f'--ss-{css_key}-rgb', f'{red}, {green}, {blue}'))

    for var_name, spec, fallback in _DERIVED_COLOR_SPECS:
        css_vars.append((var_name, _resolve_css(transform, spec, fallback)))

    for var_name, fg_spec, bg_spec, fallback in _DERIVED_TEXT_SPECS:
        css_vars.append((var_name, _resolve_text_css(transform, fg_spec, bg_spec, fallback)))

    css_vars.extend(
        (
            ('--ss-on-accent', _contrast_ink_hex(colors.accent)),
            ('--ss-on-success', _contrast_ink_hex(colors.success)),
            ('--ss-on-danger', _contrast_ink_hex(colors.danger)),
            ('--ss-shadow-sm', '0 4px 14px rgba(0, 0, 0, 0.28)' if is_dark else '0 2px 10px rgba(15, 23, 42, 0.07)'),
            ('--ss-shadow-md', '0 12px 32px rgba(0, 0, 0, 0.36)' if is_dark else '0 8px 24px rgba(15, 23, 42, 0.10)'),
        ),
    )

    return is_dark, tuple(css_vars)


def build_web_theme_payload(theme: Theme | None = None) -> dict[str, object]:
    """Return a JSON-serializable theme dictionary for the active (or given) `Theme`."""
    active_theme = get_active_theme() if theme is None else theme
    is_dark, css_vars = _compute_theme_variables(active_theme)
    return {
        'name': active_theme.name,
        'generation': get_theme_generation(),
        'scheme': 'dark' if is_dark else 'light',
        'is_dark': is_dark,
        'is_canonical_dark': active_theme.colors == DARK_THEME_COLORS,
        'vars': dict(css_vars),
    }


def render_web_theme_css(theme: Theme | None = None) -> str:
    """Render a standalone `:root` CSS stylesheet for the active (or given) `Theme`."""
    active_theme = get_active_theme() if theme is None else theme
    is_dark, css_vars = _compute_theme_variables(active_theme)
    scheme = 'dark' if is_dark else 'light'
    lines = [
        ':root {',
        f'    color-scheme: {scheme};',
        *(f'    {name}: {value};' for name, value in css_vars),
        '}',
        '',
    ]
    return '\r\n'.join(lines)
