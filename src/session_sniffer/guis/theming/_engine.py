"""Theme engine that maps the GUI's canonical (Dark theme) design colors onto any theme.

Every color hard-coded in the GUI is authored against the canonical Dark palette (`DARK_THEME_COLORS`).
`ThemeTransform` maps such a design color onto a target theme in the perceptual OKLab color space:

* Lightness and neutral tint follow a piecewise-linear curve through the neutral tokens
  (background, surface, control, border, muted text, text, strong text), so e.g. the canonical
  background maps exactly to the theme background and in-between greys land in-between.
* The chromatic part of a color is rotated and scaled by hue, interpolated between the chromatic
  tokens (danger, warning, success, accent, secondary), so the canonical accent maps exactly to the
  theme accent and e.g. a cyan lands between the theme's success and accent hues.
* Colors close to a chromatic token in lightness are additionally pulled towards that token's
  lightness, so solid accent fills keep their role (and their contrast with label text).

For QSS/HTML text, `ThemeTransform.qss` also keeps every declaration block's text color readable
against its background, preserving the contrast level the canonical design intended.

Transformed colors are emitted as Qt `#AARRGGBB` hex strings. The GUI never authors 8-digit hex
colors, so such values are recognized as already themed and left untouched, which makes the
transform idempotent for hex colors.
"""

import functools
import itertools
import math
import re
from typing import TYPE_CHECKING, Final

from PySide6.QtGui import QColor

from session_sniffer.guis.theming._color_math import Lab, Rgb, contrast_ratio, ensure_contrast, oklab_to_rgb, rgb_to_oklab
from session_sniffer.models.themes import DARK_THEME_COLORS, ThemeColors

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

_NEUTRAL_TOKENS: Final = ('background', 'surface', 'control', 'border', 'text_muted', 'text', 'text_strong')
_CHROMATIC_TOKENS: Final = ('danger', 'warning', 'success', 'accent', 'secondary')

_DEEPEST_EXTRAPOLATION_FACTOR: Final = 2.5
_CHROMA_RATIO_RANGE: Final = (0.25, 2.5)
_ANCHOR_LIGHTNESS_SIGMA: Final = 0.12
_ANCHOR_FULL_CHROMA: Final = 0.06
_MIN_HUE_CHROMA: Final = 1e-5
_FULL_CIRCLE: Final = 360.0
_HALF_CIRCLE: Final = 180.0

_TARGET_TEXT_CONTRAST: Final = 4.5
_MIN_BACKGROUND_ALPHA: Final = 0.5
_HEX_ARGB_LENGTH: Final = 8
_RGB_COMPONENT_COUNT: Final = 3
_RGBA_COMPONENT_COUNT: Final = 4

_NAMED_COLORS: Final = '|'.join(sorted((name for name in QColor.colorNames() if name != 'transparent'), key=len, reverse=True))

_COLOR_PATTERN: Final = (
    r'#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3})(?![0-9a-zA-Z_-])'
    r'|\brgba?\(\s*[0-9.%\s,]+\)'
    rf'|(?<![\w#-])(?:{_NAMED_COLORS})(?![\w-])'
)
_COLOR_RE: Final = re.compile(_COLOR_PATTERN, re.IGNORECASE)
_QSS_BLOCK_RE: Final = re.compile(r'\{([^{}]*)\}')
_STYLE_ATTRIBUTE_RE: Final = re.compile(r"""(\bstyle\s*=\s*)(["'])(.*?)\2""", re.IGNORECASE | re.DOTALL)
_COLOR_ATTRIBUTE_RE: Final = re.compile(r"""(\b(?:fill|stroke|stop-color|color|bgcolor|flood-color|lighting-color)\s*=\s*)(["'])([^"']*)\2""", re.IGNORECASE)
_DECLARATION_RE: Final = re.compile(r'([A-Za-z-]+)(\s*:\s*)([^;]*)')
_URL_RE: Final = re.compile(r'url\([^)]*\)', re.IGNORECASE)
_QSS_CACHE_LIMIT: Final = 4096


def _to_rgb(color: QColor) -> Rgb:
    return color.redF(), color.greenF(), color.blueF()


def _lerp(start: float, end: float, fraction: float) -> float:
    return start + (end - start) * fraction


def _signed_hue_delta(from_hue: float, to_hue: float) -> float:
    """Return the shortest signed rotation (degrees) from *from_hue* to *to_hue*."""
    return (to_hue - from_hue + _HALF_CIRCLE) % _FULL_CIRCLE - _HALF_CIRCLE


def _lch(lab: Lab) -> tuple[float, float, float]:
    return lab[0], math.hypot(lab[1], lab[2]), math.degrees(math.atan2(lab[2], lab[1])) % _FULL_CIRCLE


def parse_color(value: str) -> QColor | None:
    """Parse a CSS/QSS color token (hex, `rgb()`, `rgba()` or a named color) into a `QColor`.

    `rgba()` alpha values follow CSS semantics (`0`..`1` floats, or percentages); integer values above
    `1` are interpreted on Qt's `0`..`255` scale. Returns `None` when *value* is not a valid color.
    """
    stripped = value.strip()
    lowered = stripped.lower()
    if lowered.startswith(('rgb(', 'rgba(')):
        components = [component.strip() for component in stripped[stripped.index('(') + 1:-1].split(',')]
        if len(components) not in (_RGB_COMPONENT_COUNT, _RGBA_COMPONENT_COUNT):
            return None
        try:
            channels = [round(float(component[:-1]) * 2.55) if component.endswith('%') else round(float(component)) for component in components[:3]]
            alpha = 1.0
            if len(components) == _RGBA_COMPONENT_COUNT:
                alpha_text = components[3]
                if alpha_text.endswith('%'):
                    alpha = float(alpha_text[:-1]) / 100
                else:
                    alpha = float(alpha_text)
                    if alpha > 1:
                        alpha /= 255
        except ValueError:
            return None
        color = QColor(*(min(255, max(0, channel)) for channel in channels))
        color.setAlphaF(min(1.0, max(0.0, alpha)))
        return color
    color = QColor(stripped)
    return color if color.isValid() else None


def _is_themed_marker(value: str) -> bool:
    return value.startswith('#') and len(value) == _HEX_ARGB_LENGTH + 1


class ThemeTransform:
    """Map canonical Dark-theme design colors onto a target `ThemeColors` palette."""

    def __init__(self, colors: ThemeColors) -> None:
        """Precompute the neutral lightness curve and chromatic hue anchors for *colors*."""
        self.colors = colors
        self.is_identity = colors == DARK_THEME_COLORS

        canonical = {name: rgb_to_oklab(_to_rgb(QColor(value))) for name, value in DARK_THEME_COLORS.as_dict().items()}
        target = {name: rgb_to_oklab(_to_rgb(QColor(value))) for name, value in colors.as_dict().items()}

        # Neutral curve: (canonical lab, target lab) pairs sorted by canonical lightness, prefixed by
        # a "deepest" anchor (pure black canonically) extrapolated beyond the background.
        target_background, target_surface = target['background'], target['surface']
        deepest_lightness = min(1.0, max(0.0, target_background[0] + (target_background[0] - target_surface[0]) * _DEEPEST_EXTRAPOLATION_FACTOR))
        neutral_pairs: list[tuple[Lab, Lab]] = [((0.0, 0.0, 0.0), (deepest_lightness, target_background[1], target_background[2]))]
        neutral_pairs.extend((canonical[name], target[name]) for name in _NEUTRAL_TOKENS)
        neutral_pairs.sort(key=lambda pair: pair[0][0])
        self._neutral_pairs: Sequence[tuple[Lab, Lab]] = tuple(neutral_pairs)

        # Chromatic anchors: (canonical hue, hue offset, chroma ratio, canonical L, target L correction).
        # Hue and chroma are measured relative to the neutral axis at the anchor's canonical lightness,
        # which is exactly what `map_lab` rotates and scales, so each token maps onto its target exactly.
        anchors: list[tuple[float, float, float, float, float]] = []
        for name in _CHROMATIC_TOKENS:
            canonical_lab, target_lab = canonical[name], target[name]
            canonical_neutral, target_neutral = self._neutral_interpolation(canonical_lab[0])
            _, canonical_c, canonical_h = _lch((canonical_lab[0], canonical_lab[1] - canonical_neutral[1], canonical_lab[2] - canonical_neutral[2]))
            _, target_c, target_h = _lch((target_lab[0], target_lab[1] - target_neutral[1], target_lab[2] - target_neutral[2]))
            hue_offset = _signed_hue_delta(canonical_h, target_h) if target_c > _MIN_HUE_CHROMA else 0.0
            chroma_ratio = min(_CHROMA_RATIO_RANGE[1], max(_CHROMA_RATIO_RANGE[0], target_c / canonical_c))
            lightness_correction = target_lab[0] - target_neutral[0]
            anchors.append((canonical_h, hue_offset, chroma_ratio, canonical_lab[0], lightness_correction))
        anchors.sort(key=lambda anchor: anchor[0])
        self._chromatic_anchors: Sequence[tuple[float, float, float, float, float]] = tuple(anchors)

        self._map_rgb_cached = functools.lru_cache(maxsize=4096)(self._map_rgb_uncached)
        self._qss_cache: dict[str, str] = {}
        self._qss_outputs: set[str] = set()

    # ------------------------------------------------------------------
    # Core color mapping
    # ------------------------------------------------------------------

    def _neutral_interpolation(self, lightness: float) -> tuple[Lab, Lab]:
        """Return the (canonical, target) neutral-axis colors interpolated at canonical *lightness*."""
        pairs = self._neutral_pairs
        if lightness <= pairs[0][0][0]:
            return pairs[0]
        for (lower_canonical, lower_target), (upper_canonical, upper_target) in itertools.pairwise(pairs):
            if lightness <= upper_canonical[0]:
                span = upper_canonical[0] - lower_canonical[0]
                fraction = (lightness - lower_canonical[0]) / span if span else 0.0
                canonical_point = tuple(_lerp(lower_canonical[i], upper_canonical[i], fraction) for i in range(3))
                target_point = tuple(_lerp(lower_target[i], upper_target[i], fraction) for i in range(3))
                return (canonical_point[0], canonical_point[1], canonical_point[2]), (target_point[0], target_point[1], target_point[2])
        return pairs[-1]

    def _hue_weights(self, hue: float) -> tuple[int, int, float]:
        """Return the indexes of the chromatic anchors surrounding *hue* and the fraction between them."""
        anchors = self._chromatic_anchors
        count = len(anchors)
        for i in range(count):
            start_hue = anchors[i][0]
            end_hue = anchors[(i + 1) % count][0]
            span = (end_hue - start_hue) % _FULL_CIRCLE
            offset = (hue - start_hue) % _FULL_CIRCLE
            if offset <= span:
                return i, (i + 1) % count, (offset / span if span else 0.0)
        return 0, 0, 0.0

    def map_lab(self, lab: Lab) -> Lab:
        """Map a canonical OKLab color onto the target theme."""
        lightness, a_axis, b_axis = lab
        canonical_neutral, target_neutral = self._neutral_interpolation(lightness)
        deviation_a, deviation_b = a_axis - canonical_neutral[1], b_axis - canonical_neutral[2]
        chroma = math.hypot(deviation_a, deviation_b)

        mapped_lightness = target_neutral[0]
        mapped_a, mapped_b = target_neutral[1], target_neutral[2]
        if chroma > _MIN_HUE_CHROMA:
            hue = math.degrees(math.atan2(deviation_b, deviation_a)) % _FULL_CIRCLE
            first, second, fraction = self._hue_weights(hue)
            first_anchor, second_anchor = self._chromatic_anchors[first], self._chromatic_anchors[second]
            hue_offset = _lerp(first_anchor[1], second_anchor[1], fraction)
            chroma_ratio = _lerp(first_anchor[2], second_anchor[2], fraction)
            chroma_weight = min(1.0, chroma / _ANCHOR_FULL_CHROMA)
            for anchor, weight in ((first_anchor, 1 - fraction), (second_anchor, fraction)):
                proximity = math.exp(-(((lightness - anchor[3]) / _ANCHOR_LIGHTNESS_SIGMA) ** 2))
                mapped_lightness += weight * proximity * chroma_weight * anchor[4]
            mapped_hue = math.radians(hue + hue_offset)
            mapped_chroma = chroma * chroma_ratio
            mapped_a += mapped_chroma * math.cos(mapped_hue)
            mapped_b += mapped_chroma * math.sin(mapped_hue)
        return min(1.0, max(0.0, mapped_lightness)), mapped_a, mapped_b

    def _map_rgb_uncached(self, rgb: Rgb) -> Rgb:
        return oklab_to_rgb(self.map_lab(rgb_to_oklab(rgb)))

    def map_qcolor(self, color: QColor) -> QColor:
        """Return *color* mapped onto the target theme (alpha preserved)."""
        if self.is_identity:
            return QColor(color)
        mapped = QColor.fromRgbF(*self._map_rgb_cached(_to_rgb(color)))
        mapped.setAlpha(color.alpha())
        return mapped

    def color(self, value: str) -> str:
        """Map a single color token, returning a Qt `#AARRGGBB` string (or *value* unchanged for the identity theme)."""
        if self.is_identity or _is_themed_marker(value.strip()):
            return value
        parsed = parse_color(value)
        if parsed is None:
            return value
        return self.map_qcolor(parsed).name(QColor.NameFormat.HexArgb)

    def text_on(self, foreground: QColor, background: QColor) -> QColor:
        """Map a canonical foreground/background pair and keep the foreground readable on the mapped background."""
        mapped_foreground = self.map_qcolor(foreground)
        if self.is_identity:
            return mapped_foreground
        mapped_background = self.map_qcolor(background)
        target_ratio = min(_TARGET_TEXT_CONTRAST, contrast_ratio(_to_rgb(foreground), _to_rgb(background)))
        red, green, blue = ensure_contrast(_to_rgb(mapped_foreground), _to_rgb(mapped_background), target_ratio)
        adjusted = QColor.fromRgbF(red, green, blue)
        adjusted.setAlpha(mapped_foreground.alpha())
        return adjusted

    # ------------------------------------------------------------------
    # Text (QSS / HTML / SVG) mapping
    # ------------------------------------------------------------------

    def _map_color_match(self, match: re.Match[str]) -> str:
        return self.color(match.group(0))

    def _map_colors_in(self, text: str) -> str:
        return _sub_outside_urls(_COLOR_RE, self._map_color_match, text)

    def _map_declarations(self, body: str) -> str:
        """Map colors in a declaration list and keep its `color` readable against its background."""
        if any(_is_themed_marker(match.group(0)) for match in _COLOR_RE.finditer(body)):
            # Already (partially) themed content has no canonical colors left to compare contrast with.
            return self._map_colors_in(body)
        canonical_background: QColor | None = None
        canonical_foreground: QColor | None = None
        canonical_selection_background: QColor | None = None
        canonical_selection_foreground: QColor | None = None
        for declaration in _DECLARATION_RE.finditer(body):
            property_name = declaration.group(1).lower()
            colors = [parsed for match in _COLOR_RE.finditer(_URL_RE.sub('', declaration.group(3))) if (parsed := parse_color(match.group(0))) is not None]
            opaque = [color for color in colors if color.alphaF() >= _MIN_BACKGROUND_ALPHA]
            if property_name in ('background', 'background-color') and opaque:
                canonical_background = _average_color(opaque)
            elif property_name == 'color' and colors:
                canonical_foreground = colors[0]
            elif property_name == 'selection-background-color' and opaque:
                canonical_selection_background = _average_color(opaque)
            elif property_name == 'selection-color' and colors:
                canonical_selection_foreground = colors[0]

        if canonical_foreground is None and canonical_selection_foreground is None:
            return self._map_colors_in(body)

        background = canonical_background if canonical_background is not None else QColor(DARK_THEME_COLORS.background)
        foreground_hex = self.text_on(canonical_foreground, background).name(QColor.NameFormat.HexArgb) if canonical_foreground is not None else None
        selection_background = canonical_selection_background if canonical_selection_background is not None else background
        selection_foreground_hex = (
            self.text_on(canonical_selection_foreground, selection_background).name(QColor.NameFormat.HexArgb)
            if canonical_selection_foreground is not None
            else None
        )

        def _replace(declaration: re.Match[str]) -> str:
            property_name = declaration.group(1).lower()
            value = declaration.group(3)
            if property_name == 'color' and foreground_hex is not None:
                value = _COLOR_RE.sub(foreground_hex, value, count=1)
            elif property_name == 'selection-color' and selection_foreground_hex is not None:
                value = _COLOR_RE.sub(selection_foreground_hex, value, count=1)
            else:
                value = self._map_colors_in(value)
            return f'{declaration.group(1)}{declaration.group(2)}{value}'

        return _DECLARATION_RE.sub(_replace, body)

    def qss(self, text: str) -> str:
        """Map every design color in a QSS stylesheet, inline CSS declaration list, or Qt rich-text HTML string."""
        if self.is_identity or text in self._qss_outputs:
            return text
        if (cached := self._qss_cache.get(text)) is not None:
            return cached

        if '{' in text or 'style' in text.lower() or '=' in text:
            mapped = _QSS_BLOCK_RE.sub(lambda match: '{' + self._map_declarations(match.group(1)) + '}', text)
            mapped = _STYLE_ATTRIBUTE_RE.sub(lambda match: match.group(1) + match.group(2) + self._map_declarations(match.group(3)) + match.group(2), mapped)
            mapped = _COLOR_ATTRIBUTE_RE.sub(lambda match: match.group(1) + match.group(2) + self._map_colors_in(match.group(3)) + match.group(2), mapped)
        else:
            mapped = self._map_declarations(text)

        if len(self._qss_cache) >= _QSS_CACHE_LIMIT:
            self._qss_cache.clear()
            self._qss_outputs.clear()
        self._qss_cache[text] = mapped
        self._qss_outputs.add(mapped)
        return mapped

    def svg(self, text: str) -> str:
        """Map every color in an SVG document (attributes and inline styles), emitting `#rrggbb` colors."""
        if self.is_identity:
            return text

        def _map_svg_color(match: re.Match[str]) -> str:
            parsed = parse_color(match.group(0))
            if parsed is None:
                return match.group(0)
            return self.map_qcolor(parsed).name(QColor.NameFormat.HexRgb)

        def _map_value(value: str) -> str:
            return _sub_outside_urls(_COLOR_RE, _map_svg_color, value)

        mapped = _COLOR_ATTRIBUTE_RE.sub(lambda match: match.group(1) + match.group(2) + _map_value(match.group(3)) + match.group(2), text)
        return _STYLE_ATTRIBUTE_RE.sub(lambda match: match.group(1) + match.group(2) + _map_value(match.group(3)) + match.group(2), mapped)


def _sub_outside_urls(pattern: re.Pattern[str], replacement: Callable[[re.Match[str]], str], text: str) -> str:
    """Apply `pattern.sub` to *text* while leaving `url(...)` segments (file paths) untouched."""
    pieces: list[str] = []
    position = 0
    for url_match in _URL_RE.finditer(text):
        pieces.extend((pattern.sub(replacement, text[position:url_match.start()]), url_match.group(0)))
        position = url_match.end()
    pieces.append(pattern.sub(replacement, text[position:]))
    return ''.join(pieces)


def _average_color(colors: list[QColor]) -> QColor:
    count = len(colors)
    return QColor(
        round(sum(color.red() for color in colors) / count),
        round(sum(color.green() for color in colors) / count),
        round(sum(color.blue() for color in colors) / count),
    )
