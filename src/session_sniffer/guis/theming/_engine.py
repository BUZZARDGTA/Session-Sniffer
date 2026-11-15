"""Theme engine that resolves semantic `@token` bindings and maps canonical Dark design colors onto any theme.

Stylesheets and painting helpers can bind directly to any of the 20 `ThemeColors` tokens via `@<token>`
expressions (with optional `~<tint>/<mix_pct>` color mixing, `[<canonical_color>]` exact Dark-palette anchors,
`:hover` / `:pressed` / `:disabled` state steps, and `/<alpha_pct>` opacity), guaranteeing strict single-token
isolation with zero cross-bleeding while preserving rich gradients and translucent surfaces. Proprietary brand
colors (such as Looky System purple) can be locked via `@lock[<color>]` so themes never alter their hue.

Un-tokenized literal colors authored against `DARK_THEME_COLORS` are mapped onto the active theme in perceptual
OKLab space along a neutral lightness ramp (`background`, `surface`, `text_muted`, `text`, `text_strong`) and
four chromatic hue anchors (`danger`, `warning`, `success`, `accent`).
"""

import functools
import itertools
import math
import re
from dataclasses import fields
from typing import TYPE_CHECKING, Final

from PySide6.QtGui import QColor

from session_sniffer.guis.theming._color_math import Lab, Rgb, contrast_ratio, ensure_contrast, oklab_to_rgb, rgb_to_oklab
from session_sniffer.models.themes import DARK_THEME_COLORS, ThemeColors

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from PySide6.QtCore import Qt

_NEUTRAL_TOKENS: Final = ('background', 'surface', 'text_muted', 'text', 'text_strong')
_CHROMATIC_TOKENS: Final = ('danger', 'warning', 'success', 'accent')
_CHROMATIC_TOKEN_SET: Final[frozenset[str]] = frozenset(_CHROMATIC_TOKENS)
_TOKEN_NAMES: Final[frozenset[str]] = frozenset(field.name for field in fields(ThemeColors))
_BRAND_LOCK_DIRECTIVE: Final = 'lock'

_DARK_DEEPEST_FACTOR: Final = 0.55
_MAX_NEUTRAL_CHROMA: Final = 0.035
_CHROMA_RATIO_RANGE: Final = (0.25, 2.5)
_ANCHOR_LIGHTNESS_SIGMA: Final = 0.12
_ANCHOR_FULL_CHROMA: Final = 0.06
_MIN_HUE_CHROMA: Final = 1e-5
_LIGHT_INVERT_DL_THRESHOLD: Final = 0.14
_TRANSLUCENT_BOOST_MAX_ALPHA: Final = 0.92
_SELECTION_CHROMA_THRESHOLD: Final = 0.04
_LIGHT_SELECTION_MIN_ALPHA: Final = 0.22
_LIGHT_MID_LIGHTNESS: Final = 0.5
_LOW_ALPHA_TIER_THRESHOLD: Final = 0.08
_TINTED_NEUTRAL_CHROMA_THRESHOLD: Final = 0.008
_FULL_CIRCLE: Final = 360.0
_HALF_CIRCLE: Final = 180.0

_HOVER_LIGHT_THRESHOLD: Final = 0.80
_PRESSED_DARK_THRESHOLD: Final = 0.16
_HOVER_STEP: Final = 0.065
_PRESSED_DARK_STEP: Final = 0.04
_PRESSED_MID_STEP: Final = -0.055
_PRESSED_LIGHT_STEP: Final = -0.115
_DISABLED_BG_MIX: Final = 0.58

_TARGET_TEXT_CONTRAST: Final = 4.5
_MIN_BACKGROUND_ALPHA: Final = 0.5
_HEX_ARGB_LENGTH: Final = 8
_RGB_COMPONENT_COUNT: Final = 3
_RGBA_COMPONENT_COUNT: Final = 4

_NAMED_COLORS: Final = '|'.join(sorted((name for name in QColor.colorNames() if name != 'transparent'), key=len, reverse=True))

_AT_EXPR_PATTERN: Final = (
    r'(?<![\w#-])@(?P<t_base>[a-z_]+)'
    r'(?:~(?P<t_tint>[a-z_]+)(?:/(?P<t_mix>\d{1,3}))?)?'
    r'(?:\[(?P<t_canon>[^\]]+)\])?'
    r'(?::(?P<t_state>hover|pressed|disabled))?'
    r'(?:/(?P<t_alpha>\d{1,3}))?(?![\w-])'
)
_COLOR_PATTERN: Final = (
    _AT_EXPR_PATTERN
    + r'|#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3})(?![0-9a-zA-Z_-])'
    + r'|\brgba?\(\s*[0-9.%\s,]+\)'
    + rf'|(?<![\w#-])(?:{_NAMED_COLORS})(?![\w-])'
)
_AT_EXPR_FULL_RE: Final = re.compile(rf'^{_AT_EXPR_PATTERN}$')
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


def _mix_rgb(first: Rgb, second: Rgb, fraction: float) -> Rgb:
    return (_lerp(first[0], second[0], fraction), _lerp(first[1], second[1], fraction), _lerp(first[2], second[2], fraction))


def _clamp_neutral_chroma(lab: Lab) -> Lab:
    chroma = math.hypot(lab[1], lab[2])
    if chroma <= _MAX_NEUTRAL_CHROMA or chroma <= 0.0:
        return lab
    scale = _MAX_NEUTRAL_CHROMA / chroma
    return lab[0], lab[1] * scale, lab[2] * scale


def _signed_hue_delta(from_hue: float, to_hue: float) -> float:
    """Return the shortest signed rotation (degrees) from *from_hue* to *to_hue*."""
    return (to_hue - from_hue + _HALF_CIRCLE) % _FULL_CIRCLE - _HALF_CIRCLE


def _lch(lab: Lab) -> tuple[float, float, float]:
    return lab[0], math.hypot(lab[1], lab[2]), math.degrees(math.atan2(lab[2], lab[1])) % _FULL_CIRCLE


_CANONICAL_PALETTE: Final[dict[str, Rgb]] = {name: _to_rgb(QColor(value)) for name, value in DARK_THEME_COLORS.as_dict().items()}


def _apply_token_state(rgb: Rgb, state: str, background_rgb: Rgb) -> Rgb:
    if state == 'disabled':
        return _mix_rgb(rgb, background_rgb, _DISABLED_BG_MIX)
    lab_l, lab_a, lab_b = rgb_to_oklab(rgb)
    if state == 'hover':
        delta = _HOVER_STEP if lab_l <= _HOVER_LIGHT_THRESHOLD else -_HOVER_STEP
    elif lab_l <= _PRESSED_DARK_THRESHOLD:
        delta = _PRESSED_DARK_STEP
    elif lab_l <= _HOVER_LIGHT_THRESHOLD:
        delta = _PRESSED_MID_STEP
    else:
        delta = _PRESSED_LIGHT_STEP
    return oklab_to_rgb((min(1.0, max(0.0, lab_l + delta)), lab_a, lab_b))


def _parse_rgb_function(stripped: str) -> QColor | None:
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


def _parse_literal_color(value: str) -> QColor | None:
    """Parse a non-`@token` CSS/QSS color literal (`#hex`, `rgb()`, `rgba()`, or named color)."""
    stripped = value.strip()
    if not stripped or stripped.startswith('@'):
        return None
    if stripped.lower().startswith(('rgb(', 'rgba(')):
        return _parse_rgb_function(stripped)
    color = QColor(stripped)
    return color if color.isValid() else None


def _map_canonical_chromatic(canon_rgb: Rgb, canon_alpha: float, canon_tok_rgb: Rgb, target_tok_rgb: Rgb, *, is_dark_theme: bool) -> tuple[Rgb, float]:
    canon_l, canon_c, canon_h = _lch(rgb_to_oklab(canon_rgb))
    ctok_l, ctok_c, ctok_h = _lch(rgb_to_oklab(canon_tok_rgb))
    ttok_l, ttok_c, ttok_h = _lch(rgb_to_oklab(target_tok_rgb))

    dh = _signed_hue_delta(ctok_h, ttok_h) if ttok_c > _MIN_HUE_CHROMA and ctok_c > _MIN_HUE_CHROMA else 0.0
    c_ratio = min(2.2, max(0.2, ttok_c / ctok_c)) if ctok_c > _MIN_HUE_CHROMA else 1.0
    mapped_c = canon_c * c_ratio
    mapped_h = math.radians((canon_h + dh) % _FULL_CIRCLE)

    dl = canon_l - ctok_l
    mapped_l = min(0.92, max(0.12, ttok_l - dl * 0.25)) if not is_dark_theme and dl > _LIGHT_INVERT_DL_THRESHOLD else min(0.96, max(0.08, ttok_l + dl * 0.9))

    alpha = (
        min(0.94, canon_alpha + 0.18)
        if not is_dark_theme and _MIN_BACKGROUND_ALPHA <= canon_alpha < _TRANSLUCENT_BOOST_MAX_ALPHA
        else canon_alpha
    )
    return oklab_to_rgb((mapped_l, mapped_c * math.cos(mapped_h), mapped_c * math.sin(mapped_h))), alpha


def _map_canonical_low_alpha(base: str, canon_rgb: Rgb, canon_alpha: float, palette: dict[str, Rgb], *, is_dark_theme: bool) -> tuple[Rgb, float]:
    canon_lab = rgb_to_oklab(canon_rgb)
    canon_c = math.hypot(canon_lab[1], canon_lab[2])
    target_tok_rgb = palette[base]
    if base == 'selection' and canon_c > _SELECTION_CHROMA_THRESHOLD:
        rgb, _ = _map_canonical_chromatic(canon_rgb, 1.0, _CANONICAL_PALETTE[base], target_tok_rgb, is_dark_theme=is_dark_theme)
        alpha = max(canon_alpha, _LIGHT_SELECTION_MIN_ALPHA) if not is_dark_theme and canon_alpha < _LIGHT_SELECTION_MIN_ALPHA else canon_alpha
        return rgb, alpha
    if is_dark_theme:
        return _mix_rgb(canon_rgb, target_tok_rgb, 0.35), canon_alpha
    ttok_lab = rgb_to_oklab(target_tok_rgb)
    contrast_pole = oklab_to_rgb((0.20, ttok_lab[1] * 0.5, ttok_lab[2] * 0.5)) if canon_lab[0] > _LIGHT_MID_LIGHTNESS else (1.0, 0.0, 0.0)
    boosted_alpha = max(canon_alpha, 0.14) if canon_alpha >= _LOW_ALPHA_TIER_THRESHOLD else max(canon_alpha, 0.06)
    return _mix_rgb(target_tok_rgb, contrast_pole, 0.65), boosted_alpha


def _map_canonical_neutral(
    base: str,
    tint: str | None,
    canon_color: QColor,
    palette: dict[str, Rgb],
    *,
    is_dark_theme: bool,
) -> tuple[Rgb, float]:
    canon_rgb = _to_rgb(canon_color)
    canon_alpha = canon_color.alphaF()
    if canon_alpha < _MIN_BACKGROUND_ALPHA:
        return _map_canonical_low_alpha(base, canon_rgb, canon_alpha, palette, is_dark_theme=is_dark_theme)

    canon_lab = rgb_to_oklab(canon_rgb)
    ctok_lab = rgb_to_oklab(_CANONICAL_PALETTE[base])
    ttok_lab = rgb_to_oklab(palette[base])

    dl = canon_lab[0] - ctok_lab[0]
    mapped_l = min(1.0, max(0.0, ttok_lab[0] + dl * 0.9 if is_dark_theme else ttok_lab[0] - dl * 0.75))

    da, db = canon_lab[1] - ctok_lab[1], canon_lab[2] - ctok_lab[2]
    dev_c = math.hypot(da, db)
    if tint is not None and dev_c > _MIN_HUE_CHROMA:
        _, ctint_c, ctint_h = _lch(rgb_to_oklab(_CANONICAL_PALETTE[tint]))
        _, ttint_c, ttint_h = _lch(rgb_to_oklab(palette[tint]))
        dh = _signed_hue_delta(ctint_h, ttint_h) if ttint_c > _MIN_HUE_CHROMA and ctint_c > _MIN_HUE_CHROMA else 0.0
        c_scale = min(1.8, max(0.4, ttint_c / ctint_c)) if ctint_c > _MIN_HUE_CHROMA else 1.0
        dev_h = math.radians((math.degrees(math.atan2(db, da)) + dh) % _FULL_CIRCLE)
        scaled_c = dev_c * c_scale * (1.0 if is_dark_theme else 0.75)
        mapped_a = ttok_lab[1] + scaled_c * math.cos(dev_h)
        mapped_b = ttok_lab[2] + scaled_c * math.sin(dev_h)
    else:
        ttok_c = math.hypot(ttok_lab[1], ttok_lab[2])
        keep = (0.35 if ttok_c > _TINTED_NEUTRAL_CHROMA_THRESHOLD else 0.75) * (1.0 if is_dark_theme else 0.6)
        mapped_a = ttok_lab[1] + da * keep
        mapped_b = ttok_lab[2] + db * keep

    return oklab_to_rgb((mapped_l, mapped_a, mapped_b)), canon_alpha


def _resolve_anchored_rgb_alpha(
    base: str,
    tint: str | None,
    canon_color: QColor,
    palette: dict[str, Rgb],
) -> tuple[Rgb, float]:
    canon_rgb = _to_rgb(canon_color)
    canon_alpha = canon_color.alphaF()
    if base == _BRAND_LOCK_DIRECTIVE:
        return canon_rgb, canon_alpha

    is_dark_theme = rgb_to_oklab(palette['text'])[0] >= rgb_to_oklab(palette['background'])[0]
    same_tokens = palette[base] == _CANONICAL_PALETTE[base] and (tint is None or palette[tint] == _CANONICAL_PALETTE[tint])
    if same_tokens and (canon_alpha >= _MIN_BACKGROUND_ALPHA or is_dark_theme):
        return canon_rgb, canon_alpha

    if base in _CHROMATIC_TOKEN_SET:
        return _map_canonical_chromatic(canon_rgb, canon_alpha, _CANONICAL_PALETTE[base], palette[base], is_dark_theme=is_dark_theme)
    return _map_canonical_neutral(base, tint, canon_color, palette, is_dark_theme=is_dark_theme)


def _resolve_token_color(spec: str, palette: dict[str, Rgb]) -> QColor | None:
    """Resolve a `@token` expression against *palette*, or return `None` when *spec* is not a valid token."""
    match = _AT_EXPR_FULL_RE.match(spec.strip())
    if match is None:
        return None
    base = match.group('t_base')
    tint = match.group('t_tint')
    canon_text = match.group('t_canon')
    mix_text = match.group('t_mix')

    if base == _BRAND_LOCK_DIRECTIVE:
        if canon_text is None or tint is not None:
            return None
    elif base not in _TOKEN_NAMES or (tint is not None and tint not in _TOKEN_NAMES):
        return None

    if canon_text is not None:
        canon_color = _parse_literal_color(canon_text)
        if canon_color is None:
            return None
        rgb, alpha = _resolve_anchored_rgb_alpha(base, tint, canon_color, palette)
    else:
        if tint is not None and mix_text is None:
            return None
        rgb = palette[base]
        alpha = 1.0
        if tint is not None and mix_text is not None:
            mix_fraction = min(100, max(0, int(mix_text))) / 100.0
            rgb = _mix_rgb(rgb, palette[tint], mix_fraction)

    if (state := match.group('t_state')) is not None and base != _BRAND_LOCK_DIRECTIVE:
        rgb = _apply_token_state(rgb, state, palette['background'])

    color = QColor.fromRgbF(rgb[0], rgb[1], rgb[2])
    if (alpha_text := match.group('t_alpha')) is not None:
        color.setAlphaF(min(100, max(0, int(alpha_text))) / 100.0)
    else:
        color.setAlphaF(alpha)
    return color


def parse_color(value: str) -> QColor | None:
    """Parse a CSS/QSS color token (`@token`, hex, `rgb()`, `rgba()`, or named color) into a canonical `QColor`."""
    stripped = value.strip()
    if stripped.startswith('@'):
        return _resolve_token_color(stripped, _CANONICAL_PALETTE)
    return _parse_literal_color(stripped)


def _is_themed_marker(value: str) -> bool:
    return value.startswith('#') and len(value) == _HEX_ARGB_LENGTH + 1


class ThemeTransform:
    """Resolve `@token` expressions and map canonical Dark-theme colors onto a target `ThemeColors` palette."""

    def __init__(self, colors: ThemeColors) -> None:
        """Precompute the target token palette, neutral lightness ramp, and chromatic hue anchors for *colors*."""
        self.colors = colors
        self.is_identity = colors == DARK_THEME_COLORS
        self._target_palette: dict[str, Rgb] = {name: _to_rgb(QColor(value)) for name, value in colors.as_dict().items()}

        canonical = {name: rgb_to_oklab(rgb) for name, rgb in _CANONICAL_PALETTE.items()}
        target = {name: rgb_to_oklab(rgb) for name, rgb in self._target_palette.items()}

        target_bg = target['background']
        target_surface = target['surface']
        is_dark_theme = target['text'][0] >= target_bg[0]
        deepest_l = target_bg[0] * _DARK_DEEPEST_FACTOR if is_dark_theme else min(1.0, max(target_bg[0], target_surface[0]))
        deepest_neutral = _clamp_neutral_chroma((deepest_l, target_bg[1], target_bg[2]))

        neutral_pairs: list[tuple[Lab, Lab]] = [((0.0, 0.0, 0.0), deepest_neutral)]
        for name in _NEUTRAL_TOKENS:
            target_point = target[name] if name in ('background', 'surface') else _clamp_neutral_chroma(target[name])
            neutral_pairs.append((canonical[name], target_point))
        neutral_pairs.sort(key=lambda pair: pair[0][0])
        self._neutral_pairs: Sequence[tuple[Lab, Lab]] = tuple(neutral_pairs)

        anchors: list[tuple[float, float, float, float, float]] = []
        for name in _CHROMATIC_TOKENS:
            canonical_lab, target_lab = canonical[name], target[name]
            _, target_neutral = self._neutral_interpolation(canonical_lab[0])
            _, canonical_c, canonical_h = _lch(canonical_lab)
            _, target_c, target_h = _lch(target_lab)
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
        """Return the `(canonical, target)` neutral-axis colors interpolated at canonical *lightness*."""
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
            # Clamp high-chroma background bleed when mapping chromatic foregrounds/accents.
            neutral_a, neutral_b = _clamp_neutral_chroma(target_neutral)[1:]
            chroma_blend = min(1.0, chroma / _ANCHOR_FULL_CHROMA)
            mapped_a = _lerp(mapped_a, neutral_a, chroma_blend)
            mapped_b = _lerp(mapped_b, neutral_b, chroma_blend)

            hue = math.degrees(math.atan2(deviation_b, deviation_a)) % _FULL_CIRCLE
            first, second, fraction = self._hue_weights(hue)
            first_anchor, second_anchor = self._chromatic_anchors[first], self._chromatic_anchors[second]
            hue_offset = _lerp(first_anchor[1], second_anchor[1], fraction)
            chroma_ratio = _lerp(first_anchor[2], second_anchor[2], fraction)
            for anchor, weight in ((first_anchor, 1 - fraction), (second_anchor, fraction)):
                proximity = math.exp(-(((lightness - anchor[3]) / _ANCHOR_LIGHTNESS_SIGMA) ** 2))
                mapped_lightness += weight * proximity * chroma_blend * anchor[4]
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

    def resolve_canonical(self, value: str | QColor | Qt.GlobalColor) -> QColor | None:
        """Resolve *value* (`@token` expression, CSS color string, or `QColor`) in the canonical Dark palette."""
        if isinstance(value, str):
            return parse_color(value)
        qcolor = QColor(value)
        return qcolor if qcolor.isValid() else None

    def resolve_target(self, value: str | QColor | Qt.GlobalColor) -> QColor | None:
        """Resolve *value* (`@token` expression, CSS color string, or `QColor`) in the target theme palette."""
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith('@'):
                return _resolve_token_color(stripped, self._target_palette)
            parsed = parse_color(stripped)
            if parsed is None or _is_themed_marker(stripped):
                return parsed
            return self.map_qcolor(parsed)
        qcolor = QColor(value)
        return self.map_qcolor(qcolor) if qcolor.isValid() else None

    def color(self, value: str) -> str:
        """Map a single color or `@token` string, returning a Qt `#AARRGGBB` string."""
        stripped = value.strip()
        if stripped.startswith('@'):
            resolved = _resolve_token_color(stripped, self._target_palette)
            return value if resolved is None else resolved.name(QColor.NameFormat.HexArgb)
        if self.is_identity or _is_themed_marker(stripped):
            return value
        parsed = parse_color(stripped)
        return value if parsed is None else self.map_qcolor(parsed).name(QColor.NameFormat.HexArgb)

    def _contrast_pair(self, canon_fg: QColor, canon_bg: QColor, target_fg: QColor, target_bg: QColor) -> QColor:
        target_ratio = min(_TARGET_TEXT_CONTRAST, contrast_ratio(_to_rgb(canon_fg), _to_rgb(canon_bg)))
        red, green, blue = ensure_contrast(_to_rgb(target_fg), _to_rgb(target_bg), target_ratio)
        adjusted = QColor.fromRgbF(red, green, blue)
        adjusted.setAlpha(target_fg.alpha())
        return adjusted

    def text_on(self, foreground: str | QColor | Qt.GlobalColor, background: str | QColor | Qt.GlobalColor) -> QColor:
        """Map a foreground/background pair (`@token` or `QColor`) and keep foreground readable on the target background."""
        target_fg = self.resolve_target(foreground)
        if target_fg is None or self.is_identity:
            return target_fg if target_fg is not None else QColor()
        canon_fg = self.resolve_canonical(foreground)
        canon_bg = self.resolve_canonical(background)
        target_bg = self.resolve_target(background)
        if canon_fg is None or canon_bg is None or target_bg is None:
            return target_fg
        return self._contrast_pair(canon_fg, canon_bg, target_fg, target_bg)

    # ------------------------------------------------------------------
    # Text (QSS / HTML / SVG) mapping
    # ------------------------------------------------------------------

    def _map_color_match(self, match: re.Match[str]) -> str:
        return self.color(match.group(0))

    def _map_colors_in(self, text: str) -> str:
        return _sub_outside_urls(_COLOR_RE, self._map_color_match, text)

    def _resolve_declaration_fg_hex(
        self,
        fg_spec: str | None,
        bg_pair: tuple[QColor, QColor] | None,
    ) -> str | None:
        if fg_spec is None:
            return None
        if bg_pair is None:
            if fg_spec.startswith('@') and not fg_spec.startswith('@lock[') and '[' not in fg_spec:
                return self.color(fg_spec)
            bg_pair = (QColor(DARK_THEME_COLORS.background), QColor(self.colors.background))
        canon_fg = self.resolve_canonical(fg_spec)
        target_fg = self.resolve_target(fg_spec)
        if canon_fg is None or target_fg is None:
            return None
        return self._contrast_pair(canon_fg, bg_pair[0], target_fg, bg_pair[1]).name(QColor.NameFormat.HexArgb)

    def _map_declarations(self, body: str) -> str:
        """Map colors in a declaration list and keep its `color` readable against its explicit background."""
        if self.is_identity or any(_is_themed_marker(match.group(0)) for match in _COLOR_RE.finditer(body)):
            return self._map_colors_in(body)

        bg_pair: tuple[QColor, QColor] | None = None
        sel_bg_pair: tuple[QColor, QColor] | None = None
        fg_spec: str | None = None
        sel_fg_spec: str | None = None

        for declaration in _DECLARATION_RE.finditer(body):
            prop = declaration.group(1).lower()
            specs = [m.group(0) for m in _COLOR_RE.finditer(_URL_RE.sub('', declaration.group(3)))]
            opaque_pairs = [
                (canon, targ)
                for spec in specs
                if (canon := self.resolve_canonical(spec)) is not None
                and canon.alphaF() >= _MIN_BACKGROUND_ALPHA
                and (targ := self.resolve_target(spec)) is not None
            ]
            if prop in ('background', 'background-color') and opaque_pairs:
                bg_pair = (_average_color([p[0] for p in opaque_pairs]), _average_color([p[1] for p in opaque_pairs]))
            elif prop == 'color' and specs:
                fg_spec = specs[0]
            elif prop == 'selection-background-color' and opaque_pairs:
                sel_bg_pair = (_average_color([p[0] for p in opaque_pairs]), _average_color([p[1] for p in opaque_pairs]))
            elif prop == 'selection-color' and specs:
                sel_fg_spec = specs[0]

        if fg_spec is None and sel_fg_spec is None:
            return self._map_colors_in(body)

        foreground_hex = self._resolve_declaration_fg_hex(fg_spec, bg_pair)
        selection_foreground_hex = self._resolve_declaration_fg_hex(sel_fg_spec, sel_bg_pair or bg_pair)

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
        """Map every `@token` and design color in a QSS stylesheet, inline CSS list, or rich-text HTML string."""
        if text in self._qss_outputs or (self.is_identity and '@' not in text):
            return text
        if (cached := self._qss_cache.get(text)) is not None:
            return cached

        if '{' in text or _STYLE_ATTRIBUTE_RE.search(text) is not None or _COLOR_ATTRIBUTE_RE.search(text) is not None:
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
        if self.is_identity and '@' not in text:
            return text

        def _map_svg_color(match: re.Match[str]) -> str:
            resolved = self.resolve_target(match.group(0))
            return match.group(0) if resolved is None else resolved.name(QColor.NameFormat.HexRgb)

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
