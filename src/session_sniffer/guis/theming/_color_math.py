"""Pure color-space helpers (sRGB <-> OKLab) and WCAG contrast utilities used by the theme engine."""

import math

type Rgb = tuple[float, float, float]
"""Linear-agnostic sRGB triplet with each channel in the `0.0`..`1.0` range."""

type Lab = tuple[float, float, float]
"""OKLab triplet `(L, a, b)`."""

_SRGB_LINEAR_THRESHOLD = 0.04045
_SRGB_ENCODE_THRESHOLD = 0.0031308
_GAMUT_EPSILON = 1e-4
_GAMUT_SEARCH_STEPS = 18


def _srgb_to_linear(channel: float) -> float:
    if channel <= _SRGB_LINEAR_THRESHOLD:
        return channel / 12.92
    return math.pow((channel + 0.055) / 1.055, 2.4)


def _linear_to_srgb(channel: float) -> float:
    if channel <= _SRGB_ENCODE_THRESHOLD:
        return channel * 12.92
    return 1.055 * math.pow(channel, 1 / 2.4) - 0.055


def rgb_to_oklab(rgb: Rgb) -> Lab:
    """Convert an sRGB triplet to OKLab."""
    red, green, blue = (_srgb_to_linear(channel) for channel in rgb)
    long_cone = math.cbrt(0.4122214708 * red + 0.5363325363 * green + 0.0514459929 * blue)
    medium_cone = math.cbrt(0.2119034982 * red + 0.6806995451 * green + 0.1073969566 * blue)
    short_cone = math.cbrt(0.0883024619 * red + 0.2817188376 * green + 0.6299787005 * blue)
    return (
        0.2104542553 * long_cone + 0.7936177850 * medium_cone - 0.0040720468 * short_cone,
        1.9779984951 * long_cone - 2.4285922050 * medium_cone + 0.4505937099 * short_cone,
        0.0259040371 * long_cone + 0.7827717662 * medium_cone - 0.8086757660 * short_cone,
    )


def _oklab_to_linear_rgb(lab: Lab) -> Rgb:
    lightness, a_axis, b_axis = lab
    long_cone = (lightness + 0.3963377774 * a_axis + 0.2158037573 * b_axis) ** 3
    medium_cone = (lightness - 0.1055613458 * a_axis - 0.0638541728 * b_axis) ** 3
    short_cone = (lightness - 0.0894841775 * a_axis - 1.2914855480 * b_axis) ** 3
    return (
        4.0767416621 * long_cone - 3.3077115913 * medium_cone + 0.2309699292 * short_cone,
        -1.2684380046 * long_cone + 2.6097574011 * medium_cone - 0.3413193965 * short_cone,
        -0.0041960863 * long_cone - 0.7034186147 * medium_cone + 1.7076147010 * short_cone,
    )


def _is_in_gamut(linear_rgb: Rgb) -> bool:
    return all(-_GAMUT_EPSILON <= channel <= 1 + _GAMUT_EPSILON for channel in linear_rgb)


def oklab_to_rgb(lab: Lab) -> Rgb:
    """Convert OKLab to sRGB, reducing chroma (preserving lightness and hue) until the color fits the sRGB gamut."""
    lightness = min(1.0, max(0.0, lab[0]))
    a_axis, b_axis = lab[1], lab[2]
    linear_rgb = _oklab_to_linear_rgb((lightness, a_axis, b_axis))
    if not _is_in_gamut(linear_rgb):
        low, high = 0.0, 1.0
        for _ in range(_GAMUT_SEARCH_STEPS):
            middle = (low + high) / 2
            if _is_in_gamut(_oklab_to_linear_rgb((lightness, a_axis * middle, b_axis * middle))):
                low = middle
            else:
                high = middle
        linear_rgb = _oklab_to_linear_rgb((lightness, a_axis * low, b_axis * low))
    red, green, blue = (min(1.0, max(0.0, _linear_to_srgb(min(1.0, max(0.0, channel))))) for channel in linear_rgb)
    return red, green, blue


def relative_luminance(rgb: Rgb) -> float:
    """Return the WCAG 2.x relative luminance of an sRGB triplet."""
    red, green, blue = (_srgb_to_linear(channel) for channel in rgb)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def contrast_ratio(first: Rgb, second: Rgb) -> float:
    """Return the WCAG 2.x contrast ratio between two sRGB triplets (`1.0`..`21.0`)."""
    first_luminance, second_luminance = relative_luminance(first), relative_luminance(second)
    lighter, darker = max(first_luminance, second_luminance), min(first_luminance, second_luminance)
    return (lighter + 0.05) / (darker + 0.05)


def ensure_contrast(foreground: Rgb, background: Rgb, minimum_ratio: float) -> Rgb:
    """Return *foreground* with its OKLab lightness pushed away from *background* until *minimum_ratio* is reached.

    Hue and chroma are preserved as far as the sRGB gamut allows. When neither direction can reach the
    requested ratio, the direction offering the higher contrast is used at its extreme.
    """
    if contrast_ratio(foreground, background) >= minimum_ratio:
        return foreground

    foreground_lab = rgb_to_oklab(foreground)
    satisfying: list[tuple[float, Rgb]] = []  # (lightness change, color)
    extremes: list[tuple[float, Rgb]] = []  # (contrast ratio, color)
    for target_lightness in (1.0, 0.0):
        extreme = oklab_to_rgb((target_lightness, foreground_lab[1], foreground_lab[2]))
        extreme_ratio = contrast_ratio(extreme, background)
        if extreme_ratio < minimum_ratio:
            extremes.append((extreme_ratio, extreme))
            continue
        # Binary search the smallest lightness move towards `target_lightness` that satisfies the ratio.
        near, far, best = foreground_lab[0], target_lightness, extreme
        for _ in range(_GAMUT_SEARCH_STEPS):
            middle = (near + far) / 2
            candidate = oklab_to_rgb((middle, foreground_lab[1], foreground_lab[2]))
            if contrast_ratio(candidate, background) >= minimum_ratio:
                best, far = candidate, middle
            else:
                near = middle
        satisfying.append((abs(far - foreground_lab[0]), best))
    if satisfying:
        return min(satisfying, key=lambda item: item[0])[1]
    return max(extremes, key=lambda item: item[0])[1]
