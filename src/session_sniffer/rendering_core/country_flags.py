"""Cache and lookup utilities for country flag images."""

import logging
from functools import lru_cache
from typing import TYPE_CHECKING

from PySide6.QtGui import QImage

from session_sniffer.constants.local import IMAGES_DIR_PATH
from session_sniffer.models.player_lookup import PlayerCountryFlag

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

COUNTRY_FLAGS_DIR_PATH = IMAGES_DIR_PATH / 'country_flags'
_ISO_ALPHA2_LEN = 2

_country_flag_cache: dict[str, PlayerCountryFlag] = {}
_missing_country_flag_codes: set[str] = set()


@lru_cache(maxsize=1)
def _get_available_country_flag_codes() -> frozenset[str]:
    """Return the cached set of uppercase ISO alpha-2 country codes available on disk."""
    if not COUNTRY_FLAGS_DIR_PATH.is_dir():
        return frozenset()
    return frozenset(
        flag_path.stem.upper()
        for flag_path in COUNTRY_FLAGS_DIR_PATH.glob('*.png')
        if len(flag_path.stem) == _ISO_ALPHA2_LEN and flag_path.stem.isascii() and flag_path.stem.isalpha()
    )


def _normalize_alpha2_code(country_code: str) -> str | None:
    normalized = country_code.strip().upper()
    if len(normalized) == _ISO_ALPHA2_LEN and normalized.isascii() and normalized.isalpha():
        return normalized
    return None


def has_country_flag(country_code: str) -> bool:
    """Return `True` when a bundled PNG flag exists for ISO alpha-2 *country_code*."""
    normalized = _normalize_alpha2_code(country_code)
    return normalized is not None and normalized in _get_available_country_flag_codes()


def resolve_country_flag_path(country_code: str) -> Path | None:
    """Return the filesystem path to the bundled PNG flag for *country_code*, or `None` if unavailable."""
    normalized = _normalize_alpha2_code(country_code)
    if normalized is None or normalized not in _get_available_country_flag_codes():
        return None
    flag_path = COUNTRY_FLAGS_DIR_PATH / f'{normalized}.png'
    return flag_path if flag_path.is_file() else None


def preload_country_flags() -> None:
    """Preload all country flag images into memory cache.

    Safe to execute from a background thread because QImage decoding does not
    require the Qt GUI thread.
    """
    if not COUNTRY_FLAGS_DIR_PATH.is_dir():
        return

    for flag_path in COUNTRY_FLAGS_DIR_PATH.glob('*.png'):
        country_code = flag_path.stem.upper()
        if country_code in _country_flag_cache:
            continue

        try:
            image = QImage()
            image.loadFromData(flag_path.read_bytes())
            if not image.isNull():
                _country_flag_cache[country_code] = PlayerCountryFlag(image)
        except OSError as e:
            logger.debug('Failed to preload country flag "%s": %s', flag_path, e)


def get_country_flag(country_code: str) -> PlayerCountryFlag | None:
    """Return the cached PlayerCountryFlag for the given country code, loading on demand if not cached."""
    country_code = country_code.strip().upper()
    if not country_code or country_code in _missing_country_flag_codes:
        return None

    if country_code in _country_flag_cache:
        return _country_flag_cache[country_code]

    flag_path = COUNTRY_FLAGS_DIR_PATH / f'{country_code}.png'
    if not flag_path.exists():
        logger.warning('Missing country flag image for country code: %s', country_code)
        _missing_country_flag_codes.add(country_code)
        return None

    try:
        image = QImage()
        image.loadFromData(flag_path.read_bytes())
    except OSError as e:
        logger.debug('Failed to load country flag "%s": %s', flag_path, e)
        _missing_country_flag_codes.add(country_code)
        return None

    if image.isNull():
        _missing_country_flag_codes.add(country_code)
        return None

    country_flag = PlayerCountryFlag(image)
    _country_flag_cache[country_code] = country_flag
    return country_flag


def warm_country_flag_icons() -> None:
    """Warm up QPixmap and QIcon instances for all preloaded country flags.

    Must be called from the Qt GUI thread.
    """
    for flag in _country_flag_cache.values():
        _ = flag.icon
