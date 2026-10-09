"""Cache and lookup utilities for country flag images."""

import logging

from PySide6.QtGui import QImage

from session_sniffer.constants.local import IMAGES_DIR_PATH
from session_sniffer.models.player_lookup import PlayerCountryFlag

logger = logging.getLogger(__name__)

COUNTRY_FLAGS_DIR_PATH = IMAGES_DIR_PATH / 'country_flags'

_country_flag_cache: dict[str, PlayerCountryFlag] = {}
_missing_country_flag_codes: set[str] = set()


def preload_country_flags() -> int:
    """Preload all country flag images into memory cache.

    Safe to execute from a background thread because QImage decoding does not
    require the Qt GUI thread. Returns the total count of preloaded flags.
    """
    if not COUNTRY_FLAGS_DIR_PATH.is_dir():
        return 0

    loaded_count = 0
    for flag_path in COUNTRY_FLAGS_DIR_PATH.glob('*.png'):
        country_code = flag_path.stem.upper()
        if country_code in _country_flag_cache:
            continue

        try:
            image = QImage()
            image.loadFromData(flag_path.read_bytes())
            if not image.isNull():
                _country_flag_cache[country_code] = PlayerCountryFlag(image)
                loaded_count += 1
        except OSError as e:
            logger.debug('Failed to preload country flag "%s": %s', flag_path, e)

    return loaded_count


def get_country_flag(country_code: str) -> PlayerCountryFlag | None:
    """Return the cached PlayerCountryFlag for the given country code, loading on demand if not cached."""
    country_code = country_code.strip().upper()
    if not country_code:
        return None

    if country_code in _country_flag_cache:
        return _country_flag_cache[country_code]

    if country_code in _missing_country_flag_codes:
        return None

    flag_path = COUNTRY_FLAGS_DIR_PATH / f'{country_code}.png'
    if not flag_path.exists():
        logger.warning('Missing country flag image for country code: %s', country_code)
        _missing_country_flag_codes.add(country_code)
        return None

    image = QImage()
    image.loadFromData(flag_path.read_bytes())
    if image.isNull():
        _missing_country_flag_codes.add(country_code)
        return None

    country_flag = PlayerCountryFlag(image)
    _country_flag_cache[country_code] = country_flag
    return country_flag


def warm_country_flag_icons() -> int:
    """Warm up QPixmap and QIcon instances for all preloaded country flags.

    Must be called from the Qt GUI thread. Returns the total count of warmed flags.
    """
    warmed_count = 0
    for flag in _country_flag_cache.values():
        _ = flag.icon
        warmed_count += 1
    return warmed_count
