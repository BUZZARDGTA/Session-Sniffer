"""Application internationalization (i18n), locale detection, and plural-aware translation lookup."""

import json
import locale
import logging
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from PySide6.QtCore import QCoreApplication, QLibraryInfo, QLocale, Qt, QTranslator
from PySide6.QtGui import QGuiApplication

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

TRANSLATIONS_DIR_PATH: Final[Path] = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent.parent.parent)) / 'resources' / 'translations'

DEFAULT_LANGUAGE: Final[str] = 'en'

SUPPORTED_LANGUAGES: Final[dict[str, str]] = {
    'en': 'English',
    'ar': 'العربية (Arabic)',
    'bg': 'Български (Bulgarian)',
    'ca': 'Català (Catalan)',
    'cs': 'Čeština (Czech)',
    'da': 'Dansk (Danish)',
    'de': 'Deutsch (German)',
    'es': 'Español (Spanish)',
    'fa': 'فارسی (Persian)',
    'fi': 'Suomi (Finnish)',
    'fr': 'Français (French)',
    'gd': 'Gàidhlig (Scottish Gaelic)',
    'he': 'עברית (Hebrew)',
    'hr': 'Hrvatski (Croatian)',
    'hu': 'Magyar (Hungarian)',
    'it': 'Italiano (Italian)',
    'ja': '日本語 (Japanese)',
    'ka': 'ქართული (Georgian)',
    'kk': 'Қазақ тілі (Kazakh)',
    'ko': '한국어 (Korean)',
    'lg': 'Oluganda (Luganda)',
    'lv': 'Latviešu (Latvian)',
    'nl': 'Nederlands (Dutch)',
    'nn': 'Norsk nynorsk (Norwegian Nynorsk)',
    'pl': 'Polski (Polish)',
    'pt-BR': 'Português - Brasil (Portuguese)',
    'ru': 'Русский (Russian)',
    'sk': 'Slovenčina (Slovak)',
    'sv': 'Svenska (Swedish)',
    'tr': 'Türkçe (Turkish)',
    'uk': 'Українська (Ukrainian)',
    'zh-CN': '简体中文 (Simplified Chinese)',
    'zh-TW': '繁體中文 (Traditional Chinese)',
}

SUPPORTED_LANGUAGE_CODES: Final[tuple[str, ...]] = tuple(SUPPORTED_LANGUAGES.keys())

LANGUAGE_COUNTRY_FLAGS: Final[dict[str, str]] = {
    'en': 'US',
    'ar': 'SA',
    'bg': 'BG',
    'ca': 'AD',
    'cs': 'CZ',
    'da': 'DK',
    'de': 'DE',
    'es': 'ES',
    'fa': 'IR',
    'fi': 'FI',
    'fr': 'FR',
    'gd': 'GB',
    'he': 'IL',
    'hr': 'HR',
    'hu': 'HU',
    'it': 'IT',
    'ja': 'JP',
    'ka': 'GE',
    'kk': 'KZ',
    'ko': 'KR',
    'lg': 'UG',
    'lv': 'LV',
    'nl': 'NL',
    'nn': 'NO',
    'pl': 'PL',
    'pt-BR': 'BR',
    'ru': 'RU',
    'sk': 'SK',
    'sv': 'SE',
    'tr': 'TR',
    'uk': 'UA',
    'zh-CN': 'CN',
    'zh-TW': 'TW',
}

RTL_LANGUAGE_CODES: Final[frozenset[str]] = frozenset({'ar', 'fa', 'he'})

_CANONICAL_LOOKUP_MAP: Final[dict[str, str]] = {code.casefold(): code for code in SUPPORTED_LANGUAGE_CODES}

LOCALE_TAG_ALIASES: Final[dict[str, str]] = {
    'iw': 'he',
    'nb': 'nn',
    'no': 'nn',
    'pt': 'pt-BR',
    'pt-pt': 'pt-BR',
    'pt-br': 'pt-BR',
    'zh': 'zh-CN',
    'zh-chs': 'zh-CN',
    'zh-cn': 'zh-CN',
    'zh-sg': 'zh-CN',
    'zh-hans': 'zh-CN',
    'zh-hans-cn': 'zh-CN',
    'zh-cht': 'zh-TW',
    'zh-hk': 'zh-TW',
    'zh-mo': 'zh-TW',
    'zh-tw': 'zh-TW',
    'zh-hant': 'zh-TW',
    'zh-hant-hk': 'zh-TW',
    'zh-hant-mo': 'zh-TW',
    'zh-hant-tw': 'zh-TW',
}

_QT_TRANSLATION_STEMS: Final[dict[str, str]] = {
    'ar': 'qtbase_ar',
    'bg': 'qtbase_bg',
    'ca': 'qtbase_ca',
    'cs': 'qtbase_cs',
    'da': 'qtbase_da',
    'de': 'qtbase_de',
    'es': 'qtbase_es',
    'fa': 'qtbase_fa',
    'fi': 'qtbase_fi',
    'fr': 'qtbase_fr',
    'gd': 'qtbase_gd',
    'he': 'qtbase_he',
    'hr': 'qtbase_hr',
    'hu': 'qtbase_hu',
    'it': 'qtbase_it',
    'ja': 'qtbase_ja',
    'ka': 'qtbase_ka',
    'kk': 'qtbase_kk',
    'ko': 'qtbase_ko',
    'lg': 'qtbase_lg',
    'lv': 'qtbase_lv',
    'nl': 'qtbase_nl',
    'nn': 'qtbase_nn',
    'pl': 'qtbase_pl',
    'pt-BR': 'qtbase_pt_BR',
    'ru': 'qtbase_ru',
    'sk': 'qtbase_sk',
    'sv': 'qtbase_sv',
    'tr': 'qtbase_tr',
    'uk': 'qtbase_uk',
    'zh-CN': 'qtbase_zh_CN',
    'zh-TW': 'qtbase_zh_TW',
}


_TWO: Final[int] = 2
_THREE: Final[int] = 3
_FOUR: Final[int] = 4
_TEN: Final[int] = 10
_ELEVEN: Final[int] = 11
_TWELVE: Final[int] = 12
_THIRTEEN: Final[int] = 13
_FOURTEEN: Final[int] = 14
_NINETEEN: Final[int] = 19
_NINETY_NINE: Final[int] = 99
_HUNDRED: Final[int] = 100


def _empty_messages() -> dict[str, str]:
    return {}


def _empty_plurals() -> dict[str, dict[str, str]]:
    return {}


def _empty_catalog_cache() -> dict[str, _TranslationCatalog]:
    return {}


@dataclass(slots=True)
class _TranslationCatalog:
    messages: dict[str, str]
    plurals: dict[str, dict[str, str]]
    reverse_messages: dict[str, str]


@dataclass(slots=True)
class _I18nState:
    active_language: str = DEFAULT_LANGUAGE
    active_messages: dict[str, str] = field(default_factory=_empty_messages)
    active_plurals: dict[str, dict[str, str]] = field(default_factory=_empty_plurals)
    catalog_cache: dict[str, _TranslationCatalog] = field(default_factory=_empty_catalog_cache)
    known_canonical_keys: frozenset[str] | None = None
    qt_translator: QTranslator | None = None


_STATE = _I18nState()
_STATE_LOCK = threading.RLock()


def _lookup_tag(tag: str) -> str | None:
    return _CANONICAL_LOOKUP_MAP.get(tag) or LOCALE_TAG_ALIASES.get(tag)


def normalize_language_code(raw_code: object) -> str | None:
    """Normalize a raw language code or OS locale tag to a supported canonical language key, or `None`."""
    if not isinstance(raw_code, str):
        return None
    cleaned = raw_code.strip().replace('_', '-')
    if not cleaned:
        return None
    if '.' in cleaned:
        cleaned = cleaned.split('.', 1)[0]
    if '@' in cleaned:
        cleaned = cleaned.split('@', 1)[0]
    lowered = cleaned.casefold()
    if (exact := _lookup_tag(lowered)) is not None:
        return exact
    # Try progressive prefix matching, e.g. 'zh-Hans-CN' -> 'zh-Hans' -> 'zh-CN', or 'fr-FR' -> 'fr'.
    parts = lowered.split('-')
    for length in range(len(parts) - 1, 0, -1):
        prefix = '-'.join(parts[:length])
        if (matched := _lookup_tag(prefix)) is not None:
            return matched
    return None


def detect_system_language() -> str:
    """Detect the operating system display language mapped to a supported language code, or `'en'`."""
    system_locale = QLocale.system()
    candidates: list[str] = list(system_locale.uiLanguages())
    if bcp47 := system_locale.bcp47Name():
        candidates.append(bcp47)
    if qt_name := system_locale.name():
        candidates.append(qt_name)
    try:
        stdlib_locale = locale.getlocale()[0]
    except ValueError:
        stdlib_locale = None
    if stdlib_locale is not None and stdlib_locale:
        candidates.append(stdlib_locale)

    for candidate in candidates:
        normalized = normalize_language_code(candidate)
        if normalized is not None:
            return normalized
    return DEFAULT_LANGUAGE


def resolve_effective_language(*, language: str, follow_system: bool) -> str:
    """Resolve the active language code given manual selection and *follow_system* preference."""
    if follow_system:
        return detect_system_language()
    return normalize_language_code(language) or DEFAULT_LANGUAGE


def _parse_catalog_payload(raw_data: object) -> tuple[dict[str, str], dict[str, dict[str, str]], dict[str, str]]:
    """Extract validated `messages`, `plurals`, and reverse lookup tables from JSON data."""
    messages: dict[str, str] = {}
    plurals: dict[str, dict[str, str]] = {}
    reverse_messages: dict[str, str] = {}
    if not isinstance(raw_data, dict):
        return messages, plurals, reverse_messages

    raw_dict = cast('dict[object, object]', raw_data)
    raw_messages = raw_dict.get('messages')
    if isinstance(raw_messages, dict):
        for raw_key, raw_val in cast('dict[object, object]', raw_messages).items():
            if isinstance(raw_key, str) and isinstance(raw_val, str) and raw_val:
                messages[raw_key] = raw_val
                reverse_messages.setdefault(raw_val, raw_key)

    raw_plurals = raw_dict.get('plurals')
    if isinstance(raw_plurals, dict):
        for raw_key, raw_forms in cast('dict[object, object]', raw_plurals).items():
            if not isinstance(raw_key, str) or not isinstance(raw_forms, dict):
                continue
            forms = {
                form_key: form_val
                for form_key, form_val in cast('dict[object, object]', raw_forms).items()
                if isinstance(form_key, str) and isinstance(form_val, str)
            }
            if forms:
                plurals[raw_key] = forms

    return messages, plurals, reverse_messages


def _load_catalog(language_code: str) -> _TranslationCatalog:
    with _STATE_LOCK:
        cached = _STATE.catalog_cache.get(language_code)
        if cached is not None:
            return cached

    if language_code == DEFAULT_LANGUAGE:
        catalog = _TranslationCatalog(messages={}, plurals={}, reverse_messages={})
        with _STATE_LOCK:
            _STATE.catalog_cache[language_code] = catalog
        return catalog

    catalog_path = TRANSLATIONS_DIR_PATH / f'{language_code}.json'
    messages: dict[str, str] = {}
    plurals: dict[str, dict[str, str]] = {}
    reverse_messages: dict[str, str] = {}

    if catalog_path.is_file():
        try:
            raw_data: object = json.loads(catalog_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError) as e:
            logger.warning('Failed to load translation catalog %s: %s', catalog_path, e)
        else:
            messages, plurals, reverse_messages = _parse_catalog_payload(raw_data)

    catalog = _TranslationCatalog(messages=messages, plurals=plurals, reverse_messages=reverse_messages)
    with _STATE_LOCK:
        _STATE.catalog_cache[language_code] = catalog
        if messages:
            _STATE.known_canonical_keys = None
    return catalog


def _get_known_canonical_keys() -> frozenset[str]:
    with _STATE_LOCK:
        if _STATE.known_canonical_keys is not None:
            return _STATE.known_canonical_keys

    keys: set[str] = set()
    for code in SUPPORTED_LANGUAGE_CODES:
        if code == DEFAULT_LANGUAGE:
            continue
        catalog = _load_catalog(code)
        if catalog.messages:
            keys.update(catalog.messages.keys())
            break
    frozen = frozenset(keys)
    with _STATE_LOCK:
        _STATE.known_canonical_keys = frozen
    return frozen


def _apply_qt_translator(language_code: str) -> None:
    app_instance = QCoreApplication.instance()
    if app_instance is None:
        return
    if _STATE.qt_translator is not None:
        app_instance.removeTranslator(_STATE.qt_translator)
        _STATE.qt_translator = None

    qm_stem = _QT_TRANSLATION_STEMS.get(language_code)
    if qm_stem is None:
        return

    translator = QTranslator()
    loaded = False
    qt_translations_dir = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
    if qt_translations_dir and Path(qt_translations_dir).is_dir():
        loaded = translator.load(qm_stem, qt_translations_dir)
    if not loaded:
        logger.debug('Qt base translation %s not found in %s', qm_stem, qt_translations_dir)
        return
    if app_instance.installTranslator(translator):
        _STATE.qt_translator = translator


def is_rtl_language(language_code: str) -> bool:
    """Return `True` if *language_code* uses a right-to-left script (`'ar'`, `'fa'`, `'he'`)."""
    resolved = normalize_language_code(language_code) or DEFAULT_LANGUAGE
    return resolved in RTL_LANGUAGE_CODES


def _apply_layout_direction(language_code: str) -> None:
    app_instance = QCoreApplication.instance()
    if not isinstance(app_instance, QGuiApplication):
        return
    target_direction = Qt.LayoutDirection.RightToLeft if language_code in RTL_LANGUAGE_CODES else Qt.LayoutDirection.LeftToRight
    if app_instance.layoutDirection() != target_direction:
        app_instance.setLayoutDirection(target_direction)


def get_active_language() -> str:
    """Return the currently active canonical language code (e.g. `'en'`, `'fr'`, `'zh-CN'`)."""
    with _STATE_LOCK:
        return _STATE.active_language


def set_active_language(language_code: str) -> bool:
    """Activate *language_code* and load its catalog and Qt base translations.

    Returns:
        `True` if the active language changed, `False` otherwise.
    """
    resolved = normalize_language_code(language_code) or DEFAULT_LANGUAGE
    catalog = _load_catalog(resolved)
    with _STATE_LOCK:
        changed = resolved != _STATE.active_language
        _STATE.active_language = resolved
        _STATE.active_messages = catalog.messages
        _STATE.active_plurals = catalog.plurals
        _apply_qt_translator(resolved)
        _apply_layout_direction(resolved)
    return changed


def _format_template(template: str, fallback_template: str, kwargs: dict[str, object]) -> str:
    if not kwargs:
        return template
    try:
        return template.format(**kwargs)
    except KeyError, ValueError, IndexError:
        logger.warning('Invalid translation placeholder template %r; falling back to source text.', template)
        return fallback_template.format(**kwargs)


def tr(text: str, **kwargs: object) -> str:
    """Translate canonical English *text* into the active language and format any keyword placeholders."""
    with _STATE_LOCK:
        active_lang = _STATE.active_language
        translated = text if active_lang == DEFAULT_LANGUAGE else _STATE.active_messages.get(text, text)
    return _format_template(translated, text, kwargs)


def _plural_other(_count: int) -> str:
    return 'other'


def _plural_one_upto_two(count: int) -> str:
    return 'one' if count in (0, 1) else 'other'


def _slavic_bcs_or_east(count: int, *, rest_category: str) -> str:
    mod10 = count % _TEN
    mod100 = count % _HUNDRED
    if mod10 == 1 and mod100 != _ELEVEN:
        return 'one'
    if _TWO <= mod10 <= _FOUR and not _TWELVE <= mod100 <= _FOURTEEN:
        return 'few'
    return rest_category


def _plural_east_slavic(count: int) -> str:
    return _slavic_bcs_or_east(count, rest_category='many')


def _plural_croatian(count: int) -> str:
    return _slavic_bcs_or_east(count, rest_category='other')


def _plural_polish(count: int) -> str:
    if count == 1:
        return 'one'
    mod10 = count % _TEN
    mod100 = count % _HUNDRED
    if _TWO <= mod10 <= _FOUR and not _TWELVE <= mod100 <= _FOURTEEN:
        return 'few'
    return 'many'


def _plural_west_slavic(count: int) -> str:
    if count == 1:
        return 'one'
    if _TWO <= count <= _FOUR:
        return 'few'
    return 'other'


def _plural_latvian(count: int) -> str:
    mod10 = count % _TEN
    mod100 = count % _HUNDRED
    if not mod10 or _ELEVEN <= mod100 <= _NINETEEN:
        return 'zero'
    if mod10 == 1 and mod100 != _ELEVEN:
        return 'one'
    return 'other'


def _plural_scottish_gaelic(count: int) -> str:
    if count in (1, _ELEVEN):
        return 'one'
    if count in (_TWO, _TWELVE):
        return 'two'
    if _THREE <= count <= _TEN or _THIRTEEN <= count <= _NINETEEN:
        return 'few'
    return 'other'


def _plural_arabic(count: int) -> str:
    mod100 = count % _HUNDRED
    category = 'other'
    if not count:
        category = 'zero'
    elif count == 1:
        category = 'one'
    elif count == _TWO:
        category = 'two'
    elif _THREE <= mod100 <= _TEN:
        category = 'few'
    elif _ELEVEN <= mod100 <= _NINETY_NINE:
        category = 'many'
    return category


def _plural_hebrew(count: int) -> str:
    if count == 1:
        return 'one'
    if count == _TWO:
        return 'two'
    if count > _TEN and not count % _TEN:
        return 'many'
    return 'other'


_PLURAL_SELECTORS: Final[dict[str, Callable[[int], str]]] = {
    'ja': _plural_other,
    'ko': _plural_other,
    'zh-CN': _plural_other,
    'zh-TW': _plural_other,
    'fa': _plural_one_upto_two,
    'fr': _plural_one_upto_two,
    'ru': _plural_east_slavic,
    'uk': _plural_east_slavic,
    'hr': _plural_croatian,
    'pl': _plural_polish,
    'cs': _plural_west_slavic,
    'sk': _plural_west_slavic,
    'lv': _plural_latvian,
    'gd': _plural_scottish_gaelic,
    'ar': _plural_arabic,
    'he': _plural_hebrew,
}


def select_plural_category(language_code: str, count: int) -> str:
    """Return the CLDR plural category (`'zero'`, `'one'`, `'two'`, `'few'`, `'many'`, `'other'`) for *count* in *language_code*."""
    abs_count = abs(count)
    selector = _PLURAL_SELECTORS.get(language_code)
    if selector is not None:
        return selector(abs_count)
    return 'one' if abs_count == 1 else 'other'


def tr_plural(singular: str, plural: str, count: int, **kwargs: object) -> str:
    """Translate a count-dependent template into the active language using plural category rules."""
    fallback = singular if abs(count) == 1 else plural
    with _STATE_LOCK:
        active_lang = _STATE.active_language
        plural_forms = None if active_lang == DEFAULT_LANGUAGE else _STATE.active_plurals.get(singular)

    template = fallback
    if plural_forms is not None:
        category = select_plural_category(active_lang, count)
        template = plural_forms.get(category) or plural_forms.get('other') or fallback

    format_args: dict[str, object] = {'count': count, **kwargs}
    return _format_template(template, fallback, format_args)


def lookup_canonical_message(rendered_text: str, *, from_language: str) -> str | None:
    """Resolve *rendered_text* back to its canonical English key when reversing from *from_language*."""
    if not rendered_text:
        return None
    if from_language == DEFAULT_LANGUAGE:
        return rendered_text if rendered_text in _get_known_canonical_keys() else None
    catalog = _load_catalog(from_language)
    return catalog.reverse_messages.get(rendered_text)


def get_web_panel_i18n() -> dict[str, str]:
    """Return all localized UI strings consumed by the Embedded Web Server HTML dashboard."""
    return {
        'page_title': tr('Session Sniffer Web Panel'),
        'subtitle': tr(
            'The best <span style="color: #22c55e; font-weight: 600;">FREE</span> and '
            '<span style="color: #22c55e; font-weight: 600;">Open-Source</span> packet sniffer',
        ),
        'capture_stopped': tr('CAPTURE STOPPED'),
        'uptime': tr('Uptime'),
        'captured_packets': tr('Captured Packets'),
        'search_placeholder': tr('Search connected + disconnected players...'),
        'search_placeholder_merged': tr('Search players...'),
        'all_columns': tr('All Columns'),
        'connected': tr('Connected'),
        'disconnected': tr('Disconnected'),
        'clear': tr('Clear'),
        'connected_players_count': tr('Connected Players ({count})'),
        'disconnected_players_count': tr('Disconnected Players ({count})'),
        'players_count': tr('Players ({count})'),
        'no_connected_players': tr('No connected players'),
        'no_connected_players_subtitle': tr('Connected players will appear here.'),
        'no_disconnected_players': tr('No disconnected players'),
        'no_disconnected_players_subtitle': tr('Disconnected players will appear here.'),
        'no_players': tr('No players'),
        'no_players_subtitle': tr('Players will appear here.'),
        'no_matching_connected_players': tr('No matching connected players'),
        'no_matching_disconnected_players': tr('No matching disconnected players'),
        'no_matching_players': tr('No matching players'),
        'no_matching_players_subtitle': tr('No players match the current search filter.'),
        'waiting_for_data': tr('Waiting for data...'),
        'player': tr('Player'),
        'na': tr('N/A'),
        'connection_error': tr('Connection error - retrying...'),
        'actions': tr('Actions'),
        'close': tr('Close'),
        'copied_to_clipboard': tr('Copied to clipboard!'),
        'copy': tr('Copy'),
        'copy_ip_address': tr('Copy IP Address'),
        'copy_username': tr('Copy Username'),
        'copy_row': tr('Copy Row'),
        'copy_for_discord': tr('Copy for Discord'),
        'ip_lookup_details': tr('IP Lookup Details'),
        'player_joins': tr('Player Joins'),
        'looky_system': tr('Looky System'),
        'open_website': tr('Open Website'),
        'view_on_website': tr('View on Website'),
        'ping': tr('Ping'),
        'web_check_host': tr('Web (Check-Host)'),
        'search': tr('Search'),
        'seen_stats': tr('Seen Stats'),
        'rate_graph': tr('Rate Graph'),
        'host_diagnostics': tr('Host Diagnostics…'),
        'host_diagnostics_title': tr('Session Host Diagnostics'),
        'copy_host_ip': tr('Copy Host IP'),
        'copy_host_details': tr('Copy Host Details'),
        'copied_host_details': tr('Copied Host Details!'),
        'badge_session_host': tr('Session Host'),
        'badge_gta5_relay': tr('GTA5 Relay'),
        'badge_high_rate': tr('High-Rate traffic detected (exceeds PPS/BPS thresholds)'),
        'badge_identified': tr('Identified player (Player Identifier)'),
        'badge_looky': tr('Looky System'),
        'sort_column': tr('Sort Column'),
        'sort_order': tr('Sort Order'),
        'sort_default': tr('Default'),
        'sort_asc': tr('Ascending'),
        'sort_desc': tr('Descending'),
        'rows_label': tr('Rows:'),
        'page_label': tr('Page:'),
        'all': tr('All'),
        'all_count': tr('All ({count})'),
        'previous_page': tr('Previous Page'),
        'next_page': tr('Next Page'),
        'current_session': tr('Current Session'),
        'session_players_count': tr("Session '{name}' Players ({count})"),
        'split_view': tr('Split View'),
        'tabs': tr('Tabs'),
        'merge': tr('MERGE'),
        'split': tr('SPLIT'),
        'merge_tables_tooltip': tr('Merge connected and disconnected tables into one'),
        'split_tables_tooltip': tr('Split into connected and disconnected tables'),
        'live': tr('Live'),
        'reconnecting': tr('Reconnecting…'),
        'pps': tr('PPS'),
        'bps': tr('BPS'),
        'current': tr('Current'),
        'average': tr('Average'),
        'peak_pps': tr('Peak PPS'),
        'peak_bps': tr('Peak BPS'),
        'loading': tr('Loading...'),
    }
