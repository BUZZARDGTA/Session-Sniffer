"""Sync shared themes, i18n catalogs, metadata, Lucide SVG icons, and flags from Session Sniffer into `website/assets/`."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tomllib
from pathlib import Path
from typing import Final, cast

from packaging.version import Version

from session_sniffer.constants.tables import (
    GUI_COLUMN_HEADERS_TOOLTIPS,
    LOCATION_COLUMNS,
    ORGANIZATION_COLUMNS,
    PORT_COLUMNS,
    STATUS_COLUMNS,
)
from session_sniffer.i18n import (
    DEFAULT_LANGUAGE,
    LANGUAGE_COUNTRY_FLAGS,
    LOCALE_TAG_ALIASES,
    RTL_LANGUAGE_CODES,
    SUPPORTED_LANGUAGES,
)
from session_sniffer.models.themes import (
    BUILTIN_THEMES,
    DEFAULT_THEME_NAME,
    THEME_COLOR_TOKENS,
    THEME_NAME_MAX_LENGTH,
    THEME_TOKEN_CATEGORIES,
    Theme,
)
from session_sniffer.utils import format_project_version

REPO_ROOT: Final = Path(__file__).resolve().parent.parent
WEBSITE_DIR: Final = REPO_ROOT / 'website'
ASSETS_DIR: Final = WEBSITE_DIR / 'assets'
FLAGS_OUT_DIR: Final = ASSETS_DIR / 'flags'
I18N_OUT_DIR: Final = ASSETS_DIR / 'i18n'
SITE_TRANSLATIONS_DIR: Final = WEBSITE_DIR / 'translations'

ICONS_SRC_DIR: Final = REPO_ROOT / 'resources' / 'icons'
FLAGS_SRC_DIR: Final = REPO_ROOT / 'resources' / 'images' / 'country_flags'
APP_TRANSLATIONS_SRC_DIR: Final = REPO_ROOT / 'resources' / 'translations'
PYPROJECT_PATH: Final = REPO_ROOT / 'pyproject.toml'

_SVG_OPEN_TAG_RE: Final = re.compile(r'<svg\b([^>]*)>(.*)</svg>', re.DOTALL | re.IGNORECASE)
_VIEWBOX_RE: Final = re.compile(r'viewBox="([^"]+)"', re.IGNORECASE)
_VERSION_BASE_RE: Final = re.compile(r'^(v?\d+\.\d+\.\d+(?:[-.]?(?:rc|alpha|beta)\d*)?)', re.IGNORECASE)
_TAG_SERIES_RE: Final = re.compile(r'^v?(\d+\.\d+)', re.IGNORECASE)
_DEFAULT_ICON_STROKE_RE: Final = re.compile(r'#a5b4c4', re.IGNORECASE)
_PLACEHOLDER_RE: Final = re.compile(r'\{[a-zA-Z0-9_]+(?::[^}]+)?\}')
_LIGHT_LUMINANCE_THRESHOLD: Final = 140.0
_PREDECESSOR_COMMITS_COUNT: Final = 99  # PS3-Blacklist-Sniffer (94) + PC-Blacklist-Sniffer (5)

# Canonical columns rendered in the website's interactive Connected & Disconnected preview tables.
PREVIEW_TABLE_COLUMNS: Final[tuple[str, ...]] = (
    'ASN / ISP',
    'BPS',
    'Bandwidth',
    'Country',
    'First Seen',
    'Hosting',
    'Hostname',
    'IP Address',
    'Last Rejoin',
    'Last Seen',
    'Mobile',
    'PPS',
    'Packets',
    'Pinging',
    'Ports',
    'Region',
    'Rejoins',
    'Session Time',
    'T. Session Time',
    'Usernames',
    'VPN',
)

# Canonical keys pulled verbatim from `resources/translations/<lang>.json` ("messages") so the website's
# interactive Session Sniffer preview and Theme Studio stay 100% consistent with the desktop app.
SHARED_APP_MESSAGE_KEYS: Final[tuple[str, ...]] = (
    # Menu bar & exact MainWindow menu items (1:1 with main_window.py & mixins)
    'Capture',
    'Tools',
    'Statistics',
    'Data && Files',
    'Settings',
    'Help',
    'Stop Capture',
    'Change Interface',
    'Hotspot && Sharing',
    'Player Resolver',
    'Current Session',
    'Session History',
    'Host History',
    '{game} Process',
    'Solo Public Session',
    'Suspend Process',
    'Detections Manager',
    'UserIP Manager',
    'Logs Manager',
    'Most Seen Players',
    'Port Scanner',
    'Ping Diagnostics',
    'Capture Statistics',
    'Session Rate Graph',
    'Session Timeline',
    'Country Breakdown',
    'Reconnect Frequency',
    'Session Duration',
    'Port Heatmap',
    'Open Local AppData Folder',
    'Open Roaming AppData Folder',
    'Open UserIP Databases Folder',
    'Open UserIP Backups Folder',
    'Open User Scripts Folder',
    'Application Logs',
    'Open Logging Folder',
    'Open Sessions Folder',
    'Open Detection_Logging.csv',
    'Open Protection_Logging.csv',
    'Open UserIP_Logging.csv',
    'Debug Logs',
    'Open Debug Logs Folder',
    'Open debug.log',
    'Open crash.log',
    'Open settings.json',
    'Open Settings',
    'Official Website',
    'Project Repository',
    'Documentation',
    'Tips and Tricks',
    'Release Notes',
    'View License',
    'Report Issue',
    'Discord Server',
    'Check for Updates',
    'About',
    'Player High Rate Monitor',
    # Dashboard header & exact SessionStatusBar (1:1 with _main_header.py & status_bar_renderer.py)
    'The best <span style="color: #22c55e; font-weight: 600;">FREE</span> and <span style="color: #22c55e; font-weight: 600;">Open-Source</span> packet sniffer',
    'Search connected + disconnected players...',
    'Search players...',
    'All Columns',
    'Uptime',
    'Captured Packets',
    'Capture:',
    'Interface:',
    'IP:',
    'Config:',
    'Discord:',
    'Connected',
    'Feature Set:',
    'Performance:',
    'Latency:',
    '{latency}ms',
    # Section bars, expand buttons & tables (1:1 with _session_table_section.py)
    'Connected Players ({count})',
    'Disconnected Players ({count})',
    'Players ({count})',
    'Show Connected Players ({count})',
    'Show Disconnected Players ({count})',
    'All Tables Minimized',
    'Expand connected or disconnected players below to view session data',
    # Session table empty-state placeholders (1:1 with tables.py _paint_empty_state)
    'No matching players',
    'No matching connected players',
    'No matching disconnected players',
    'No players match the current search filter.',
    'No players',
    'Players will appear here.',
    'No connected players',
    'Connected players will appear here.',
    'No disconnected players',
    'Disconnected players will appear here.',
    'Rows:',
    'Page:',
    'All ({count})',
    'MERGE',
    'SPLIT',
    'CLEAR',
    'Usernames',
    'First Seen',
    'Last Rejoin',
    'Last Seen',
    'T. Session Time',
    'Session Time',
    'Rejoins',
    'Packets',
    'PPS',
    'Bandwidth',
    'BPS',
    'IP Address',
    'Hostname',
    *PORT_COLUMNS,
    *(column for column in LOCATION_COLUMNS if column not in {'Lat', 'Lon', 'Offset'}),
    *ORGANIZATION_COLUMNS,
    *STATUS_COLUMNS,
    'Yes',
    'No',
    # Right-click context menu (1:1 with tables_context_menu_mixin.py)
    'Copy Selection',
    'Copy for Discord',
    'Clear Session Host',
    'Host Diagnostics…',
    'Exclude IP / Range',
    "Filter ISP '{isp}'",
    'IP Lookup Details',
    'Rate Graph',
    'Blacklist in Player High Rate Monitor',
    'Unblacklist from Player High Rate Monitor',
    'Looky System',
    'Open Website',
    'View on Website',
    'Request Crawler in My Session',
    'Rescan All Players',
    'Lookup',
    'Call Crawler',
    'Proxy Join',
    'Remove Looky Usernames…',
    'Ping',
    'ICMP Ping',
    'Web (Check-Host)…',
    'Scan Ports…',
    'UserIP',
    'Search in…',
    'UserIP All Databases',
    'UserIP Logging',
    'Sessions Logging',
    # Preview table column header tooltips (1:1 with GUI_COLUMN_HEADERS_TOOLTIPS)
    *(GUI_COLUMN_HEADERS_TOOLTIPS[col] for col in PREVIEW_TABLE_COLUMNS),
    # Theme Studio categories, tokens & built-in names
    *THEME_TOKEN_CATEGORIES,
    *(token.label for token in THEME_COLOR_TOKENS),
    *(token.description for token in THEME_COLOR_TOKENS),
    *(theme.name for theme in BUILTIN_THEMES),
)

SHARED_APP_PLURAL_SINGULAR_KEYS: Final[tuple[str, ...]] = ('Remove Player',)

SYNCED_ICONS: Final[tuple[str, ...]] = (
    'activity',
    'arrow-down-to-line',
    'arrow-left',
    'arrow-right',
    'bell',
    'bell-off',
    'book-text',
    'bot',
    'bug',
    'calendar-days',
    'chart-line',
    'chart-scatter',
    'check',
    'chevron-down',
    'chevron-right',
    'chevron-up',
    'circle-pause',
    'circle-play',
    'circle-stop',
    'cloud-download',
    'code',
    'copy',
    'crown',
    'database',
    'discord',
    'external-link',
    'eye',
    'file-cog',
    'file-text',
    'folder',
    'gamepad-2',
    'gauge',
    'github',
    'globe',
    'host_history',
    'import',
    'info',
    'lightbulb',
    'monitor-smartphone',
    'network',
    'palette',
    'radar',
    'radio',
    'radio-tower',
    'refresh-cw',
    'remove',
    'rotate-ccw',
    'rotate-ccw-clock',
    'route',
    'router',
    'save',
    'scale',
    'scan-eye',
    'search',
    'settings',
    'shield',
    'sliders-horizontal',
    'timer',
    'trophy',
    'user-plus',
    'user-round',
    'user-round-check',
    'user-round-search',
    'user-round-x',
    'volume-2',
    'volume-x',
    'wifi',
    'x',
)

DEMO_COUNTRY_FLAGS: Final[tuple[str, ...]] = (
    'AU',
    'BR',
    'CA',
    'DE',
    'FR',
    'GB',
    'JP',
    'NL',
    'SE',
    'US',
)

SYNCED_COUNTRY_FLAGS: Final[tuple[str, ...]] = tuple(sorted({*DEMO_COUNTRY_FLAGS, *LANGUAGE_COUNTRY_FLAGS.values()}))


def _hex_to_rgb(hex_color: str) -> tuple[int, int, int]:
    """Convert a `#rrggbb` color string into an `(r, g, b)` integer tuple."""
    cleaned = hex_color.lstrip('#')
    return int(cleaned[0:2], 16), int(cleaned[2:4], 16), int(cleaned[4:6], 16)


def _is_light_hex(hex_color: str) -> bool:
    """Return True when *hex_color* exceeds Session Sniffer's light-theme luminance threshold."""
    red, green, blue = _hex_to_rgb(hex_color)
    return (0.2126 * red + 0.7152 * green + 0.0722 * blue) > _LIGHT_LUMINANCE_THRESHOLD


def _theme_slug(name: str) -> str:
    """Convert a built-in theme display name into a stable CSS data-theme slug."""
    return re.sub(r'[^a-z0-9]+', '-', name.strip().casefold()).strip('-')


def _write_crlf_text(path: Path, content: str) -> None:
    """Write UTF-8 text using repository-standard CRLF line endings."""
    normalized = content.replace('\r\n', '\n').replace('\r', '\n')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='\r\n') as handle:
        handle.write(normalized)


def _read_project_version() -> tuple[str, str, str]:
    """Read `(full_version, display_version, app_version)` from `pyproject.toml`."""
    data = tomllib.loads(PYPROJECT_PATH.read_text(encoding='utf-8'))
    project_raw: object = data.get('project')
    raw_version = 'v1.5.0'
    if isinstance(project_raw, dict):
        version_raw: object = cast('dict[str, object]', project_raw).get('version')
        if isinstance(version_raw, str) and version_raw:
            raw_version = version_raw
    match = _VERSION_BASE_RE.match(raw_version)
    display_version = str(match.group(1)) if match else raw_version
    app_version = format_project_version(Version(raw_version))
    return raw_version, display_version, app_version


def _build_theme_css_block(theme: Theme, selector: str) -> str:
    """Render one CSS selector block mapping all 20 `ThemeColors` tokens to `--ss-*` variables."""
    colors_map = theme.colors.as_dict()
    scheme = 'light' if _is_light_hex(theme.colors.background) else 'dark'
    lines = [
        f'{selector} {{',
        f'    color-scheme: {scheme};',
    ]
    for token_name, hex_value in colors_map.items():
        css_key = token_name.replace('_', '-')
        red, green, blue = _hex_to_rgb(hex_value)
        lines.append(f'    --ss-{css_key}: {hex_value};')
        lines.append(f'    --ss-{css_key}-rgb: {red}, {green}, {blue};')
    lines.append('}')
    return '\n'.join(lines)


def _generate_themes_css() -> str:
    """Generate `themes.generated.css` directly from `BUILTIN_THEMES`."""
    header = (
        '/*\n'
        ' * AUTO-GENERATED from src/session_sniffer/models/themes.py\n'
        ' * Do not edit by hand — run `python website/sync_assets.py` to refresh.\n'
        ' */\n'
    )
    blocks: list[str] = []
    for theme in BUILTIN_THEMES:
        slug = _theme_slug(theme.name)
        selector = f':root,\n[data-theme="{slug}"]' if theme.name == DEFAULT_THEME_NAME else f'[data-theme="{slug}"]'
        blocks.append(_build_theme_css_block(theme, selector))
    return header + '\n' + '\n\n'.join(blocks) + '\n'


def _svg_to_symbol(svg_path: Path, symbol_id: str, *, preserve_colors: bool = False) -> str:
    """Convert a standalone SVG file into a `<symbol>` element for the shared inline icon sprite."""
    raw_svg = svg_path.read_text(encoding='utf-8').strip()
    match = _SVG_OPEN_TAG_RE.search(raw_svg)
    if match is None:
        message = f'Could not parse SVG root tag in {svg_path}'
        raise ValueError(message)

    attrs = match.group(1)
    inner = match.group(2).strip()
    viewbox_match = _VIEWBOX_RE.search(attrs)
    viewbox = viewbox_match.group(1) if viewbox_match else '0 0 24 24'

    if preserve_colors:
        cleaned_attrs = re.sub(r'\s*xmlns="[^"]+"', '', attrs).strip()
        return f'<symbol id="{symbol_id}" {cleaned_attrs}>{inner}</symbol>'

    normalized_inner = _DEFAULT_ICON_STROKE_RE.sub('currentColor', inner)
    compact_inner = re.sub(r'\s*\r?\n\s*', '', normalized_inner)
    return (
        f'<symbol id="{symbol_id}" viewBox="{viewbox}" fill="none" stroke="currentColor" '
        f'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{compact_inner}</symbol>'
    )


def _build_icon_sprite() -> str:
    """Build the inline SVG sprite containing `app_icon` plus all synced Lucide icons."""
    symbols: list[str] = [_svg_to_symbol(ICONS_SRC_DIR / 'app_icon.svg', 'icon-app_icon', preserve_colors=True)]
    for icon_name in SYNCED_ICONS:
        icon_path = ICONS_SRC_DIR / f'{icon_name}.svg'
        if not icon_path.is_file():
            message = f'Missing icon file: {icon_path}'
            raise FileNotFoundError(message)
        symbols.append(_svg_to_symbol(icon_path, f'icon-{icon_name}'))
    return '<svg xmlns="http://www.w3.org/2000/svg" aria-hidden="true" style="position:absolute;width:0;height:0;overflow:hidden">' + ''.join(symbols) + '</svg>'


def _load_json_dict(path: Path) -> dict[str, object]:
    """Load a JSON object file as a string-keyed dictionary."""
    raw: object = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(raw, dict):
        message = f'Expected JSON object in {path}'
        raise TypeError(message)
    return cast('dict[str, object]', raw)


def _load_site_english_catalog() -> dict[str, str]:
    """Load the canonical English website translation catalog from `website/translations/en.json`."""
    en_path = SITE_TRANSLATIONS_DIR / 'en.json'
    raw = _load_json_dict(en_path)
    result: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(value, str) or not value:
            message = f'Invalid English site translation value for {key!r} in {en_path}'
            raise ValueError(message)
        result[key] = value
    return result


def _extract_shared_app_strings(lang_code: str) -> dict[str, str]:
    """Extract the website's shared desktop-app strings from `resources/translations/<lang>.json`."""
    app_catalog_path = APP_TRANSLATIONS_SRC_DIR / f'{lang_code}.json'
    if not app_catalog_path.is_file():
        message = f'Missing app translation catalog: {app_catalog_path}'
        raise FileNotFoundError(message)

    raw = _load_json_dict(app_catalog_path)
    messages_raw = raw.get('messages')
    plurals_raw = raw.get('plurals')
    messages = cast('dict[str, object]', messages_raw) if isinstance(messages_raw, dict) else {}
    plurals = cast('dict[str, object]', plurals_raw) if isinstance(plurals_raw, dict) else {}

    extracted: dict[str, str] = {}
    for key in SHARED_APP_MESSAGE_KEYS:
        val = messages.get(key)
        if isinstance(val, str) and val:
            extracted[key] = val.replace('&&', '&')

    for plural_key in SHARED_APP_PLURAL_SINGULAR_KEYS:
        forms_raw = plurals.get(plural_key)
        if isinstance(forms_raw, dict):
            forms = cast('dict[str, object]', forms_raw)
            singular = forms.get('one') or forms.get('other')
            if isinstance(singular, str) and singular:
                extracted[plural_key] = singular.replace('&&', '&')

    return extracted


def _load_and_validate_site_locale(lang_code: str, en_catalog: dict[str, str]) -> dict[str, str]:
    """Load and validate `website/translations/<lang>.json` against `en.json` keys and placeholders."""
    locale_path = SITE_TRANSLATIONS_DIR / f'{lang_code}.json'
    if not locale_path.is_file():
        message = f'Missing website translation catalog: {locale_path}'
        raise FileNotFoundError(message)

    raw = _load_json_dict(locale_path)
    missing_keys = sorted(set(en_catalog) - set(raw))
    extra_keys = sorted(set(raw) - set(en_catalog))
    if missing_keys or extra_keys:
        message = f'Key mismatch in {locale_path}: missing={missing_keys[:5]}, extra={extra_keys[:5]}'
        raise ValueError(message)

    validated: dict[str, str] = {}
    for key, en_text in en_catalog.items():
        val = raw[key]
        if not isinstance(val, str) or not val.strip():
            message = f'Empty or non-string value for {key!r} in {locale_path}'
            raise ValueError(message)
        expected_placeholders = set(_PLACEHOLDER_RE.findall(en_text))
        actual_placeholders = set(_PLACEHOLDER_RE.findall(val))
        if expected_placeholders != actual_placeholders:
            message = f'Placeholder mismatch for {key!r} in {locale_path}: expected {expected_placeholders}, got {actual_placeholders}'
            raise ValueError(message)
        validated[key] = val
    return validated


def _sync_i18n_bundles(en_catalog: dict[str, str]) -> int:
    """Generate per-language lazy-load JS bundles in `website/assets/i18n/<lang>.js`."""
    I18N_OUT_DIR.mkdir(parents=True, exist_ok=True)
    generated_count = 0

    for lang_code in SUPPORTED_LANGUAGES:
        if lang_code == DEFAULT_LANGUAGE:
            continue
        app_strings = _extract_shared_app_strings(lang_code)
        site_strings = _load_and_validate_site_locale(lang_code, en_catalog)
        bundle_payload = {
            'app': app_strings,
            'site': site_strings,
        }
        serialized = json.dumps(bundle_payload, ensure_ascii=False, separators=(',', ':'))
        content = (
            '/* AUTO-GENERATED by website/sync_assets.py — do not edit by hand. */\n'
            f'window.__ssRegisterLocale({json.dumps(lang_code)}, {serialized});\n'
        )
        _write_crlf_text(I18N_OUT_DIR / f'{lang_code}.js', content)
        generated_count += 1

    return generated_count


def _classify_tag_kind(tag_name: str) -> str:
    """Classify a Git release tag as `pre`, `post`, or `stable`."""
    lower = tag_name.casefold()
    if any(token in lower for token in ('rc', 'alpha', 'beta', '.pre')):
        return 'pre'
    if 'post' in lower:
        return 'post'
    return 'stable'


def _collect_git_history_metadata() -> dict[str, object]:
    """Collect commit count and full sorted Git release tag archive from the local repository."""
    git_exe = shutil.which('git')
    repo_commits = 0
    tags: list[dict[str, str]] = []
    series_counts: dict[str, int] = {}

    if git_exe is not None:
        count_proc = subprocess.run(
            [git_exe, '-C', str(REPO_ROOT), 'rev-list', '--count', 'HEAD'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            check=False,
        )
        if not count_proc.returncode and count_proc.stdout.strip().isdigit():
            repo_commits = int(count_proc.stdout.strip())

        tag_proc = subprocess.run(
            [
                git_exe,
                '-C',
                str(REPO_ROOT),
                'tag',
                '--sort=-creatordate',
                '--format=%(creatordate:short)|%(refname:short)',
            ],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            check=False,
        )
        if not tag_proc.returncode:
            for raw_line in tag_proc.stdout.splitlines():
                line = raw_line.strip()
                if '|' not in line:
                    continue
                tag_date, tag_name = line.split('|', 1)
                match = _TAG_SERIES_RE.match(tag_name)
                series = f'v{match.group(1)}' if match else 'other'
                series_counts[series] = series_counts.get(series, 0) + 1
                tags.append(
                    {
                        't': tag_name,
                        'd': tag_date,
                        's': series,
                        'k': _classify_tag_kind(tag_name),
                    },
                )

    return {
        'repoCommits': repo_commits,
        'predecessorCommits': _PREDECESSOR_COMMITS_COUNT,
        'totalCommits': repo_commits + _PREDECESSOR_COMMITS_COUNT,
        'totalTags': len(tags),
        'seriesCounts': series_counts,
        'tags': tags,
    }


def _generate_app_data_js(en_catalog: dict[str, str]) -> str:
    """Generate `app-data.generated.js` containing themes, languages, English defaults, version, history, and SVG sprite."""
    full_version, display_version, app_version = _read_project_version()
    missing_lang_flags = sorted(set(SUPPORTED_LANGUAGES) - set(LANGUAGE_COUNTRY_FLAGS))
    if missing_lang_flags:
        message = f'Missing LANGUAGE_COUNTRY_FLAGS mappings for: {missing_lang_flags}'
        raise ValueError(message)

    payload: dict[str, object] = {
        'version': display_version,
        'appVersion': app_version,
        'fullVersion': full_version,
        'languagesCount': len(SUPPORTED_LANGUAGES),
        'defaultLanguage': DEFAULT_LANGUAGE,
        'languages': [
            {
                'code': code,
                'name': display_name,
                'flag': LANGUAGE_COUNTRY_FLAGS[code],
                'rtl': code in RTL_LANGUAGE_CODES,
            }
            for code, display_name in SUPPORTED_LANGUAGES.items()
        ],
        'localeAliases': LOCALE_TAG_ALIASES,
        'enSite': en_catalog,
        'columnTooltips': {col: GUI_COLUMN_HEADERS_TOOLTIPS[col] for col in PREVIEW_TABLE_COLUMNS},
        'defaultThemeSlug': _theme_slug(DEFAULT_THEME_NAME),
        'themeNameMaxLength': THEME_NAME_MAX_LENGTH,
        'themeCategories': list(THEME_TOKEN_CATEGORIES),
        'themeTokens': [
            {
                'name': token.name,
                'cssKey': token.name.replace('_', '-'),
                'label': token.label,
                'category': token.category,
                'description': token.description,
            }
            for token in THEME_COLOR_TOKENS
        ],
        'builtinThemes': [
            {
                'name': theme.name,
                'slug': _theme_slug(theme.name),
                'scheme': 'light' if _is_light_hex(theme.colors.background) else 'dark',
                'colors': theme.colors.as_dict(),
            }
            for theme in BUILTIN_THEMES
        ],
        'history': _collect_git_history_metadata(),
        'iconSprite': _build_icon_sprite(),
    }
    serialized = json.dumps(payload, indent=2, ensure_ascii=False)
    return (
        '/*\n'
        ' * AUTO-GENERATED from Session Sniffer source (models/themes.py, i18n.py, pyproject.toml, resources/icons/).\n'
        ' * Do not edit by hand — run `python website/sync_assets.py` to refresh.\n'
        ' */\n'
        f'window.SESSION_SNIFFER_DATA = {serialized};\n'
    )


def _sync_static_assets() -> None:
    """Copy `app_icon.svg` and required country flag PNGs into `website/assets/`."""
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    FLAGS_OUT_DIR.mkdir(parents=True, exist_ok=True)

    app_icon_text = (ICONS_SRC_DIR / 'app_icon.svg').read_text(encoding='utf-8')
    _write_crlf_text(ASSETS_DIR / 'app_icon.svg', app_icon_text)

    expected_flags = {f'{country_code}.png' for country_code in SYNCED_COUNTRY_FLAGS}
    for existing_flag in FLAGS_OUT_DIR.glob('*.png'):
        if existing_flag.name not in expected_flags:
            existing_flag.unlink()

    for country_code in SYNCED_COUNTRY_FLAGS:
        src_flag = FLAGS_SRC_DIR / f'{country_code}.png'
        if not src_flag.is_file():
            message = f'Missing country flag image: {src_flag}'
            raise FileNotFoundError(message)
        shutil.copy2(src_flag, FLAGS_OUT_DIR / f'{country_code}.png')


def main() -> None:
    """Run the full Session Sniffer -> website asset and i18n sync."""
    en_catalog = _load_site_english_catalog()
    _sync_static_assets()
    _write_crlf_text(ASSETS_DIR / 'themes.generated.css', _generate_themes_css())
    _write_crlf_text(ASSETS_DIR / 'app-data.generated.js', _generate_app_data_js(en_catalog))
    bundle_count = _sync_i18n_bundles(en_catalog)
    print(
        f'Synced {len(BUILTIN_THEMES)} themes, {len(SYNCED_ICONS) + 1} SVG icons, '
        f'{len(SYNCED_COUNTRY_FLAGS)} country flags, and {bundle_count + 1} languages into {ASSETS_DIR}',
    )


if __name__ == '__main__':
    main()
