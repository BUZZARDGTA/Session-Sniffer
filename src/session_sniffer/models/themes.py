"""Theme color tokens, built-in theme presets, and custom theme persistence (`themes.json`)."""

import json
from dataclasses import dataclass, fields
from typing import TYPE_CHECKING, Annotated, Final, Self, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, field_validator, model_validator

from session_sniffer.constants.local import SETTINGS_PATH, THEMES_PATH
from session_sniffer.utils import atomic_write_text, custom_str_to_bool
from session_sniffer.utils_exceptions import InvalidBooleanValueError

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

THEME_NAME_MAX_LENGTH: Final = 40

type HexColor = Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, pattern=r'^#[0-9a-f]{6}$')]
type ThemeName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=THEME_NAME_MAX_LENGTH)]


@dataclass(frozen=True, slots=True)
class ThemeColors:
    """The 20 semantic color tokens that fully describe a theme (all lowercase `#rrggbb` strings)."""

    # Surfaces & Bars
    background: str
    surface: str
    menubar: str
    statusbar: str
    popup: str
    # Controls & Inputs
    control: str
    input: str
    scrollbar: str
    border: str
    # Tables & Lists
    table: str
    table_alt: str
    table_header: str
    selection: str
    # Typography
    text: str
    text_muted: str
    text_strong: str
    # Accents & Status
    accent: str
    success: str
    warning: str
    danger: str

    def as_dict(self) -> dict[str, str]:
        """Return the tokens as a `{token_name: '#rrggbb'}` mapping in declaration order."""
        return {field.name: getattr(self, field.name) for field in fields(self)}


@dataclass(frozen=True, slots=True)
class ThemeColorToken:
    """User-facing metadata describing one `ThemeColors` token."""

    name: str
    label: str
    category: str
    description: str


THEME_TOKEN_CATEGORIES: Final[tuple[str, ...]] = (
    'Surfaces & Bars',
    'Controls & Inputs',
    'Tables & Lists',
    'Typography',
    'Accents & Status',
)

THEME_COLOR_TOKENS: Final[tuple[ThemeColorToken, ...]] = (
    # Surfaces & Bars
    ThemeColorToken('background', 'Window Background', 'Surfaces & Bars', 'Main window, dialog, and tab page background canvas.'),
    ThemeColorToken('surface', 'Cards & Panels', 'Surfaces & Bars', 'Group boxes, cards, panels, stat boxes, and framed containers.'),
    ThemeColorToken('menubar', 'Menu & Toolbars', 'Surfaces & Bars', 'Top menu bar, toolbars, and navigation header strips.'),
    ThemeColorToken('statusbar', 'Status Bar', 'Surfaces & Bars', 'Bottom window status bar background.'),
    ThemeColorToken('popup', 'Menus & Tooltips', 'Surfaces & Bars', 'Context menus, dropdown popups, tooltips, and busy overlays.'),
    # Controls & Inputs
    ThemeColorToken('control', 'Buttons & Controls', 'Controls & Inputs', 'Standard, compact, and dialog action buttons and inactive tabs.'),
    ThemeColorToken('input', 'Input Fields', 'Controls & Inputs', 'Text boxes, search bars, spin boxes, combo boxes, and progress tracks.'),
    ThemeColorToken('scrollbar', 'Scrollbars & Splitters', 'Controls & Inputs', 'Scrollbar thumbs, slider handles, and pane splitter bars.'),
    ThemeColorToken('border', 'Borders & Separators', 'Controls & Inputs', 'Control, card, and table borders, grid lines, and dividers.'),
    # Tables & Lists
    ThemeColorToken('table', 'Table & List Background', 'Tables & Lists', 'Primary row and viewport background for player tables, trees, and lists.'),
    ThemeColorToken('table_alt', 'Alternating Row', 'Tables & Lists', 'Alternating zebra row background in tables and tree views.'),
    ThemeColorToken('table_header', 'Table & Section Header', 'Tables & Lists', 'Table column headers, group title badges, and collapsible section bars.'),
    ThemeColorToken('selection', 'Selection Highlight', 'Tables & Lists', 'Selected rows, cells, list or menu items, and text selection.'),
    # Typography
    ThemeColorToken('text', 'Primary Text', 'Typography', 'Default body, label, input, and table cell text.'),
    ThemeColorToken('text_muted', 'Muted Text', 'Typography', 'Secondary labels, subtitles, hints, and placeholder text.'),
    ThemeColorToken('text_strong', 'Strong Text', 'Typography', 'Headings, titles, active tabs, and button labels.'),
    # Accents & Status
    ThemeColorToken('accent', 'Primary Accent', 'Accents & Status', 'Primary buttons, focus rings, checked controls, active tab bars, and links.'),
    ThemeColorToken('success', 'Success / Connected', 'Accents & Status', 'Connected player headers and rows, active capture states, and healthy metrics.'),
    ThemeColorToken('warning', 'Warning / Alert', 'Accents & Status', 'Warning banners, cautionary alerts, and high-rate indicators.'),
    ThemeColorToken('danger', 'Danger / Disconnected', 'Accents & Status', 'Destructive buttons, disconnected player headers, and error states.'),
)


@dataclass(frozen=True, slots=True)
class Theme:
    """A named theme, either built-in (read-only) or user-defined."""

    name: str
    colors: ThemeColors
    builtin: bool = False


DEFAULT_THEME_NAME: Final = 'Dark'
LIGHT_THEME_NAME: Final = 'Light'

DARK_THEME_COLORS: Final = ThemeColors(
    background='#121212',
    surface='#1e1e1e',
    menubar='#252526',
    statusbar='#252526',
    popup='#252526',
    control='#2d2d30',
    input='#1e1e1e',
    scrollbar='#424242',
    border='#3e3e42',
    table='#1e1e1e',
    table_alt='#252526',
    table_header='#2d2d30',
    selection='#1f4260',
    text='#e0e0e0',
    text_muted='#9ca3af',
    text_strong='#ffffff',
    accent='#007acc',
    success='#22c55e',
    warning='#f59e0b',
    danger='#ef4444',
)
"""The canonical palette the whole GUI is designed against (the identity theme)."""

BUILTIN_THEMES: Final[tuple[Theme, ...]] = (
    Theme(DEFAULT_THEME_NAME, DARK_THEME_COLORS, builtin=True),
    Theme(
        LIGHT_THEME_NAME,
        ThemeColors(
            background='#f3f4f6',
            surface='#ffffff',
            menubar='#e4e8ee',
            statusbar='#e4e8ee',
            popup='#ffffff',
            control='#e5e7eb',
            input='#ffffff',
            scrollbar='#b8bec8',
            border='#c4c9d1',
            table='#ffffff',
            table_alt='#f6f8fa',
            table_header='#d8e0eb',
            selection='#cce4ff',
            text='#1f2328',
            text_muted='#57606a',
            text_strong='#0b0d10',
            accent='#0969da',
            success='#1a7f37',
            warning='#b26a00',
            danger='#cf222e',
        ),
        builtin=True,
    ),
    Theme(
        'Midnight',
        ThemeColors(
            background='#000000',
            surface='#0b0b0e',
            menubar='#101015',
            statusbar='#101015',
            popup='#121218',
            control='#181820',
            input='#07070a',
            scrollbar='#2e2e38',
            border='#2a2a33',
            table='#060609',
            table_alt='#0d0d12',
            table_header='#14141c',
            selection='#17335c',
            text='#d4d4d8',
            text_muted='#8b8b94',
            text_strong='#ffffff',
            accent='#3b82f6',
            success='#22c55e',
            warning='#f59e0b',
            danger='#ef4444',
        ),
        builtin=True,
    ),
    Theme(
        'Dracula',
        ThemeColors(
            background='#21222c',
            surface='#282a36',
            menubar='#191a21',
            statusbar='#191a21',
            popup='#282a36',
            control='#343746',
            input='#1e1f29',
            scrollbar='#4d5066',
            border='#44475a',
            table='#242631',
            table_alt='#2b2d3a',
            table_header='#313442',
            selection='#44475a',
            text='#f8f8f2',
            text_muted='#9ea8c7',
            text_strong='#ffffff',
            accent='#bd93f9',
            success='#50fa7b',
            warning='#ffb86c',
            danger='#ff5555',
        ),
        builtin=True,
    ),
    Theme(
        'Nord',
        ThemeColors(
            background='#2e3440',
            surface='#3b4252',
            menubar='#292e39',
            statusbar='#292e39',
            popup='#3b4252',
            control='#434c5e',
            input='#323846',
            scrollbar='#566178',
            border='#4c566a',
            table='#313744',
            table_alt='#373e4d',
            table_header='#434c5e',
            selection='#435a78',
            text='#e5e9f0',
            text_muted='#9aa5b8',
            text_strong='#eceff4',
            accent='#5e81ac',
            success='#a3be8c',
            warning='#ebcb8b',
            danger='#bf616a',
        ),
        builtin=True,
    ),
    Theme(
        'Solarized Light',
        ThemeColors(
            background='#eee8d5',
            surface='#fdf6e3',
            menubar='#e3dcc5',
            statusbar='#e3dcc5',
            popup='#fdf6e3',
            control='#e4ddc8',
            input='#fdf6e3',
            scrollbar='#bfb79f',
            border='#c9c1a9',
            table='#fdf6e3',
            table_alt='#f4eedb',
            table_header='#dbd2b8',
            selection='#cfe2ea',
            text='#073642',
            text_muted='#657b83',
            text_strong='#002b36',
            accent='#268bd2',
            success='#859900',
            warning='#b58900',
            danger='#dc322f',
        ),
        builtin=True,
    ),
)

BUILTIN_THEME_NAMES: Final[frozenset[str]] = frozenset(theme.name.casefold() for theme in BUILTIN_THEMES)


class ThemeColorsModel(BaseModel):
    """Validated `ThemeColors` tokens as stored in `themes.json`."""

    model_config = ConfigDict(extra='ignore')

    background: HexColor = DARK_THEME_COLORS.background
    surface: HexColor = DARK_THEME_COLORS.surface
    menubar: HexColor = DARK_THEME_COLORS.menubar
    statusbar: HexColor = DARK_THEME_COLORS.statusbar
    popup: HexColor = DARK_THEME_COLORS.popup
    control: HexColor = DARK_THEME_COLORS.control
    input: HexColor = DARK_THEME_COLORS.input
    scrollbar: HexColor = DARK_THEME_COLORS.scrollbar
    border: HexColor = DARK_THEME_COLORS.border
    table: HexColor = DARK_THEME_COLORS.table
    table_alt: HexColor = DARK_THEME_COLORS.table_alt
    table_header: HexColor = DARK_THEME_COLORS.table_header
    selection: HexColor = DARK_THEME_COLORS.selection
    text: HexColor = DARK_THEME_COLORS.text
    text_muted: HexColor = DARK_THEME_COLORS.text_muted
    text_strong: HexColor = DARK_THEME_COLORS.text_strong
    accent: HexColor = DARK_THEME_COLORS.accent
    success: HexColor = DARK_THEME_COLORS.success
    warning: HexColor = DARK_THEME_COLORS.warning
    danger: HexColor = DARK_THEME_COLORS.danger

    def to_theme_colors(self) -> ThemeColors:
        """Return the tokens as an immutable `ThemeColors`."""
        return ThemeColors(**self.model_dump())

    @classmethod
    def from_theme_colors(cls, colors: ThemeColors) -> Self:
        """Build the storage model from `ThemeColors`."""
        return cls(**colors.as_dict())


class CustomThemeModel(BaseModel):
    """A user-defined custom theme."""

    model_config = ConfigDict(extra='forbid')

    name: ThemeName
    colors: ThemeColorsModel

    @field_validator('name')
    @classmethod
    def _validate_name(cls, name: str) -> str:
        if name.casefold() in BUILTIN_THEME_NAMES:
            error_message = f'Custom theme name {name!r} is reserved by a built-in theme.'
            raise ValueError(error_message)
        return name

    def to_theme(self) -> Theme:
        """Return this custom theme as a `Theme`."""
        return Theme(self.name, self.colors.to_theme_colors())


class ThemesFile(BaseModel):
    """Root model of `themes.json` (and theme export files): every user-defined custom theme."""

    model_config = ConfigDict(extra='forbid')

    custom_themes: list[CustomThemeModel] = Field(default_factory=list[CustomThemeModel])

    @model_validator(mode='after')
    def _validate_unique_names(self) -> Self:
        seen: set[str] = set()
        for theme in self.custom_themes:
            key = theme.name.casefold()
            if key in seen:
                error_message = f'Duplicate custom theme name {theme.name!r}.'
                raise ValueError(error_message)
            seen.add(key)
        return self

    def all_themes(self) -> list[Theme]:
        """Return the built-in themes followed by the custom themes."""
        return [*BUILTIN_THEMES, *(theme.to_theme() for theme in self.custom_themes)]

    def find_theme(self, name: str) -> Theme | None:
        """Return the theme named *name* (case-insensitive), or `None`."""
        key = name.strip().casefold()
        return next((theme for theme in self.all_themes() if theme.name.casefold() == key), None)


def make_unique_theme_name(desired_base: str, existing_casefold: set[str], *, fallback_base: str = 'Custom Theme') -> str:
    """Return a non-colliding custom theme name within `THEME_NAME_MAX_LENGTH`."""
    cleaned_base = desired_base.strip() or fallback_base
    trimmed_base = cleaned_base[:THEME_NAME_MAX_LENGTH].rstrip()
    if trimmed_base and trimmed_base.casefold() not in existing_casefold and trimmed_base.casefold() not in BUILTIN_THEME_NAMES:
        return trimmed_base

    counter = 2
    while True:
        suffix = f' {counter}'
        max_prefix_len = THEME_NAME_MAX_LENGTH - len(suffix)
        candidate = f'{cleaned_base[:max_prefix_len].rstrip()}{suffix}'
        if candidate.casefold() not in existing_casefold and candidate.casefold() not in BUILTIN_THEME_NAMES:
            return candidate
        counter += 1


def build_exportable_themes_json(
    themes: Sequence[Theme],
    *,
    edited_theme_name: str | None = None,
    override_name: str | None = None,
    override_colors: ThemeColors | None = None,
) -> str:
    """Serialize *themes* as ready-to-import `themes.json`, renaming any built-in presets safely."""
    models: list[CustomThemeModel] = []
    used_names: set[str] = set()
    edited_cf = edited_theme_name.casefold() if edited_theme_name is not None else None
    for theme in themes:
        is_edited = edited_cf is not None and theme.name.casefold() == edited_cf
        colors = override_colors if is_edited and override_colors is not None else theme.colors
        raw_name = (override_name.strip() or theme.name) if is_edited and override_name is not None else theme.name
        desired_name = f'{raw_name} Custom' if raw_name.casefold() in BUILTIN_THEME_NAMES else raw_name
        safe_name = make_unique_theme_name(desired_name, used_names)
        used_names.add(safe_name.casefold())
        models.append(CustomThemeModel(name=safe_name, colors=ThemeColorsModel.from_theme_colors(colors)))
    return ThemesFile(custom_themes=models).model_dump_json(indent=4)


def _serialize_themes_file(themes_file: ThemesFile) -> str:
    return themes_file.model_dump_json(indent=4) + '\n'


def load_themes_file(themes_path: Path = THEMES_PATH) -> tuple[ThemesFile, str | None]:
    """Load *themes_path*, rewriting stale or non-canonical entries, and return `(themes_file, error_or_none)`.

    A missing file yields the empty defaults without an error. An unreadable or invalid file also yields
    the empty defaults (the file on disk is left untouched until the next save) together with the error text.
    """
    if not themes_path.is_file():
        return ThemesFile(), None
    try:
        raw_text = themes_path.read_text(encoding='utf-8')
        themes_file = ThemesFile.model_validate_json(raw_text)
    except (OSError, UnicodeDecodeError, ValidationError) as e:
        return ThemesFile(), f'Failed to load themes from {themes_path}: {e}'
    canonical_text = _serialize_themes_file(themes_file)
    if raw_text != canonical_text:
        try:
            atomic_write_text(themes_path, canonical_text)
        except OSError as e:
            return themes_file, f'Failed to rewrite themes file {themes_path}: {e}'
    return themes_file, None


def save_themes_file(themes_file: ThemesFile, themes_path: Path = THEMES_PATH) -> None:
    """Atomically write *themes_file* to *themes_path*."""
    atomic_write_text(themes_path, _serialize_themes_file(themes_file))


def peek_theme_config(settings_path: Path = SETTINGS_PATH) -> tuple[str, bool, str | None]:
    """Read `GUI_THEME` and `GUI_THEME_FOLLOW_SYSTEM` from *settings_path* before full `Settings` initialization.

    Returns `(theme_name, follow_system, warning_or_none)`, defaulting to `(DEFAULT_THEME_NAME, True, ...)`
    when the settings file does not exist (first launch), omits either key, or cannot be parsed.
    """
    if not settings_path.is_file():
        return DEFAULT_THEME_NAME, True, None
    try:
        parsed: object = json.loads(settings_path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as e:
        return DEFAULT_THEME_NAME, True, f'Failed to read theme settings from {settings_path}: {e}'
    if not isinstance(parsed, dict):
        return DEFAULT_THEME_NAME, True, None

    theme_name = DEFAULT_THEME_NAME
    follow_system = True
    for raw_key, raw_value in cast('dict[object, object]', parsed).items():
        if not isinstance(raw_key, str):
            continue
        upper_key = raw_key.strip().upper()
        if upper_key == 'GUI_THEME':
            if isinstance(raw_value, str) and raw_value.strip():
                theme_name = raw_value.strip()
        elif upper_key == 'GUI_THEME_FOLLOW_SYSTEM':
            if isinstance(raw_value, bool):
                follow_system = raw_value
            elif isinstance(raw_value, str):
                try:
                    follow_system, _ = custom_str_to_bool(raw_value)
                except InvalidBooleanValueError:
                    follow_system = True
    return theme_name, follow_system, None
