"""Theme color tokens, built-in theme presets, and custom theme persistence (`themes.json`)."""

import json
from dataclasses import dataclass, fields
from typing import TYPE_CHECKING, Annotated, Final, Self, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, field_validator, model_validator

from session_sniffer.constants.local import SETTINGS_PATH, THEMES_PATH
from session_sniffer.utils import atomic_write_text

if TYPE_CHECKING:
    from pathlib import Path

THEME_NAME_MAX_LENGTH: Final = 40

type HexColor = Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, pattern=r'^#[0-9a-f]{6}$')]
type ThemeName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=THEME_NAME_MAX_LENGTH)]


@dataclass(frozen=True, slots=True)
class ThemeColors:
    """The editable color tokens that fully describe a theme.

    The application UI is designed against the built-in *Dark* theme. Every design color used by the
    GUI is mapped from that canonical palette onto the active theme's tokens by `ThemeTransform`, so
    a theme only needs to define these anchor colors (all as lowercase `#rrggbb` strings).
    """

    background: str
    surface: str
    control: str
    border: str
    text: str
    text_muted: str
    text_strong: str
    accent: str
    secondary: str
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
    description: str


THEME_COLOR_TOKENS: Final[tuple[ThemeColorToken, ...]] = (
    ThemeColorToken('background', 'Background', 'Main window and dialog background.'),
    ThemeColorToken('surface', 'Surface', 'Input fields, tables, panels, menus, and tooltips.'),
    ThemeColorToken('control', 'Control', 'Buttons, table headers, and other raised controls.'),
    ThemeColorToken('border', 'Border', 'Borders, separators, and grid lines.'),
    ThemeColorToken('text', 'Text', 'Default text color.'),
    ThemeColorToken('text_muted', 'Muted Text', 'Secondary, hint, and placeholder text.'),
    ThemeColorToken('text_strong', 'Strong Text', 'Headings, button labels, and emphasized text.'),
    ThemeColorToken('accent', 'Accent', 'Primary accent: selections, focus, links, and highlighted controls.'),
    ThemeColorToken('secondary', 'Secondary Accent', 'Secondary accent (purple family, e.g. Looky System elements).'),
    ThemeColorToken('success', 'Success', 'Positive states (connected, enabled, healthy).'),
    ThemeColorToken('warning', 'Warning', 'Warning states and cautionary highlights.'),
    ThemeColorToken('danger', 'Danger', 'Errors, destructive actions, and disconnected states.'),
)


@dataclass(frozen=True, slots=True)
class Theme:
    """A named theme, either built-in (read-only) or user-defined."""

    name: str
    colors: ThemeColors
    builtin: bool = False


DEFAULT_THEME_NAME: Final = 'Dark'

DARK_THEME_COLORS: Final = ThemeColors(
    background='#121212',
    surface='#1e1e1e',
    control='#2d2d30',
    border='#3e3e42',
    text='#e0e0e0',
    text_muted='#9ca3af',
    text_strong='#ffffff',
    accent='#007acc',
    secondary='#7c3aed',
    success='#22c55e',
    warning='#f59e0b',
    danger='#ef4444',
)
"""The canonical palette the whole GUI is designed against (the identity theme)."""

BUILTIN_THEMES: Final[tuple[Theme, ...]] = (
    Theme(DEFAULT_THEME_NAME, DARK_THEME_COLORS, builtin=True),
    Theme(
        'Light',
        ThemeColors(
            background='#f3f4f6',
            surface='#ffffff',
            control='#e5e7eb',
            border='#c4c9d1',
            text='#1f2328',
            text_muted='#57606a',
            text_strong='#0b0d10',
            accent='#0969da',
            secondary='#7a3fd1',
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
            control='#17171c',
            border='#2a2a31',
            text='#d4d4d8',
            text_muted='#8b8b94',
            text_strong='#ffffff',
            accent='#3b82f6',
            secondary='#8b5cf6',
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
            control='#343746',
            border='#44475a',
            text='#f8f8f2',
            text_muted='#9ea8c7',
            text_strong='#ffffff',
            accent='#bd93f9',
            secondary='#ff79c6',
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
            control='#434c5e',
            border='#4c566a',
            text='#e5e9f0',
            text_muted='#9aa5b8',
            text_strong='#eceff4',
            accent='#5e81ac',
            secondary='#b48ead',
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
            control='#e4ddc8',
            border='#c9c1a9',
            text='#073642',
            text_muted='#657b83',
            text_strong='#002b36',
            accent='#268bd2',
            secondary='#6c71c4',
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

    model_config = ConfigDict(extra='forbid')

    background: HexColor
    surface: HexColor
    control: HexColor
    border: HexColor
    text: HexColor
    text_muted: HexColor
    text_strong: HexColor
    accent: HexColor
    secondary: HexColor
    success: HexColor
    warning: HexColor
    danger: HexColor

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


def load_themes_file(themes_path: Path = THEMES_PATH) -> tuple[ThemesFile, str | None]:
    """Load *themes_path*, returning the parsed file and an error description when it could not be loaded.

    A missing file yields the empty defaults without an error. An unreadable or invalid file also yields
    the empty defaults (the file on disk is left untouched until the next save) together with the error text.
    """
    if not themes_path.is_file():
        return ThemesFile(), None
    try:
        return ThemesFile.model_validate_json(themes_path.read_text(encoding='utf-8')), None
    except (OSError, ValidationError) as e:
        return ThemesFile(), f'Failed to load themes from {themes_path}: {e}'


def save_themes_file(themes_file: ThemesFile, themes_path: Path = THEMES_PATH) -> None:
    """Atomically write *themes_file* to *themes_path*."""
    atomic_write_text(themes_path, themes_file.model_dump_json(indent=4) + '\n')


def peek_configured_theme_name(settings_path: Path = SETTINGS_PATH) -> tuple[str, str | None]:
    """Read `GUI_THEME` from *settings_path* before full `Settings` initialization.

    Returns `(theme_name, warning_or_none)`, falling back to `DEFAULT_THEME_NAME` when the settings
    file does not exist, omits `GUI_THEME`, or cannot be parsed.
    """
    if not settings_path.is_file():
        return DEFAULT_THEME_NAME, None
    try:
        parsed: object = json.loads(settings_path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as e:
        return DEFAULT_THEME_NAME, f'Failed to read GUI_THEME from {settings_path}: {e}'
    if not isinstance(parsed, dict):
        return DEFAULT_THEME_NAME, None
    for raw_key, raw_value in cast('dict[object, object]', parsed).items():
        if isinstance(raw_key, str) and raw_key.upper() == 'GUI_THEME':
            if isinstance(raw_value, str) and raw_value.strip():
                return raw_value.strip(), None
            return DEFAULT_THEME_NAME, None
    return DEFAULT_THEME_NAME, None
