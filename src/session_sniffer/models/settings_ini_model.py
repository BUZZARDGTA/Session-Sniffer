"""Pydantic model for Settings.ini validation and normalization.

Replaces the manual per-field if/elif chain in Settings.load_from_settings_file().
The model validates raw string values from the INI parser and normalizes them
into their runtime Python types, while tracking which fields need rewriting.

The INI parser produces a dict[str, str] of UPPER_CASE key → raw string value.
This model validates each field and records canonical rewrite intent via context.
"""

import ast
from dataclasses import dataclass
from typing import Any, ClassVar, Self, cast

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, ValidationInfo, field_validator, model_validator
from PySide6.QtGui import QColor

from session_sniffer.constants.standalone import (
    CAPTURE_FILTER_BLOCK_SETTINGS,
    DEFAULT_DETECTED_SERVER_COLOR,
    MAX_PORT,
    MIN_PORT,
    USERIP_BACKUP_FREQUENCIES,
    WEBSERVER_DEFAULT_HOST,
)
from session_sniffer.networking.ip_range import parse_ip_range
from session_sniffer.networking.utils import format_mac_address, is_ipv4_address, is_mac_address
from session_sniffer.utils import (
    check_case_insensitive_and_exact_match,
    custom_str_to_bool,
    custom_str_to_nonetype,
    validate_and_strip_balanced_outer_parens,
)
from session_sniffer.utils_exceptions import InvalidBooleanValueError, InvalidNoneTypeValueError, NoMatchFoundError


def _parse_int_value(value: object) -> int | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value))
        except ValueError:
            return None
    return None


def _parse_float_value(value: object) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


@dataclass(slots=True)
class SettingsValidationConfig:
    """Bundled configuration parameters for `SettingsIniModel.validate_and_get_rewrites`."""

    defaults: dict[str, Any]
    all_setting_names: tuple[str, ...]
    toggleable_connected_columns: tuple[str, ...]
    toggleable_disconnected_columns: tuple[str, ...]
    all_connected_columns: tuple[str, ...]
    all_disconnected_columns: tuple[str, ...]
    all_third_party_servers: tuple[str, ...]
    max_gui_table_rows_per_page: int
    min_gui_disconnected_players_timer: int
    max_gui_disconnected_players_limit: int


@dataclass(slots=True)
class _ValidatorContext:
    defaults: dict[str, Any]
    ini_rewrites: dict[str, str]
    flags: dict[str, Any]
    toggleable_connected_columns: tuple[str, ...]
    toggleable_disconnected_columns: tuple[str, ...]
    all_connected_columns: tuple[str, ...]
    all_disconnected_columns: tuple[str, ...]
    all_third_party_servers: tuple[str, ...]
    max_gui_table_rows_per_page: int
    min_gui_disconnected_players_timer: int
    max_gui_disconnected_players_limit: int


class SettingsIniModel(BaseModel):
    """Pydantic model representing validated Settings.ini values."""

    model_config = ConfigDict(extra='allow', strict=True, arbitrary_types_allowed=True)

    # Capture settings
    CAPTURE_INTERFACE_NAME: str | None
    CAPTURE_IP_ADDRESS: str | None
    CAPTURE_MAC_ADDRESS: str | None
    CAPTURE_ARP_SPOOFING: bool
    CAPTURE_BLOCK_THIRD_PARTY_SERVERS: tuple[str, ...]
    CAPTURE_FEATURE_SET: str | None
    CAPTURE_FILTER_PROCESS_PID: int
    CAPTURE_FILTER_PROCESS_NAME: str | None
    CAPTURE_FILTER_PROCESS_TRACK_BY_NAME: bool
    CAPTURE_OVERFLOW_TIMER: int
    CAPTURE_PS3_NAME_RESOLVER: bool
    CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER: str | None
    CAPTURE_BLOCKED_IPS: tuple[str, ...]
    CAPTURE_FILTERED_ISPS: tuple[str, ...]
    CAPTURE_FILTER_BLOCK_RTCP: bool
    CAPTURE_FILTER_BLOCK_SSDP: bool
    CAPTURE_FILTER_BLOCK_RAKNET: bool
    CAPTURE_FILTER_BLOCK_DTLS: bool
    CAPTURE_FILTER_BLOCK_UAUDP: bool
    CAPTURE_FILTER_BLOCK_CLASSICSTUN: bool
    CAPTURE_FILTER_BLOCK_LLMNR: bool

    # GUI settings
    GUI_ALWAYS_ON_TOP: bool
    GUI_REMEMBER_WINDOW_LAYOUT: bool
    GUI_SERVERS_COLOR_ENABLED: bool
    GUI_SERVERS_COLOR: str
    GUI_INTERFACE_SELECTION_AUTO_CONNECT: bool
    GUI_INTERFACE_SELECTION_HIDE_INACTIVE: bool
    GUI_INTERFACE_SELECTION_HIDE_NEIGHBOURS: bool
    GUI_SESSIONS_LOGGING: bool
    GUI_SESSIONS_LOGGING_DELETE_EMPTY_FILES: bool
    GUI_SESSIONS_LOGGING_DELETE_EMPTY_FOLDERS: bool
    GUI_RESET_PORTS_ON_REJOINS: bool
    GUI_SESSION_HOST_DETECTION: bool
    GUI_SESSION_HOST_ICON: bool
    GUI_COLUMNS_CONNECTED_SHOWN: tuple[str, ...]
    GUI_COLUMNS_DISCONNECTED_SHOWN: tuple[str, ...]
    GUI_COLUMNS_DATETIME_SHOW_DATE: bool
    GUI_COLUMNS_DATETIME_SHOW_TIME: bool
    GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME: bool
    GUI_COLUMNS_TIMEZONE_DISPLAY: str
    GUI_COLUMNS_GEO_COUNTRY_APPEND_ALPHA2: bool
    GUI_COLUMNS_GEO_CONTINENT_APPEND_ALPHA2: bool
    GUI_CONNECTED_TABLE_ROWS_PER_PAGE: int
    GUI_CONNECTED_TABLE_SORT_COLUMN: str
    GUI_CONNECTED_TABLE_SORT_ORDER: str
    GUI_DISCONNECTED_PLAYERS_ENABLED: bool
    GUI_DISCONNECTED_TABLE_ROWS_PER_PAGE: int
    GUI_DISCONNECTED_TABLE_SORT_COLUMN: str
    GUI_DISCONNECTED_TABLE_SORT_ORDER: str
    GUI_DISCONNECTED_PLAYERS_TIMER: int
    GUI_DISCONNECTED_PLAYERS_LIMIT: int
    GUI_IGNORE_SCREEN_RESOLUTION_WARNING: bool
    VOICE_NOTIFICATIONS_ENABLED: bool

    # Detection settings

    # Discord / updater
    DISCORD_PRESENCE: bool
    DISCORD_PRESENCE_TITLE: str
    SHOW_DISCORD_POPUP: bool
    DISCORD_WEBHOOK_ENABLED: bool
    DISCORD_WEBHOOK_URL: str | None
    DISCORD_WEBHOOK_REFRESH_INTERVAL: int
    DISCORD_WEBHOOK_INCLUDE_CONNECTED: bool
    DISCORD_WEBHOOK_INCLUDE_DISCONNECTED: bool
    DISCORD_WEBHOOK_MAX_ROWS_PER_TABLE: int
    DISCORD_WEBHOOK_MAX_CONNECTED_PLAYERS: int
    DISCORD_WEBHOOK_MAX_DISCONNECTED_PLAYERS: int
    DISCORD_WEBHOOK_FORMAT: str
    DISCORD_WEBHOOK_COLUMNS_CONNECTED: tuple[str, ...]
    DISCORD_WEBHOOK_COLUMNS_DISCONNECTED: tuple[str, ...]
    DISCORD_WEBHOOK_MESSAGE_IDS: str | None
    WEBSERVER_ENABLED: bool
    WEBSERVER_HOST: str
    WEBSERVER_PORT: int
    WEBSERVER_USERNAME: str | None
    WEBSERVER_PASSWORD: str | None
    UPDATER_CHANNEL: str | None
    UPDATER_SKIPPED_VERSION: str | None
    USERIP_BACKUP_FREQUENCY: str
    USERIP_BACKUP_RETENTION_LIMIT: int
    USERIP_SYNC_KNOWN_ALTS: bool
    LOOKY_ENABLED: bool
    LOOKY_EXCLUSIVE_GTA5_PROCESS: bool
    LOOKY_GAME_VERSION: str
    LOOKY_API_KEY: str | None
    PINGER_LOCAL: bool
    PING_COUNT: int
    PING_INTERVAL_MS: int
    PING_TIMEOUT_MS: int
    PING_PAYLOAD_BYTES: int
    SOLO_SESSION_DURATION: int
    HIGH_RATE_MONITOR_MODE: str
    HIGH_RATE_MONITOR_ICON: bool
    HIGH_RATE_MONITOR_RUN_IN_BACKGROUND: bool
    HIGH_RATE_MONITOR_AUTO_SELECT: bool
    HIGH_RATE_MONITOR_PPS_THRESHOLD: int
    HIGH_RATE_MONITOR_BPS_THRESHOLD: int
    HIGH_RATE_MONITOR_DURATION_THRESHOLD: int
    PLAYER_IDENTIFIER_ICON: bool
    PLAYER_IDENTIFIER_SPIKE_ZSCORE: float
    PLAYER_IDENTIFIER_SPIKE_SECONDS: int
    PLAYER_IDENTIFIER_BASELINE_SECONDS: int
    PLAYER_IDENTIFIER_CONTAMINATION_ZSCORE: float
    PLAYER_IDENTIFIER_CONTAMINATION_SECONDS: int
    PLAYER_IDENTIFIER_CONTAMINATION_MIN_SAMPLES: int
    PLAYER_IDENTIFIER_BASELINE_TIMEOUT: int
    PLAYER_IDENTIFIER_SESSION_DRIFT_ZSCORE: float

    # --- Internal context helpers ---

    _BOOL_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            'CAPTURE_ARP_SPOOFING',
            'CAPTURE_FILTER_PROCESS_TRACK_BY_NAME',
            'CAPTURE_PS3_NAME_RESOLVER',
            *CAPTURE_FILTER_BLOCK_SETTINGS,
            'DISCORD_PRESENCE',
            'DISCORD_WEBHOOK_ENABLED',
            'DISCORD_WEBHOOK_INCLUDE_CONNECTED',
            'DISCORD_WEBHOOK_INCLUDE_DISCONNECTED',
            'WEBSERVER_ENABLED',
            'GUI_ALWAYS_ON_TOP',
            'GUI_REMEMBER_WINDOW_LAYOUT',
            'GUI_SERVERS_COLOR_ENABLED',
            'GUI_COLUMNS_DATETIME_SHOW_DATE',
            'GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME',
            'GUI_COLUMNS_DATETIME_SHOW_TIME',
            'GUI_COLUMNS_GEO_CONTINENT_APPEND_ALPHA2',
            'GUI_COLUMNS_GEO_COUNTRY_APPEND_ALPHA2',
            'GUI_INTERFACE_SELECTION_AUTO_CONNECT',
            'GUI_INTERFACE_SELECTION_HIDE_INACTIVE',
            'GUI_INTERFACE_SELECTION_HIDE_NEIGHBOURS',
            'GUI_RESET_PORTS_ON_REJOINS',
            'GUI_SESSION_HOST_DETECTION',
            'GUI_SESSION_HOST_ICON',
            'GUI_SESSIONS_LOGGING',
            'GUI_SESSIONS_LOGGING_DELETE_EMPTY_FILES',
            'GUI_SESSIONS_LOGGING_DELETE_EMPTY_FOLDERS',
            'GUI_DISCONNECTED_PLAYERS_ENABLED',
            'GUI_IGNORE_SCREEN_RESOLUTION_WARNING',
            'LOOKY_ENABLED',
            'LOOKY_EXCLUSIVE_GTA5_PROCESS',
            'PINGER_LOCAL',
            'SHOW_DISCORD_POPUP',
            'VOICE_NOTIFICATIONS_ENABLED',
            'HIGH_RATE_MONITOR_ICON',
            'HIGH_RATE_MONITOR_RUN_IN_BACKGROUND',
            'HIGH_RATE_MONITOR_AUTO_SELECT',
            'PLAYER_IDENTIFIER_ICON',
            'USERIP_SYNC_KNOWN_ALTS',
        },
    )

    _CLAMPED_INT_BOUNDS: ClassVar[dict[str, tuple[int, int, int]]] = {
        'DISCORD_WEBHOOK_REFRESH_INTERVAL': (5, 300, 15),
        'SOLO_SESSION_DURATION': (6, 60, 6),
        'HIGH_RATE_MONITOR_PPS_THRESHOLD': (20, 50, 30),
        'HIGH_RATE_MONITOR_BPS_THRESHOLD': (3, 500, 5),
        'HIGH_RATE_MONITOR_DURATION_THRESHOLD': (1, 10, 3),
        'PLAYER_IDENTIFIER_SPIKE_SECONDS': (1, 30, 3),
        'PLAYER_IDENTIFIER_BASELINE_SECONDS': (5, 120, 10),
        'PLAYER_IDENTIFIER_CONTAMINATION_SECONDS': (1, 30, 5),
        'PLAYER_IDENTIFIER_CONTAMINATION_MIN_SAMPLES': (5, 60, 15),
        'PLAYER_IDENTIFIER_BASELINE_TIMEOUT': (10, 300, 30),
        'DISCORD_WEBHOOK_MAX_ROWS_PER_TABLE': (1, 100, 25),
        'DISCORD_WEBHOOK_MAX_CONNECTED_PLAYERS': (0, 100, 0),
        'DISCORD_WEBHOOK_MAX_DISCONNECTED_PLAYERS': (0, 100, 0),
        'PING_COUNT': (0, 10000, 4),
        'PING_INTERVAL_MS': (50, 10000, 250),
        'PING_TIMEOUT_MS': (100, 10000, 1000),
        'PING_PAYLOAD_BYTES': (0, 65500, 32),
    }

    _CLAMPED_FLOAT_BOUNDS: ClassVar[dict[str, tuple[float, float, float]]] = {
        'PLAYER_IDENTIFIER_SPIKE_ZSCORE': (1.0, 20.0, 3.0),
        'PLAYER_IDENTIFIER_CONTAMINATION_ZSCORE': (3.0, 50.0, 10.0),
        'PLAYER_IDENTIFIER_SESSION_DRIFT_ZSCORE': (1.0, 30.0, 6.0),
    }

    _ENUM_ALLOWED_VALUES: ClassVar[dict[str, tuple[str, ...]]] = {
        'HIGH_RATE_MONITOR_MODE': ('Smart', 'Manual'),
        'DISCORD_WEBHOOK_FORMAT': ('Desktop', 'Mobile'),
        'GUI_COLUMNS_TIMEZONE_DISPLAY': ('Timezone', 'Timezone + Local Time', 'Local Time'),
        'GUI_CONNECTED_TABLE_SORT_ORDER': ('Ascending', 'Descending'),
        'GUI_DISCONNECTED_TABLE_SORT_ORDER': ('Ascending', 'Descending'),
        'LOOKY_GAME_VERSION': ('Both', 'Legacy', 'Enhanced'),
        'USERIP_BACKUP_FREQUENCY': USERIP_BACKUP_FREQUENCIES,
    }

    _OPTIONAL_ENUM_VALUES: ClassVar[dict[str, tuple[str, ...]]] = {
        'CAPTURE_FEATURE_SET': ('GTA V', 'RDR2'),
        'UPDATER_CHANNEL': ('Stable', 'Pre-release'),
    }

    @staticmethod
    def _get_context(info: ValidationInfo) -> _ValidatorContext | None:
        if not isinstance(info.context, _ValidatorContext):
            return None
        return info.context

    @classmethod
    def _get_default_for_field(cls, info: ValidationInfo) -> object:
        context = cls._get_context(info)
        if context is None:
            return None
        if not isinstance(info.field_name, str):
            return None
        return context.defaults.get(info.field_name)

    @staticmethod
    def _record_rewrite(info: ValidationInfo, rewrite_to: str | None) -> None:
        if rewrite_to is None:
            return
        if not isinstance(info.context, _ValidatorContext):
            return
        if not isinstance(info.field_name, str):
            return
        info.context.ini_rewrites[info.field_name] = rewrite_to

    @staticmethod
    def _set_flag(info: ValidationInfo, flag_name: str, *, value: object) -> None:
        if not isinstance(info.context, _ValidatorContext):
            return
        info.context.flags[flag_name] = value

    # --- Validators ---

    @field_validator(*_BOOL_FIELDS, mode='before')
    @classmethod
    def _normalize_bool_fields(cls, value: object, info: ValidationInfo) -> bool:
        """Parse boolean-like INI tokens and record canonical rewrites when needed."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            try:
                resolved, need_rewrite = custom_str_to_bool(value)
            except InvalidBooleanValueError:
                cls._set_flag(info, 'should_rewrite', value=True)
                default_value = cls._get_default_for_field(info)
                return default_value if isinstance(default_value, bool) else False
            if need_rewrite:
                cls._record_rewrite(info, str(resolved))
            return resolved
        cls._set_flag(info, 'should_rewrite', value=True)
        default_value = cls._get_default_for_field(info)
        return default_value if isinstance(default_value, bool) else False

    @field_validator('CAPTURE_INTERFACE_NAME', mode='before')
    @classmethod
    def _parse_interface_name(cls, value: object, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            try:
                none_value, need_rewrite = custom_str_to_nonetype(value)
            except InvalidNoneTypeValueError:
                return value
            if need_rewrite:
                cls._record_rewrite(info, 'None')
            return none_value
        return cast('str | None', cls._get_default_for_field(info))

    @field_validator('CAPTURE_IP_ADDRESS', mode='before')
    @classmethod
    def _parse_ip_address(cls, value: object, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            try:
                none_value, need_rewrite = custom_str_to_nonetype(value)
            except InvalidNoneTypeValueError:
                if is_ipv4_address(value):
                    return value
                cls._set_flag(info, 'should_rewrite', value=True)
                return cast('str | None', cls._get_default_for_field(info))
            if need_rewrite:
                cls._record_rewrite(info, 'None')
            return none_value
        cls._set_flag(info, 'should_rewrite', value=True)
        return cast('str | None', cls._get_default_for_field(info))

    @field_validator('CAPTURE_MAC_ADDRESS', mode='before')
    @classmethod
    def _parse_mac_address(cls, value: object, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            try:
                none_value, need_rewrite = custom_str_to_nonetype(value)
            except InvalidNoneTypeValueError:
                formatted = format_mac_address(value)
                if is_mac_address(formatted):
                    if formatted != value:
                        cls._record_rewrite(info, formatted)
                    return formatted
                cls._set_flag(info, 'should_rewrite', value=True)
                return cast('str | None', cls._get_default_for_field(info))
            if need_rewrite:
                cls._record_rewrite(info, 'None')
            return none_value
        cls._set_flag(info, 'should_rewrite', value=True)
        return cast('str | None', cls._get_default_for_field(info))

    @field_validator(
        'CAPTURE_BLOCK_THIRD_PARTY_SERVERS',
        'GUI_COLUMNS_CONNECTED_SHOWN',
        'GUI_COLUMNS_DISCONNECTED_SHOWN',
        'DISCORD_WEBHOOK_COLUMNS_CONNECTED',
        'DISCORD_WEBHOOK_COLUMNS_DISCONNECTED',
        mode='before',
    )
    @classmethod
    def _parse_shown_columns(cls, value: object, info: ValidationInfo) -> tuple[str, ...]:
        context = cls._get_context(info)
        column_map = {
            'CAPTURE_BLOCK_THIRD_PARTY_SERVERS': context.all_third_party_servers if context else (),
            'GUI_COLUMNS_CONNECTED_SHOWN': context.toggleable_connected_columns if context else (),
            'GUI_COLUMNS_DISCONNECTED_SHOWN': context.toggleable_disconnected_columns if context else (),
            'DISCORD_WEBHOOK_COLUMNS_CONNECTED': context.all_connected_columns if context else (),
            'DISCORD_WEBHOOK_COLUMNS_DISCONNECTED': context.all_disconnected_columns if context else (),
        }
        allowed = column_map.get(info.field_name or '', ())

        if isinstance(value, tuple):
            return cast('tuple[str, ...]', value)
        if isinstance(value, str):
            normalized, need_rewrite_current, need_rewrite_settings = _normalize_tuple_column(value, allowed)
            if need_rewrite_current:
                cls._record_rewrite(info, str(normalized) if normalized is not None else str(cls._get_default_for_field(info)))
            if need_rewrite_settings:
                cls._set_flag(info, 'should_rewrite', value=True)
            return normalized if normalized is not None else cast('tuple[str, ...]', cls._get_default_for_field(info) or ())
        cls._set_flag(info, 'should_rewrite', value=True)
        return cast('tuple[str, ...]', cls._get_default_for_field(info) or ())

    @field_validator('CAPTURE_BLOCKED_IPS', mode='before')
    @classmethod
    def _parse_blocked_ips(cls, value: object, info: ValidationInfo) -> tuple[str, ...]:
        if isinstance(value, tuple):
            return cast('tuple[str, ...]', value)
        if isinstance(value, str):
            try:
                parsed: object = ast.literal_eval(value)
            except ValueError, SyntaxError, RecursionError, MemoryError:
                cls._set_flag(info, 'should_rewrite', value=True)
                return ()
            if not isinstance(parsed, tuple) or not all(isinstance(item, str) for item in cast('tuple[str | int, ...]', parsed)):
                cls._set_flag(info, 'should_rewrite', value=True)
                return ()
            valid_items: list[str] = []
            need_rewrite = False
            for item in cast('tuple[str, ...]', parsed):
                try:
                    parse_ip_range(item)
                    valid_items.append(item)
                except ValueError:
                    need_rewrite = True
            if need_rewrite:
                cls._set_flag(info, 'should_rewrite', value=True)
            return tuple(valid_items)
        cls._set_flag(info, 'should_rewrite', value=True)
        return ()

    @field_validator('CAPTURE_FILTERED_ISPS', mode='before')
    @classmethod
    def _parse_filtered_isps(cls, value: object, info: ValidationInfo) -> tuple[str, ...]:
        if isinstance(value, tuple):
            return cast('tuple[str, ...]', value)
        if isinstance(value, str):
            try:
                parsed: object = ast.literal_eval(value)
            except ValueError, SyntaxError, RecursionError, MemoryError:
                cls._set_flag(info, 'should_rewrite', value=True)
                return ()
            if not isinstance(parsed, tuple):
                cls._set_flag(info, 'should_rewrite', value=True)
                return ()
            valid_items: list[str] = []
            need_rewrite = False
            for item in cast('tuple[object, ...]', parsed):
                if isinstance(item, str) and (stripped := item.strip()):
                    if stripped != item:
                        need_rewrite = True
                    valid_items.append(stripped)
                else:
                    need_rewrite = True
            if need_rewrite:
                cls._set_flag(info, 'should_rewrite', value=True)
            return tuple(valid_items)
        cls._set_flag(info, 'should_rewrite', value=True)
        return ()

    @field_validator(*_OPTIONAL_ENUM_VALUES, mode='before')
    @classmethod
    def _parse_optional_enum(cls, value: object, info: ValidationInfo) -> str | None:
        field_name = info.field_name or ''
        allowed = cls._OPTIONAL_ENUM_VALUES[field_name]
        if value is None:
            return None
        if isinstance(value, str):
            try:
                none_value, need_rewrite = custom_str_to_nonetype(value)
            except InvalidNoneTypeValueError:
                try:
                    case_match, normalized = check_case_insensitive_and_exact_match(value, allowed)
                except NoMatchFoundError:
                    cls._set_flag(info, 'should_rewrite', value=True)
                    return cast('str | None', cls._get_default_for_field(info))
                if not case_match:
                    cls._record_rewrite(info, normalized)
                return normalized
            if need_rewrite:
                cls._record_rewrite(info, 'None')
            return none_value
        cls._set_flag(info, 'should_rewrite', value=True)
        return cast('str | None', cls._get_default_for_field(info))

    @field_validator('CAPTURE_OVERFLOW_TIMER', 'CAPTURE_FILTER_PROCESS_PID', mode='before')
    @classmethod
    def _parse_non_negative_int(cls, value: object, info: ValidationInfo) -> int:
        default = cls._get_default_for_field(info)
        fallback = 3 if info.field_name == 'CAPTURE_OVERFLOW_TIMER' else 0
        default_int = default if isinstance(default, int) else fallback

        parsed = _parse_int_value(value)
        if parsed is not None and parsed >= 0:
            return parsed
        cls._set_flag(info, 'should_rewrite', value=True)
        return default_int

    @field_validator('CAPTURE_FILTER_PROCESS_NAME', mode='before')
    @classmethod
    def _parse_filter_process_name(cls, value: object, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            try:
                none_value, need_rewrite = custom_str_to_nonetype(value)
            except InvalidNoneTypeValueError:
                stripped = value.strip()
                if stripped != value:
                    cls._set_flag(info, 'should_rewrite', value=True)
                return stripped or None
            if need_rewrite:
                cls._record_rewrite(info, 'None')
            return none_value
        cls._set_flag(info, 'should_rewrite', value=True)
        return cast('str | None', cls._get_default_for_field(info))

    @field_validator('CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER', mode='before')
    @classmethod
    def _parse_custom_filter(cls, value: object, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            try:
                none_value, need_rewrite = custom_str_to_nonetype(value)
            except InvalidNoneTypeValueError:
                stripped = validate_and_strip_balanced_outer_parens(value)
                if value != stripped:
                    cls._set_flag(info, 'should_rewrite', value=True)
                return stripped
            if need_rewrite:
                cls._record_rewrite(info, 'None')
            return none_value
        return cast('str | None', cls._get_default_for_field(info))

    @field_validator('GUI_CONNECTED_TABLE_ROWS_PER_PAGE', 'GUI_DISCONNECTED_TABLE_ROWS_PER_PAGE', mode='before')
    @classmethod
    def _parse_rows_per_page(cls, value: object, info: ValidationInfo) -> int:
        maximum_rows_per_page = 5000  # Settings.MAX_GUI_TABLE_ROWS_PER_PAGE
        context = cls._get_context(info)
        if context is not None:
            maximum_rows_per_page = context.max_gui_table_rows_per_page

        default = cls._get_default_for_field(info)
        default_int = default if isinstance(default, int) else 0

        parsed = _parse_int_value(value)
        if parsed is not None and 0 <= parsed <= maximum_rows_per_page:
            return parsed

        cls._set_flag(info, 'should_rewrite', value=True)
        return default_int

    @field_validator('WEBSERVER_PORT', mode='before')
    @classmethod
    def _parse_webserver_port(cls, value: object, info: ValidationInfo) -> int:
        default = cls._get_default_for_field(info)
        default_int = default if isinstance(default, int) else 80

        if isinstance(value, bool):
            cls._set_flag(info, 'should_rewrite', value=True)
            return default_int

        port = _parse_int_value(value)
        if port is not None and MIN_PORT <= port <= MAX_PORT:
            return port

        cls._set_flag(info, 'should_rewrite', value=True)
        return default_int

    @field_validator('WEBSERVER_HOST', mode='before')
    @classmethod
    def _parse_webserver_host(cls, value: object, info: ValidationInfo) -> str:
        default = cls._get_default_for_field(info)
        default_str = default if isinstance(default, str) else WEBSERVER_DEFAULT_HOST
        if isinstance(value, str) and is_ipv4_address(value):
            return value
        cls._set_flag(info, 'should_rewrite', value=True)
        return default_str

    @field_validator('GUI_DISCONNECTED_PLAYERS_TIMER', mode='before')
    @classmethod
    def _parse_disconnected_timer(cls, value: object, info: ValidationInfo) -> int:
        minimum_timer = 3  # Settings.MIN_GUI_DISCONNECTED_PLAYERS_TIMER_SECONDS
        context = cls._get_context(info)
        if context is not None:
            minimum_timer = context.min_gui_disconnected_players_timer

        default = cls._get_default_for_field(info)
        default_int = default if isinstance(default, int) else 10

        parsed = _parse_int_value(value)
        if parsed is not None and parsed >= minimum_timer:
            return parsed

        cls._set_flag(info, 'should_rewrite', value=True)
        return default_int

    @field_validator('GUI_DISCONNECTED_PLAYERS_LIMIT', mode='before')
    @classmethod
    def _parse_disconnected_limit(cls, value: object, info: ValidationInfo) -> int:
        maximum_limit = 20000
        context = cls._get_context(info)
        if context is not None:
            maximum_limit = context.max_gui_disconnected_players_limit

        default = cls._get_default_for_field(info)
        default_int = default if isinstance(default, int) else 500

        parsed = _parse_int_value(value)
        if parsed is not None and 0 <= parsed <= maximum_limit:
            return parsed

        cls._set_flag(info, 'should_rewrite', value=True)
        return default_int

    @field_validator('DISCORD_PRESENCE_TITLE', mode='before')
    @classmethod
    def _parse_discord_presence_title(cls, value: object, info: ValidationInfo) -> str:
        if isinstance(value, str) and len(value) != 1:
            return value
        cls._set_flag(info, 'should_rewrite', value=True)
        default_value = cls._get_default_for_field(info)
        return default_value if isinstance(default_value, str) else ''

    @field_validator('GUI_SERVERS_COLOR', mode='before')
    @classmethod
    def _parse_gui_servers_color(cls, value: object, info: ValidationInfo) -> str:
        if isinstance(value, str) and QColor(value).isValid():
            return value
        cls._set_flag(info, 'should_rewrite', value=True)
        default_value = cls._get_default_for_field(info)
        return str(default_value) if default_value is not None else DEFAULT_DETECTED_SERVER_COLOR

    @field_validator('DISCORD_WEBHOOK_URL', 'DISCORD_WEBHOOK_MESSAGE_IDS', 'WEBSERVER_USERNAME', 'WEBSERVER_PASSWORD', 'LOOKY_API_KEY', mode='before')
    @classmethod
    def _parse_optional_string(cls, value: object, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            try:
                none_value, need_rewrite = custom_str_to_nonetype(value)
            except InvalidNoneTypeValueError:
                return value
            if need_rewrite:
                cls._record_rewrite(info, 'None')
            return none_value
        cls._set_flag(info, 'should_rewrite', value=True)
        return cast('str | None', cls._get_default_for_field(info))

    @field_validator(*_CLAMPED_INT_BOUNDS, mode='before')
    @classmethod
    def _parse_clamped_int(cls, value: object, info: ValidationInfo) -> int:
        field_name = info.field_name or ''
        minimum_value, maximum_value, fallback_default = cls._CLAMPED_INT_BOUNDS[field_name]
        default = cls._get_default_for_field(info)
        default_int = default if isinstance(default, int) else fallback_default

        parsed = _parse_int_value(value)
        if parsed is None:
            cls._set_flag(info, 'should_rewrite', value=True)
            return default_int
        if parsed < minimum_value:
            cls._set_flag(info, 'should_rewrite', value=True)
            return minimum_value
        if parsed > maximum_value:
            cls._set_flag(info, 'should_rewrite', value=True)
            return maximum_value
        return parsed

    @field_validator(*_CLAMPED_FLOAT_BOUNDS, mode='before')
    @classmethod
    def _parse_clamped_float(cls, value: object, info: ValidationInfo) -> float:
        field_name = info.field_name or ''
        minimum_value, maximum_value, fallback_default = cls._CLAMPED_FLOAT_BOUNDS[field_name]
        default = cls._get_default_for_field(info)
        default_float = default if isinstance(default, float) else fallback_default

        parsed = _parse_float_value(value)
        if parsed is None:
            cls._set_flag(info, 'should_rewrite', value=True)
            return default_float
        if parsed < minimum_value:
            cls._set_flag(info, 'should_rewrite', value=True)
            return minimum_value
        if parsed > maximum_value:
            cls._set_flag(info, 'should_rewrite', value=True)
            return maximum_value
        return parsed

    @field_validator(*_ENUM_ALLOWED_VALUES, mode='before')
    @classmethod
    def _parse_enum_field(cls, value: object, info: ValidationInfo) -> str:
        field_name = info.field_name or ''
        allowed = cls._ENUM_ALLOWED_VALUES[field_name]
        if isinstance(value, str):
            try:
                case_match, normalized = check_case_insensitive_and_exact_match(value, allowed)
            except NoMatchFoundError:
                cls._set_flag(info, 'should_rewrite', value=True)
                return cast('str', cls._get_default_for_field(info))
            if not case_match:
                cls._record_rewrite(info, normalized)
            return normalized
        cls._set_flag(info, 'should_rewrite', value=True)
        return cast('str', cls._get_default_for_field(info))

    @field_validator('GUI_CONNECTED_TABLE_SORT_COLUMN', 'GUI_DISCONNECTED_TABLE_SORT_COLUMN', mode='before')
    @classmethod
    def _parse_table_sort_column(cls, value: object, info: ValidationInfo) -> str:
        context = cls._get_context(info)
        allowed = (
            context.all_connected_columns
            if context and info.field_name == 'GUI_CONNECTED_TABLE_SORT_COLUMN'
            else context.all_disconnected_columns
            if context
            else ()
        )

        if isinstance(value, str):
            try:
                case_match, normalized = check_case_insensitive_and_exact_match(value, allowed)
            except NoMatchFoundError:
                cls._set_flag(info, 'should_rewrite', value=True)
                return cast('str', cls._get_default_for_field(info))
            if not case_match:
                cls._record_rewrite(info, normalized)
            return normalized
        cls._set_flag(info, 'should_rewrite', value=True)
        return cast('str', cls._get_default_for_field(info))

    @field_validator('UPDATER_SKIPPED_VERSION', mode='before')
    @classmethod
    def _parse_updater_skipped_version(cls, value: object, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            try:
                none_value, need_rewrite = custom_str_to_nonetype(value)
            except InvalidNoneTypeValueError:
                stripped = value.strip()
                try:
                    parsed_version = Version(stripped)
                except InvalidVersion:
                    cls._set_flag(info, 'should_rewrite', value=True)
                    return cast('str | None', cls._get_default_for_field(info))

                normalized = str(parsed_version)
                if normalized != value:
                    cls._record_rewrite(info, normalized)
                return normalized
            if need_rewrite:
                cls._record_rewrite(info, 'None')
            return none_value
        cls._set_flag(info, 'should_rewrite', value=True)
        return cast('str | None', cls._get_default_for_field(info))

    @field_validator('USERIP_BACKUP_RETENTION_LIMIT', mode='before')
    @classmethod
    def _parse_userip_backup_retention_limit(cls, value: object, info: ValidationInfo) -> int:
        minimum_limit = 0  # 0 = Keep All
        maximum_limit = 100
        default = cls._get_default_for_field(info)
        default_int = default if isinstance(default, int) else 10

        parsed: int | None
        if isinstance(value, str) and value.strip().lower() in ('keep all', 'keepall', 'all'):
            cls._set_flag(info, 'should_rewrite', value=True)
            parsed = 0
        else:
            parsed = _parse_int_value(value)

        if parsed is None:
            cls._set_flag(info, 'should_rewrite', value=True)
            return default_int
        if parsed < minimum_limit:
            cls._set_flag(info, 'should_rewrite', value=True)
            return minimum_limit
        if parsed > maximum_limit:
            cls._set_flag(info, 'should_rewrite', value=True)
            return maximum_limit
        return parsed

    @model_validator(mode='after')
    def _check_datetime_columns(self, info: ValidationInfo) -> Self:
        """Ensure at least one datetime column is enabled; reset all to defaults if not."""
        if self.GUI_COLUMNS_DATETIME_SHOW_DATE is False and self.GUI_COLUMNS_DATETIME_SHOW_TIME is False and self.GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME is False:
            self._set_flag(info, 'invalid_datetime_columns_corrected', value=True)
            self._set_flag(info, 'should_rewrite', value=True)
            context = self._get_context(info)
            if context is not None:
                return self.model_copy(
                    update={
                        'GUI_COLUMNS_DATETIME_SHOW_DATE': context.defaults.get('GUI_COLUMNS_DATETIME_SHOW_DATE', False),
                        'GUI_COLUMNS_DATETIME_SHOW_TIME': context.defaults.get('GUI_COLUMNS_DATETIME_SHOW_TIME', False),
                        'GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME': context.defaults.get('GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME', True),
                    },
                )
        return self

    @model_validator(mode='after')
    def _check_table_sort_columns(self, info: ValidationInfo) -> Self:
        """Ensure sort columns exist in their respective table's enabled or forced columns."""
        updates: dict[str, Any] = {}
        context = self._get_context(info)
        forced_columns = {'Usernames', 'First Seen', 'Last Rejoin', 'Last Seen', 'Rejoins', 'IP Address'}

        for setting_key, fallback_sort, shown_columns in (
            ('GUI_CONNECTED_TABLE_SORT_COLUMN', 'Last Rejoin', self.GUI_COLUMNS_CONNECTED_SHOWN),
            ('GUI_DISCONNECTED_TABLE_SORT_COLUMN', 'Last Seen', self.GUI_COLUMNS_DISCONNECTED_SHOWN),
        ):
            if getattr(self, setting_key) not in set(shown_columns) | forced_columns:
                updates[setting_key] = fallback_sort
                if context is not None:
                    context.ini_rewrites[setting_key] = fallback_sort
                self._set_flag(info, 'should_rewrite', value=True)

        if updates:
            return self.model_copy(update=updates)
        return self

    # --- Public API ---

    @classmethod
    def validate_and_get_rewrites(
        cls,
        raw_settings: dict[str, str],
        config: SettingsValidationConfig,
    ) -> tuple[Self, dict[str, str], dict[str, Any]]:
        """Validate raw Settings.ini key/value strings and compute a rewrite plan.

        Args:
            raw_settings: Parsed raw settings mapping from the INI file (UPPER_CASE keys).
            config: Bundled validation parameters (defaults, column lists, limits, etc.).

        Returns:
            (validated_model, ini_rewrites, flags)
        """
        all_names_set = frozenset(config.all_setting_names)
        raw_keys = set(raw_settings)

        ini_rewrites: dict[str, str] = {}
        flags: dict[str, Any] = {}

        # Build full input: defaults first, then overwrite with raw values from INI
        full_input: dict[str, Any] = dict(config.defaults)
        full_input.update(raw_settings)

        context = _ValidatorContext(
            defaults=dict(config.defaults),
            ini_rewrites=ini_rewrites,
            flags=flags,
            toggleable_connected_columns=config.toggleable_connected_columns,
            toggleable_disconnected_columns=config.toggleable_disconnected_columns,
            all_connected_columns=config.all_connected_columns,
            all_disconnected_columns=config.all_disconnected_columns,
            all_third_party_servers=config.all_third_party_servers,
            max_gui_table_rows_per_page=config.max_gui_table_rows_per_page,
            min_gui_disconnected_players_timer=config.min_gui_disconnected_players_timer,
            max_gui_disconnected_players_limit=config.max_gui_disconnected_players_limit,
        )
        parsed = cls.model_validate(full_input, context=context)

        # Unknown keys trigger rewrite
        unknown_keys = raw_keys - all_names_set
        if unknown_keys:
            flags['should_rewrite'] = True

        # Missing keys trigger rewrite
        missing_keys = all_names_set - raw_keys
        if missing_keys:
            flags['should_rewrite'] = True

        # Rewrites from validators also trigger
        if ini_rewrites:
            flags['should_rewrite'] = True

        return parsed, dict(ini_rewrites), dict(flags)


def _normalize_tuple_column(
    setting_value: str,
    allowed_columns: tuple[str, ...],
) -> tuple[tuple[str, ...] | None, bool, bool]:
    """Normalize a tuple-valued INI setting (e.g. hidden columns, server list).

    Returns:
        (normalized_tuple, need_rewrite_current, need_rewrite_settings)
    """
    try:
        parsed: object = ast.literal_eval(setting_value)
    except ValueError, SyntaxError, RecursionError, MemoryError:
        return None, False, True

    if not isinstance(parsed, tuple):
        return None, False, True

    if not all(isinstance(item, str) for item in cast('tuple[str | int, ...]', parsed)):
        return None, False, True

    filtered: list[str] = []
    need_rewrite_current = False
    need_rewrite_settings = False

    for value in cast('tuple[str, ...]', parsed):
        try:
            case_match, normalized = check_case_insensitive_and_exact_match(value, allowed_columns)
        except NoMatchFoundError:
            need_rewrite_settings = True
            continue
        filtered.append(normalized)
        if not case_match:
            need_rewrite_current = True

    sorted_result = [column for column in allowed_columns if column in filtered]
    if filtered != sorted_result:
        need_rewrite_current = True

    return tuple(sorted_result), need_rewrite_current, need_rewrite_settings
