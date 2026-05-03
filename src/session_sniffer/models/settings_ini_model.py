"""Pydantic model for Settings.ini validation and normalization.

Replaces the manual per-field if/elif chain in Settings.load_from_settings_file().
The model validates raw string values from the INI parser and normalizes them
into their runtime Python types, while tracking which fields need rewriting.

The INI parser produces a dict[str, str] of UPPER_CASE key → raw string value.
This model validates each field and records canonical rewrite intent via context.
"""

import ast
from typing import Any, ClassVar, Self, cast

from pydantic import BaseModel, ConfigDict, ValidationInfo, field_validator, model_validator

from session_sniffer.networking.ip_range import parse_ip_range
from session_sniffer.networking.utils import format_mac_address, is_ipv4_address, is_mac_address
from session_sniffer.utils import (
    check_case_insensitive_and_exact_match,
    custom_str_to_bool,
    custom_str_to_nonetype,
    validate_and_strip_balanced_outer_parens,
)
from session_sniffer.utils_exceptions import InvalidBooleanValueError, InvalidNoneTypeValueError, NoMatchFoundError


class SettingsIniModel(BaseModel):
    """Pydantic model representing validated Settings.ini values."""

    model_config = ConfigDict(extra='allow', strict=True, arbitrary_types_allowed=True)

    # Capture settings
    CAPTURE_INTERFACE_NAME: str | None
    CAPTURE_IP_ADDRESS: str | None
    CAPTURE_MAC_ADDRESS: str | None
    CAPTURE_ARP_SPOOFING: bool
    CAPTURE_BLOCK_THIRD_PARTY_SERVERS: tuple[str, ...]
    CAPTURE_PROGRAM_PRESET: str | None
    CAPTURE_OVERFLOW_TIMER: int
    CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER: str | None
    CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER: str | None
    CAPTURE_BLOCKED_IPS: tuple[str, ...]

    # GUI settings
    GUI_INTERFACE_SELECTION_AUTO_CONNECT: bool
    GUI_INTERFACE_SELECTION_HIDE_INACTIVE: bool
    GUI_INTERFACE_SELECTION_HIDE_NEIGHBOURS: bool
    GUI_SESSIONS_LOGGING: bool
    GUI_RESET_PORTS_ON_REJOINS: bool
    GUI_SESSION_HOST_DETECTION: bool
    GUI_RATE_GRAPH_ALWAYS_ON_TOP: bool
    GUI_RATE_GRAPH_MAX_HISTORY: int
    GUI_COLUMNS_CONNECTED_SHOWN: tuple[str, ...]
    GUI_COLUMNS_DISCONNECTED_SHOWN: tuple[str, ...]
    GUI_COLUMNS_DATETIME_SHOW_DATE: bool
    GUI_COLUMNS_DATETIME_SHOW_TIME: bool
    GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME: bool
    GUI_COLUMNS_GEO_COUNTRY_APPEND_ALPHA2: bool
    GUI_COLUMNS_GEO_CONTINENT_APPEND_ALPHA2: bool
    GUI_CONNECTED_TABLE_ROWS_PER_PAGE: int
    GUI_DISCONNECTED_TABLE_ROWS_PER_PAGE: int
    GUI_DISCONNECTED_PLAYERS_TIMER: int

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
    UPDATER_CHANNEL: str | None

    # --- Internal context helpers ---

    _BOOL_FIELDS: ClassVar[frozenset[str]] = frozenset({
        'CAPTURE_ARP_SPOOFING',
        'DISCORD_PRESENCE',
        'DISCORD_WEBHOOK_ENABLED',
        'DISCORD_WEBHOOK_INCLUDE_CONNECTED',
        'DISCORD_WEBHOOK_INCLUDE_DISCONNECTED',
        'GUI_COLUMNS_DATETIME_SHOW_DATE',
        'GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME',
        'GUI_COLUMNS_DATETIME_SHOW_TIME',
        'GUI_COLUMNS_GEO_CONTINENT_APPEND_ALPHA2',
        'GUI_COLUMNS_GEO_COUNTRY_APPEND_ALPHA2',
        'GUI_INTERFACE_SELECTION_AUTO_CONNECT',
        'GUI_INTERFACE_SELECTION_HIDE_INACTIVE',
        'GUI_INTERFACE_SELECTION_HIDE_NEIGHBOURS',
        'GUI_RATE_GRAPH_ALWAYS_ON_TOP',
        'GUI_RESET_PORTS_ON_REJOINS',
        'GUI_SESSION_HOST_DETECTION',
        'GUI_SESSIONS_LOGGING',
        'SHOW_DISCORD_POPUP',
    })

    @staticmethod
    def _get_context(info: ValidationInfo) -> dict[str, Any] | None:
        context_obj = info.context
        if not isinstance(context_obj, dict):
            return None
        return cast('dict[str, Any]', context_obj)

    @classmethod
    def _get_default_for_field(cls, info: ValidationInfo) -> object:
        context = cls._get_context(info)
        if context is None:
            return None
        defaults_obj = context.get('defaults')
        if not isinstance(defaults_obj, dict):
            return None
        if not isinstance(info.field_name, str):
            return None
        return cast('dict[str, Any]', defaults_obj).get(info.field_name)

    @staticmethod
    def _record_rewrite(info: ValidationInfo, rewrite_to: str | None) -> None:
        if rewrite_to is None:
            return
        context_obj = info.context
        if not isinstance(context_obj, dict):
            return
        context = cast('dict[str, Any]', context_obj)
        ini_rewrites = context.setdefault('ini_rewrites', {})
        if isinstance(info.field_name, str) and isinstance(ini_rewrites, dict):
            cast('dict[str, str]', ini_rewrites)[info.field_name] = rewrite_to

    @staticmethod
    def _set_flag(info: ValidationInfo, flag_name: str, *, value: object) -> None:
        context_obj = info.context
        if not isinstance(context_obj, dict):
            return
        context = cast('dict[str, Any]', context_obj)
        flags = context.setdefault('flags', {})
        if isinstance(flags, dict):
            cast('dict[str, Any]', flags)[flag_name] = value

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
                default_value = cls._get_default_for_field(info)
                if isinstance(default_value, bool):
                    cls._set_flag(info, 'should_rewrite', value=True)
                    return default_value
                cls._set_flag(info, 'should_rewrite', value=True)
                return False
            if need_rewrite:
                cls._record_rewrite(info, str(resolved))
            return resolved
        default_value = cls._get_default_for_field(info)
        if isinstance(default_value, bool):
            cls._set_flag(info, 'should_rewrite', value=True)
            return default_value
        cls._set_flag(info, 'should_rewrite', value=True)
        return False

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

    @field_validator('CAPTURE_BLOCK_THIRD_PARTY_SERVERS', mode='before')
    @classmethod
    def _parse_block_servers(cls, value: object, info: ValidationInfo) -> tuple[str, ...]:
        context = cls._get_context(info)
        all_servers: tuple[str, ...] = ()
        if context is not None:
            servers_obj = context.get('all_third_party_servers')
            if isinstance(servers_obj, tuple):
                all_servers = cast('tuple[str, ...]', servers_obj)

        if isinstance(value, tuple):
            return cast('tuple[str, ...]', value)
        if isinstance(value, str):
            normalized, need_rewrite_current, need_rewrite_settings = _normalize_tuple_column(value, all_servers)
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
            except (ValueError, SyntaxError, RecursionError, MemoryError):
                cls._set_flag(info, 'should_rewrite', value=True)
                return ()
            if not isinstance(parsed, tuple):
                cls._set_flag(info, 'should_rewrite', value=True)
                return ()
            if not all(isinstance(item, str) for item in parsed):  # pyright: ignore[reportUnknownVariableType]
                cls._set_flag(info, 'should_rewrite', value=True)
                return ()
            valid_items: list[str] = []
            need_rewrite = False
            for item in cast('tuple[str, ...]', parsed):
                try:
                    parse_ip_range(item)
                    valid_items.append(item)
                except (ValueError, TypeError):
                    need_rewrite = True
            if need_rewrite:
                cls._set_flag(info, 'should_rewrite', value=True)
            return tuple(valid_items)
        cls._set_flag(info, 'should_rewrite', value=True)
        return ()

    @field_validator('CAPTURE_PROGRAM_PRESET', mode='before')
    @classmethod
    def _parse_program_preset(cls, value: object, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            try:
                none_value, need_rewrite = custom_str_to_nonetype(value)
            except InvalidNoneTypeValueError:
                try:
                    case_match, normalized = check_case_insensitive_and_exact_match(value, ('GTA5', 'Minecraft'))
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

    @field_validator('CAPTURE_OVERFLOW_TIMER', mode='before')
    @classmethod
    def _parse_overflow_timer(cls, value: object, info: ValidationInfo) -> int:
        if isinstance(value, (int, float)):
            return int(value) if value >= 1 else cast('int', cls._get_default_for_field(info) or 3)
        if isinstance(value, str):
            try:
                parsed = int(float(value))
            except (ValueError, TypeError):
                cls._set_flag(info, 'should_rewrite', value=True)
                return cast('int', cls._get_default_for_field(info) or 3)
            if parsed >= 1:
                return parsed
            cls._set_flag(info, 'should_rewrite', value=True)
            return cast('int', cls._get_default_for_field(info) or 3)
        cls._set_flag(info, 'should_rewrite', value=True)
        return cast('int', cls._get_default_for_field(info) or 3)

    @field_validator('CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER', 'CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER', mode='before')
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

    @field_validator('GUI_COLUMNS_CONNECTED_SHOWN', mode='before')
    @classmethod
    def _parse_connected_shown(cls, value: object, info: ValidationInfo) -> tuple[str, ...]:
        context = cls._get_context(info)
        allowed: tuple[str, ...] = ()
        if context is not None:
            obj = context.get('toggleable_connected_columns')
            if isinstance(obj, tuple):
                allowed = cast('tuple[str, ...]', obj)
        return cls._parse_shown_columns(value, allowed, info)

    @field_validator('GUI_COLUMNS_DISCONNECTED_SHOWN', mode='before')
    @classmethod
    def _parse_disconnected_shown(cls, value: object, info: ValidationInfo) -> tuple[str, ...]:
        context = cls._get_context(info)
        allowed: tuple[str, ...] = ()
        if context is not None:
            obj = context.get('toggleable_disconnected_columns')
            if isinstance(obj, tuple):
                allowed = cast('tuple[str, ...]', obj)
        return cls._parse_shown_columns(value, allowed, info)

    @field_validator('DISCORD_WEBHOOK_COLUMNS_CONNECTED', mode='before')
    @classmethod
    def _parse_webhook_columns_connected(cls, value: object, info: ValidationInfo) -> tuple[str, ...]:
        context = cls._get_context(info)
        allowed: tuple[str, ...] = ()
        if context is not None:
            obj = context.get('webhook_all_connected_columns')
            if isinstance(obj, tuple):
                allowed = cast('tuple[str, ...]', obj)
        return cls._parse_shown_columns(value, allowed, info)

    @field_validator('DISCORD_WEBHOOK_COLUMNS_DISCONNECTED', mode='before')
    @classmethod
    def _parse_webhook_columns_disconnected(cls, value: object, info: ValidationInfo) -> tuple[str, ...]:
        context = cls._get_context(info)
        allowed: tuple[str, ...] = ()
        if context is not None:
            obj = context.get('webhook_all_disconnected_columns')
            if isinstance(obj, tuple):
                allowed = cast('tuple[str, ...]', obj)
        return cls._parse_shown_columns(value, allowed, info)

    @classmethod
    def _parse_shown_columns(cls, value: object, allowed: tuple[str, ...], info: ValidationInfo) -> tuple[str, ...]:
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

    @field_validator('GUI_CONNECTED_TABLE_ROWS_PER_PAGE', 'GUI_DISCONNECTED_TABLE_ROWS_PER_PAGE', mode='before')
    @classmethod
    def _parse_rows_per_page(cls, value: object, info: ValidationInfo) -> int:
        max_rpp = 5000  # Settings.MAX_GUI_TABLE_ROWS_PER_PAGE
        context = cls._get_context(info)
        if context is not None:
            ctx_max = context.get('max_gui_table_rows_per_page')
            if isinstance(ctx_max, int):
                max_rpp = ctx_max

        if isinstance(value, int):
            if 0 <= value <= max_rpp:
                return value
            cls._set_flag(info, 'should_rewrite', value=True)
            default = cls._get_default_for_field(info)
            return default if isinstance(default, int) else 0
        if isinstance(value, str):
            try:
                parsed = int(float(value))
            except (ValueError, TypeError):
                cls._set_flag(info, 'should_rewrite', value=True)
                default = cls._get_default_for_field(info)
                return default if isinstance(default, int) else 0
            if 0 <= parsed <= max_rpp:
                return parsed
            cls._set_flag(info, 'should_rewrite', value=True)
            default = cls._get_default_for_field(info)
            return default if isinstance(default, int) else 0
        cls._set_flag(info, 'should_rewrite', value=True)
        default = cls._get_default_for_field(info)
        return default if isinstance(default, int) else 0

    @field_validator('GUI_RATE_GRAPH_MAX_HISTORY', mode='before')
    @classmethod
    def _parse_rate_graph_max_history(cls, value: object, info: ValidationInfo) -> int:
        min_val = 60
        max_val = 7200

        if isinstance(value, (int, float)):
            int_value = int(value)
            if min_val <= int_value <= max_val:
                return int_value
            cls._set_flag(info, 'should_rewrite', value=True)
            default = cls._get_default_for_field(info)
            return default if isinstance(default, int) else 3600
        if isinstance(value, str):
            try:
                parsed = int(float(value))
            except (ValueError, TypeError):
                cls._set_flag(info, 'should_rewrite', value=True)
                default = cls._get_default_for_field(info)
                return default if isinstance(default, int) else 3600
            if min_val <= parsed <= max_val:
                return parsed
            cls._set_flag(info, 'should_rewrite', value=True)
            default = cls._get_default_for_field(info)
            return default if isinstance(default, int) else 3600
        cls._set_flag(info, 'should_rewrite', value=True)
        default = cls._get_default_for_field(info)
        return default if isinstance(default, int) else 3600

    @field_validator('GUI_DISCONNECTED_PLAYERS_TIMER', mode='before')
    @classmethod
    def _parse_disconnected_timer(cls, value: object, info: ValidationInfo) -> int:
        min_timer = 3  # Settings.MIN_GUI_DISCONNECTED_PLAYERS_TIMER_SECONDS
        context = cls._get_context(info)
        if context is not None:
            ctx_min = context.get('min_gui_disconnected_players_timer')
            if isinstance(ctx_min, int):
                min_timer = ctx_min

        if isinstance(value, (int, float)):
            int_value = int(value)
            if int_value >= min_timer:
                return int_value
            cls._set_flag(info, 'should_rewrite', value=True)
            return cast('int', cls._get_default_for_field(info) or 10)
        if isinstance(value, str):
            try:
                parsed = int(float(value))
            except (ValueError, TypeError):
                cls._set_flag(info, 'should_rewrite', value=True)
                return cast('int', cls._get_default_for_field(info) or 10)
            if parsed >= min_timer:
                return parsed
            cls._set_flag(info, 'should_rewrite', value=True)
            return cast('int', cls._get_default_for_field(info) or 10)
        cls._set_flag(info, 'should_rewrite', value=True)
        return cast('int', cls._get_default_for_field(info) or 10)

    @field_validator('DISCORD_PRESENCE_TITLE', mode='before')
    @classmethod
    def _parse_discord_presence_title(cls, value: object, info: ValidationInfo) -> str:
        if isinstance(value, str) and len(value) == 1:
            cls._set_flag(info, 'should_rewrite', value=True)
            default_value = cls._get_default_for_field(info)
            return default_value if isinstance(default_value, str) else ''
        if isinstance(value, str):
            return value
        cls._set_flag(info, 'should_rewrite', value=True)
        default_value = cls._get_default_for_field(info)
        return default_value if isinstance(default_value, str) else ''

    @field_validator('DISCORD_WEBHOOK_URL', 'DISCORD_WEBHOOK_MESSAGE_IDS', mode='before')
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

    @field_validator('DISCORD_WEBHOOK_REFRESH_INTERVAL', mode='before')
    @classmethod
    def _parse_webhook_refresh_interval(cls, value: object, info: ValidationInfo) -> int:
        min_val = 5
        max_val = 300
        default = cls._get_default_for_field(info)
        default_int = default if isinstance(default, int) else 15

        parsed: int | None = None
        if isinstance(value, (int, float)):
            parsed = int(value)
        elif isinstance(value, str):
            try:
                parsed = int(float(value))
            except (ValueError, TypeError):
                parsed = None

        if parsed is None:
            cls._set_flag(info, 'should_rewrite', value=True)
            return default_int
        if parsed < min_val:
            cls._set_flag(info, 'should_rewrite', value=True)
            return min_val
        if parsed > max_val:
            cls._set_flag(info, 'should_rewrite', value=True)
            return max_val
        return parsed

    @field_validator('DISCORD_WEBHOOK_MAX_ROWS_PER_TABLE', mode='before')
    @classmethod
    def _parse_webhook_max_rows(cls, value: object, info: ValidationInfo) -> int:
        min_val = 1
        max_val = 100
        default = cls._get_default_for_field(info)
        default_int = default if isinstance(default, int) else 25

        parsed: int | None = None
        if isinstance(value, (int, float)):
            parsed = int(value)
        elif isinstance(value, str):
            try:
                parsed = int(float(value))
            except (ValueError, TypeError):
                parsed = None

        if parsed is None:
            cls._set_flag(info, 'should_rewrite', value=True)
            return default_int
        if parsed < min_val:
            cls._set_flag(info, 'should_rewrite', value=True)
            return min_val
        if parsed > max_val:
            cls._set_flag(info, 'should_rewrite', value=True)
            return max_val
        return parsed

    @field_validator('DISCORD_WEBHOOK_MAX_CONNECTED_PLAYERS', 'DISCORD_WEBHOOK_MAX_DISCONNECTED_PLAYERS', mode='before')
    @classmethod
    def _parse_webhook_max_players(cls, value: object, info: ValidationInfo) -> int:
        min_val = 0  # 0 = All (unlimited)
        max_val = 100
        default = cls._get_default_for_field(info)
        default_int = default if isinstance(default, int) else 0

        parsed: int | None = None
        if isinstance(value, (int, float)):
            parsed = int(value)
        elif isinstance(value, str):
            try:
                parsed = int(float(value))
            except (ValueError, TypeError):
                parsed = None

        if parsed is None:
            cls._set_flag(info, 'should_rewrite', value=True)
            return default_int
        if parsed < min_val:
            cls._set_flag(info, 'should_rewrite', value=True)
            return min_val
        if parsed > max_val:
            cls._set_flag(info, 'should_rewrite', value=True)
            return max_val
        return parsed

    @field_validator('DISCORD_WEBHOOK_FORMAT', mode='before')
    @classmethod
    def _parse_webhook_format(cls, value: object, info: ValidationInfo) -> str:
        if isinstance(value, str):
            try:
                case_match, normalized = check_case_insensitive_and_exact_match(value, ('Desktop', 'Mobile'))
            except NoMatchFoundError:
                cls._set_flag(info, 'should_rewrite', value=True)
                return cast('str', cls._get_default_for_field(info))
            if not case_match:
                cls._record_rewrite(info, normalized)
            return normalized
        cls._set_flag(info, 'should_rewrite', value=True)
        return cast('str', cls._get_default_for_field(info))

    @field_validator('UPDATER_CHANNEL', mode='before')
    @classmethod
    def _parse_updater_channel(cls, value: object, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            try:
                none_value, need_rewrite = custom_str_to_nonetype(value)
            except InvalidNoneTypeValueError:
                try:
                    case_match, normalized = check_case_insensitive_and_exact_match(value, ('Stable', 'RC'))
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

    @model_validator(mode='after')
    def _check_datetime_columns(self, info: ValidationInfo) -> Self:
        """Ensure at least one datetime column is enabled; reset all to defaults if not."""
        if (
            self.GUI_COLUMNS_DATETIME_SHOW_DATE is False
            and self.GUI_COLUMNS_DATETIME_SHOW_TIME is False
            and self.GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME is False
        ):
            self._set_flag(info, 'invalid_datetime_columns_corrected', value=True)
            self._set_flag(info, 'should_rewrite', value=True)
            context = self._get_context(info)
            if context is not None:
                defaults_obj = context.get('defaults')
                if isinstance(defaults_obj, dict):
                    defaults = cast('dict[str, Any]', defaults_obj)
                    show_date = defaults.get('GUI_COLUMNS_DATETIME_SHOW_DATE', False)
                    show_time = defaults.get('GUI_COLUMNS_DATETIME_SHOW_TIME', False)
                    show_elapsed = defaults.get('GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME', True)
                    self.GUI_COLUMNS_DATETIME_SHOW_DATE = show_date  # pyright: ignore[reportConstantRedefinition]  # pylint: disable=invalid-name
                    self.GUI_COLUMNS_DATETIME_SHOW_TIME = show_time  # pyright: ignore[reportConstantRedefinition]  # pylint: disable=invalid-name
                    self.GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME = show_elapsed  # pyright: ignore[reportConstantRedefinition]  # pylint: disable=invalid-name
        return self

    # --- Public API ---

    @classmethod
    def validate_and_get_rewrites(  # pylint: disable=too-many-arguments
        cls,
        raw_settings: dict[str, str],
        *,
        defaults: dict[str, Any],
        all_setting_names: tuple[str, ...],
        toggleable_connected_columns: tuple[str, ...],
        toggleable_disconnected_columns: tuple[str, ...],
        webhook_all_connected_columns: tuple[str, ...],
        webhook_all_disconnected_columns: tuple[str, ...],
        all_third_party_servers: tuple[str, ...],
        max_gui_table_rows_per_page: int,
        min_gui_disconnected_players_timer: int,
    ) -> tuple[Self, dict[str, str], dict[str, Any]]:
        """Validate raw Settings.ini key/value strings and compute a rewrite plan.

        Args:
            raw_settings: Parsed raw settings mapping from the INI file (UPPER_CASE keys).
            defaults: Default values for all settings (UPPER_CASE keys).
            all_setting_names: Tuple of known setting names (UPPER_CASE).
            toggleable_connected_columns: Allowed column names for connected shown columns.
            toggleable_disconnected_columns: Allowed column names for disconnected shown columns.
            webhook_all_connected_columns: Allowed column names for the connected webhook table.
            webhook_all_disconnected_columns: Allowed column names for the disconnected webhook table.
            all_third_party_servers: All third-party server names for block list.
            max_gui_table_rows_per_page: Maximum allowed rows per page.
            min_gui_disconnected_players_timer: Minimum allowed disconnected timer.

        Returns:
            (validated_model, ini_rewrites, flags)
        """
        all_names_set = frozenset(all_setting_names)
        raw_keys = set(raw_settings)

        ini_rewrites: dict[str, str] = {}
        flags: dict[str, Any] = {}

        # Build full input: defaults first, then overwrite with raw values from INI
        full_input: dict[str, Any] = dict(defaults)
        full_input.update(raw_settings)

        context: dict[str, Any] = {
            'ini_rewrites': ini_rewrites,
            'flags': flags,
            'defaults': dict(defaults),
            'toggleable_connected_columns': toggleable_connected_columns,
            'toggleable_disconnected_columns': toggleable_disconnected_columns,
            'webhook_all_connected_columns': webhook_all_connected_columns,
            'webhook_all_disconnected_columns': webhook_all_disconnected_columns,
            'all_third_party_servers': all_third_party_servers,
            'max_gui_table_rows_per_page': max_gui_table_rows_per_page,
            'min_gui_disconnected_players_timer': min_gui_disconnected_players_timer,
        }

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
    except (ValueError, SyntaxError, RecursionError, MemoryError):
        return None, False, True

    if not isinstance(parsed, tuple):
        return None, False, True

    if not all(isinstance(item, str) for item in parsed):  # pyright: ignore[reportUnknownVariableType]
        return None, False, True

    parsed = cast('tuple[str, ...]', parsed)

    filtered: list[str] = []
    need_rewrite_current = False
    need_rewrite_settings = False

    for value in parsed:
        try:
            case_match, normalized = check_case_insensitive_and_exact_match(value, allowed_columns)
        except NoMatchFoundError:
            need_rewrite_settings = True
            continue
        filtered.append(normalized)
        if not case_match:
            need_rewrite_current = True

    sorted_result = [col for col in allowed_columns if col in filtered]
    if filtered != sorted_result:
        need_rewrite_current = True

    return tuple(sorted_result), need_rewrite_current, need_rewrite_settings
