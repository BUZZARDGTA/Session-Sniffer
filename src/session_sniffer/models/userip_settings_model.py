"""Pydantic models for UserIP JSON database settings and entries."""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator
from PySide6.QtGui import QColor

from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.text_utils import DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS
from session_sniffer.utils import check_case_insensitive_and_exact_match, custom_str_to_bool
from session_sniffer.utils_exceptions import InvalidBooleanValueError, NoMatchFoundError

type EntrySource = Literal['Manual', 'Session', 'Looky', 'Auto-IP', 'Import']

USERIP_SOURCE_VALUES: tuple[EntrySource, ...] = (
    'Manual',
    'Session',
    'Looky',
    'Auto-IP',
    'Import',
)

USERIP_SETTINGS_KEYS: tuple[str, ...] = (
    'ENABLED',
    'COLOR',
    'LOG',
    'NOTIFICATIONS',
    'VOICE_NOTIFICATIONS',
    'PROTECTION',
    'PROTECTION_SUSPEND_PROCESS_MODE',
)

USERIP_ENTRY_KEYS: tuple[str, ...] = (
    'username',
    'ip',
    'is_looky',
    'notes',
    'source',
    'detections_count',
    'added_at',
    'updated_at',
    'first_seen_at',
    'last_seen_at',
)


def get_current_iso_timestamp() -> str:
    """Return the current local timestamp formatted as an ISO-8601 string with timezone offset."""
    return datetime.now(tz=LOCAL_TZ).isoformat(timespec='seconds')


def normalize_iso_timestamp(value: object) -> tuple[str | None, bool]:
    """Validate and normalize an optional ISO-8601 timestamp value.

    Returns:
        A tuple of `(normalized_iso_or_none, is_canonical)`.
    """
    if value is None:
        return None, True
    if not isinstance(value, str):
        return None, False
    stripped = value.strip()
    if not stripped:
        return None, False
    try:
        parsed = datetime.fromisoformat(stripped)
    except ValueError:
        return None, False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=LOCAL_TZ)
    normalized = parsed.isoformat(timespec='seconds')
    return normalized, normalized == value


def format_iso_timestamp_display(iso_str: str | None) -> str:
    """Format an ISO-8601 timestamp string as `YYYY-MM-DD HH:MM:SS` in local time, or empty string if absent."""
    if iso_str is None or not iso_str:
        return ''
    try:
        parsed = datetime.fromisoformat(iso_str)
    except ValueError:
        return iso_str
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(LOCAL_TZ)
    return parsed.strftime('%Y-%m-%d %H:%M:%S')


def _parse_iso_for_compare(iso_str: str) -> datetime | None:
    """Parse an ISO-8601 string into a timezone-aware datetime for chronological comparison."""
    try:
        parsed = datetime.fromisoformat(iso_str)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=LOCAL_TZ)
    return parsed


def pick_earliest_iso(first: str | None, second: str | None) -> str | None:
    """Return the chronologically earlier of two optional ISO-8601 timestamps."""
    if first is None or not first:
        return second
    if second is None or not second:
        return first
    dt_first = _parse_iso_for_compare(first)
    dt_second = _parse_iso_for_compare(second)
    if dt_first is not None and dt_second is not None:
        return first if dt_first <= dt_second else second
    return min(first, second)


def pick_latest_iso(first: str | None, second: str | None) -> str | None:
    """Return the chronologically later of two optional ISO-8601 timestamps."""
    if first is None or not first:
        return second
    if second is None or not second:
        return first
    dt_first = _parse_iso_for_compare(first)
    dt_second = _parse_iso_for_compare(second)
    if dt_first is not None and dt_second is not None:
        return first if dt_first >= dt_second else second
    return max(first, second)


def normalize_userip_source(value: object, *, is_looky: bool = False) -> tuple[EntrySource, bool]:
    """Validate and normalize a raw UserIP entry source string.

    Returns:
        A tuple of `(normalized_source, is_canonical)`.
    """
    default_source: EntrySource = 'Looky' if is_looky else 'Manual'
    if not isinstance(value, str):
        return default_source, False
    stripped = value.strip()
    if not stripped:
        return default_source, False
    try:
        case_match, normalized = check_case_insensitive_and_exact_match(stripped, USERIP_SOURCE_VALUES)
    except NoMatchFoundError:
        return default_source, False
    resolved = cast('EntrySource', normalized)
    if is_looky and resolved == 'Manual':
        return 'Looky', False
    return resolved, case_match and stripped == value


@dataclass(slots=True)
class _UserIPSettingsContext:
    need_rewrite: bool = False


class UserIPSettingsModel(BaseModel):
    """Pydantic model for the `settings` object of a UserIP `.json` database file."""

    model_config = ConfigDict(extra='ignore')

    ENABLED: bool = True
    COLOR: str = ''
    LOG: bool = False
    NOTIFICATIONS: bool = False
    VOICE_NOTIFICATIONS: Literal['Male', 'Female', False] = False
    PROTECTION: bool = False
    PROTECTION_SUSPEND_PROCESS_MODE: int | Literal['Auto'] = 'Auto'

    _BOOL_DEFAULTS: ClassVar[dict[str, bool]] = {
        'ENABLED': True,
        'LOG': False,
        'NOTIFICATIONS': False,
        'PROTECTION': False,
    }

    @staticmethod
    def _mark_rewrite(info: ValidationInfo) -> None:
        if isinstance(info.context, _UserIPSettingsContext):
            info.context.need_rewrite = True

    @field_validator('ENABLED', 'LOG', 'NOTIFICATIONS', 'PROTECTION', mode='before')
    @classmethod
    def _normalize_bool(cls, value: object, info: ValidationInfo) -> bool:
        """Validate boolean settings and normalize string booleans."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            try:
                resolved, _ = custom_str_to_bool(value.strip())
            except InvalidBooleanValueError:
                cls._mark_rewrite(info)
                return cls._BOOL_DEFAULTS.get(info.field_name or '', False)
            cls._mark_rewrite(info)
            return resolved
        cls._mark_rewrite(info)
        return cls._BOOL_DEFAULTS.get(info.field_name or '', False)

    @field_validator('COLOR', mode='before')
    @classmethod
    def _normalize_color(cls, value: object, info: ValidationInfo) -> str:
        """Accept empty string or any valid QColor string (CSS name or #RRGGBB hex)."""
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                if stripped != value:
                    cls._mark_rewrite(info)
                return ''
            if QColor.isValidColorName(stripped):
                if stripped != value:
                    cls._mark_rewrite(info)
                return stripped
        cls._mark_rewrite(info)
        return 'WHITE'

    @field_validator('VOICE_NOTIFICATIONS', mode='before')
    @classmethod
    def _normalize_voice_notifications(cls, value: object, info: ValidationInfo) -> Literal['Male', 'Female', False]:
        """Accept False, 'Male', or 'Female' (case-insensitive); normalize 'True' to 'Male'."""
        if isinstance(value, bool):
            if value:
                cls._mark_rewrite(info)
                return 'Male'
            return False
        if isinstance(value, str):
            stripped = value.strip()
            try:
                resolved, _ = custom_str_to_bool(stripped)
            except InvalidBooleanValueError:
                try:
                    case_match, normalized = check_case_insensitive_and_exact_match(stripped, ('Male', 'Female'))
                except NoMatchFoundError:
                    pass
                else:
                    if not case_match or stripped != value:
                        cls._mark_rewrite(info)
                    return cast('Literal["Male", "Female"]', normalized)
            else:
                cls._mark_rewrite(info)
                return 'Male' if resolved else False
        cls._mark_rewrite(info)
        return False

    @field_validator('PROTECTION_SUSPEND_PROCESS_MODE', mode='before')
    @classmethod
    def _normalize_suspend_mode(cls, value: object, info: ValidationInfo) -> int | Literal['Auto']:
        """Accept 'Auto' (or False), 'Manual' (or True -> default duration), or a non-negative integer."""
        if isinstance(value, bool):
            cls._mark_rewrite(info)
            return DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS if value else 'Auto'
        if isinstance(value, (int, float)):
            int_val = int(value)
            if isinstance(value, float) or int_val < 0:
                cls._mark_rewrite(info)
            return int_val if int_val >= 0 else 'Auto'
        if isinstance(value, str):
            stripped = value.strip()
            try:
                resolved, _ = custom_str_to_bool(stripped)
            except InvalidBooleanValueError:
                pass
            else:
                cls._mark_rewrite(info)
                return DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS if resolved else 'Auto'

            try:
                case_match, normalized = check_case_insensitive_and_exact_match(stripped, ('Auto', 'Manual'))
            except NoMatchFoundError:
                pass
            else:
                if normalized == 'Manual' or not case_match or stripped != value:
                    cls._mark_rewrite(info)
                return DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS if normalized == 'Manual' else 'Auto'

            is_manual_parens = stripped.upper().startswith('MANUAL(') and stripped.endswith(')')
            try:
                parsed_int: int | None = int(float(stripped[7:-1] if is_manual_parens else stripped))
            except ValueError:
                parsed_int = DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS if is_manual_parens else None
            if parsed_int is not None:
                cls._mark_rewrite(info)
                return parsed_int if parsed_int >= 0 else 'Auto'

        cls._mark_rewrite(info)
        return 'Auto'

    @classmethod
    def validate_settings(cls, raw_settings: dict[str, Any]) -> tuple[Self, bool]:
        """Validate a raw settings dictionary and report whether the file needs rewriting."""
        ctx = _UserIPSettingsContext()
        normalized_input: dict[str, Any] = {}
        for raw_key, raw_val in raw_settings.items():
            upper_key = raw_key.strip().upper()
            if upper_key != raw_key or upper_key not in USERIP_SETTINGS_KEYS or upper_key in normalized_input:
                ctx.need_rewrite = True
            if upper_key in USERIP_SETTINGS_KEYS:
                normalized_input[upper_key] = raw_val

        if list(raw_settings.keys()) != list(USERIP_SETTINGS_KEYS):
            ctx.need_rewrite = True

        validated = cls.model_validate(normalized_input, context=ctx)
        return validated, ctx.need_rewrite


class UserIPEntryModel(BaseModel):
    """Pydantic model for a single entry in a UserIP `.json` database file."""

    model_config = ConfigDict(extra='forbid')

    username: str
    ip: str
    is_looky: bool = False
    notes: str = ''
    source: EntrySource = 'Manual'
    detections_count: int = Field(default=0, ge=0)
    added_at: str = Field(default_factory=get_current_iso_timestamp)
    updated_at: str | None = None
    first_seen_at: str | None = None
    last_seen_at: str | None = None

    @classmethod
    def from_raw_entry_dict(
        cls,
        entry_dict: dict[str, Any],
        *,
        username: str,
        ip: str,
        is_looky: bool,
        notes: str,
    ) -> tuple[Self, bool]:
        """Construct a `UserIPEntryModel` from a raw entry dictionary and report whether metadata was canonical."""
        raw_source: object = entry_dict.get('source', 'Looky' if is_looky else 'Manual')
        source, source_clean = normalize_userip_source(raw_source, is_looky=is_looky)

        raw_detections: object = entry_dict.get('detections_count', 0)
        detections_clean = isinstance(raw_detections, int) and not isinstance(raw_detections, bool) and raw_detections >= 0
        if isinstance(raw_detections, bool):
            detections_count = 0
        elif isinstance(raw_detections, (int, float)):
            detections_count = max(0, int(raw_detections))
        elif isinstance(raw_detections, str) and raw_detections.strip().isdigit():
            detections_count = int(raw_detections.strip())
        else:
            detections_count = 0

        added_at_norm, added_clean = normalize_iso_timestamp(entry_dict.get('added_at'))
        added_at = added_at_norm if added_at_norm is not None else get_current_iso_timestamp()
        updated_at, updated_clean = normalize_iso_timestamp(entry_dict.get('updated_at'))
        first_seen_at, first_seen_clean = normalize_iso_timestamp(entry_dict.get('first_seen_at'))
        last_seen_at, last_seen_clean = normalize_iso_timestamp(entry_dict.get('last_seen_at'))
        earliest_seen = pick_earliest_iso(first_seen_at, last_seen_at)
        clamped_added_at = pick_earliest_iso(added_at, earliest_seen) or added_at
        if clamped_added_at != added_at:
            added_at = clamped_added_at
            added_clean = False

        keys_clean = list(entry_dict.keys()) == list(USERIP_ENTRY_KEYS)
        is_canonical = keys_clean and source_clean and detections_clean and added_clean and updated_clean and first_seen_clean and last_seen_clean
        entry = cls(
            username=username, ip=ip, is_looky=is_looky, notes=notes, source=source,
            detections_count=detections_count, added_at=added_at, updated_at=updated_at, first_seen_at=first_seen_at, last_seen_at=last_seen_at,
        )
        return entry, is_canonical

    def merge_duplicate(self, other: Self) -> Self:
        """Merge metadata and timestamps from a duplicate `(username, ip)` entry into this entry."""
        self_start = _parse_iso_for_compare(self.first_seen_at or self.last_seen_at or '')
        self_end = _parse_iso_for_compare(self.last_seen_at or self.first_seen_at or '')
        other_start = _parse_iso_for_compare(other.first_seen_at or other.last_seen_at or '')
        other_end = _parse_iso_for_compare(other.last_seen_at or other.first_seen_at or '')
        disjoint_windows = (
            self_start is not None
            and self_end is not None
            and other_start is not None
            and other_end is not None
            and (self_end < other_start or other_end < self_start)
        )
        merged_detections = (
            self.detections_count + other.detections_count
            if disjoint_windows
            else max(self.detections_count, other.detections_count)
        )
        merged_is_looky = self.is_looky or other.is_looky
        merged_source: EntrySource = 'Looky' if merged_is_looky else self.source
        first_seen_at = pick_earliest_iso(self.first_seen_at, other.first_seen_at)
        last_seen_at = pick_latest_iso(self.last_seen_at, other.last_seen_at)
        earliest_seen = pick_earliest_iso(first_seen_at, last_seen_at)
        added_at = pick_earliest_iso(pick_earliest_iso(self.added_at, other.added_at), earliest_seen) or self.added_at
        return self.model_copy(
            update={
                'is_looky': merged_is_looky,
                'source': merged_source,
                'notes': self.notes or other.notes,
                'detections_count': merged_detections,
                'added_at': added_at,
                'updated_at': pick_latest_iso(self.updated_at, other.updated_at),
                'first_seen_at': first_seen_at,
                'last_seen_at': last_seen_at,
            },
        )


class UserIPDatabaseFile(BaseModel):
    """Pydantic model representing an entire UserIP `.json` database file."""

    model_config = ConfigDict(extra='forbid')

    settings: UserIPSettingsModel = Field(default_factory=UserIPSettingsModel)
    entries: list[UserIPEntryModel] = Field(default_factory=list[UserIPEntryModel])

    def serialize_to_json(self) -> str:
        """Serialize this UserIP database file to a formatted JSON string with trailing newline."""
        return json.dumps(self.model_dump(), indent=4, ensure_ascii=False) + '\n'


DEFAULT_USERIP_FILES_SETTINGS: dict[str, UserIPSettingsModel] = {
    'Blacklist.json': UserIPSettingsModel(
        ENABLED=True,
        COLOR='RED',
        LOG=True,
        NOTIFICATIONS=True,
        VOICE_NOTIFICATIONS='Male',
        PROTECTION=False,
        PROTECTION_SUSPEND_PROCESS_MODE='Auto',
    ),
    'Enemylist.json': UserIPSettingsModel(
        ENABLED=True,
        COLOR='DARKGOLDENROD',
        LOG=True,
        NOTIFICATIONS=True,
        VOICE_NOTIFICATIONS='Male',
        PROTECTION=False,
        PROTECTION_SUSPEND_PROCESS_MODE='Auto',
    ),
    'Friendlist.json': UserIPSettingsModel(
        ENABLED=True,
        COLOR='DARKGREEN',
        LOG=True,
        NOTIFICATIONS=False,
        VOICE_NOTIFICATIONS='Female',
        PROTECTION=False,
        PROTECTION_SUSPEND_PROCESS_MODE='Auto',
    ),
    'Randomlist.json': UserIPSettingsModel(
        ENABLED=True,
        COLOR='BLACK',
        LOG=True,
        NOTIFICATIONS=False,
        VOICE_NOTIFICATIONS='Female',
        PROTECTION=False,
        PROTECTION_SUSPEND_PROCESS_MODE='Auto',
    ),
    'Searchlist.json': UserIPSettingsModel(
        ENABLED=True,
        COLOR='BLUE',
        LOG=True,
        NOTIFICATIONS=False,
        VOICE_NOTIFICATIONS='Female',
        PROTECTION=False,
        PROTECTION_SUSPEND_PROCESS_MODE='Auto',
    ),
}
