"""Pydantic model for UserIP INI [Settings] section validation.

Replaces the per-field if/elif chain in parse_userip_ini_file().
Validates raw string values from the INI parser and normalizes them
into their runtime Python types. Corruption in any field raises
a `ValidationError` that the caller translates into a user notification.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Self, cast

from pydantic import BaseModel, ConfigDict, ValidationInfo, field_validator
from PyQt6.QtGui import QColor

from session_sniffer.text_utils import parse_duration_setting
from session_sniffer.utils import check_case_insensitive_and_exact_match, custom_str_to_bool, custom_str_to_nonetype
from session_sniffer.utils_exceptions import InvalidBooleanValueError, InvalidNoneTypeValueError, NoMatchFoundError


@dataclass(slots=True)
class _UserIPValidatorContext:
    ini_rewrites: dict[str, str] = field(default_factory=dict[str, str])

    def record_rewrite(self, field_name: str, rewrite_value: str) -> None:
        """Record a field rewrite by name and its corrected string value."""
        self.ini_rewrites[field_name] = rewrite_value


class UserIPSettingsModel(BaseModel):
    """Pydantic model for a single UserIP database's [Settings] section."""

    model_config = ConfigDict(extra='forbid', strict=True, arbitrary_types_allowed=True)

    ENABLED: bool
    COLOR: QColor
    LOG: bool
    NOTIFICATIONS: bool
    VOICE_NOTIFICATIONS: Literal['Male', 'Female', False]
    PROTECTION: Literal['Suspend_Process', False]
    PROTECTION_PROCESS_PATH: Path | None
    PROTECTION_SUSPEND_PROCESS_MODE: int | Literal['Auto', 'Adaptive']

    @staticmethod
    def _record_rewrite(info: ValidationInfo, field_name: str, rewrite_value: str) -> None:
        context_obj = info.context
        if isinstance(context_obj, _UserIPValidatorContext):
            context_obj.record_rewrite(field_name, rewrite_value)

    @field_validator('ENABLED', 'LOG', 'NOTIFICATIONS', mode='before')
    @classmethod
    def _parse_bool(cls, value: object, info: ValidationInfo) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            resolved, need_rewrite = custom_str_to_bool(value)
            if need_rewrite and isinstance(info.field_name, str):
                cls._record_rewrite(info, info.field_name, str(resolved))
            return resolved
        msg = f'expected bool-like string, got {type(value).__name__}'
        raise ValueError(msg)

    @field_validator('COLOR', mode='before')
    @classmethod
    def _parse_color(cls, value: object) -> QColor:
        if isinstance(value, QColor):
            return value
        if isinstance(value, str):
            q_color = QColor(value)
            if q_color.isValid():
                return q_color
            msg = f'invalid color: {value!r}'
            raise ValueError(msg)
        msg = f'expected color string, got {type(value).__name__}'
        raise ValueError(msg)

    @field_validator('VOICE_NOTIFICATIONS', mode='before')
    @classmethod
    def _parse_voice_notifications(cls, value: object, info: ValidationInfo) -> Literal['Male', 'Female', False]:
        if isinstance(value, bool):
            if value is False:
                return value
            msg = f'expected voice notification value, got {type(value).__name__}'
            raise ValueError(msg)
        if isinstance(value, str):
            try:
                resolved, need_rewrite = custom_str_to_bool(value, only_match_against=False)
            except InvalidBooleanValueError:
                try:
                    case_match, normalized = check_case_insensitive_and_exact_match(value, ('Male', 'Female'))
                except NoMatchFoundError:
                    msg = f'invalid voice notification: {value!r}'
                    raise ValueError(msg) from None
                if not case_match and isinstance(info.field_name, str):
                    cls._record_rewrite(info, info.field_name, normalized)
                return cast("Literal['Male', 'Female']", normalized)
            if need_rewrite and isinstance(info.field_name, str):
                cls._record_rewrite(info, info.field_name, str(resolved))
            if resolved is False:
                return resolved
            msg = f'expected voice notification value, got {type(value).__name__}'
            raise ValueError(msg)
        msg = f'expected voice notification value, got {type(value).__name__}'
        raise ValueError(msg)

    @field_validator('PROTECTION', mode='before')
    @classmethod
    def _parse_protection(cls, value: object, info: ValidationInfo) -> Literal['Suspend_Process', False]:
        if isinstance(value, bool):
            if value is False:
                return value
            msg = f'expected protection value, got {type(value).__name__}'
            raise ValueError(msg)
        if isinstance(value, str):
            try:
                resolved, need_rewrite = custom_str_to_bool(value, only_match_against=False)
            except InvalidBooleanValueError:
                try:
                    case_match, normalized = check_case_insensitive_and_exact_match(
                        value, ('Suspend_Process',),
                    )
                except NoMatchFoundError:
                    msg = f'invalid protection mode: {value!r}'
                    raise ValueError(msg) from None
                if not case_match and isinstance(info.field_name, str):
                    cls._record_rewrite(info, info.field_name, normalized)
                return cast("Literal['Suspend_Process']", normalized)
            if need_rewrite and isinstance(info.field_name, str):
                cls._record_rewrite(info, info.field_name, str(resolved))
            if resolved is False:
                return resolved
            msg = f'expected protection value, got {type(value).__name__}'
            raise ValueError(msg)
        msg = f'expected protection value, got {type(value).__name__}'
        raise ValueError(msg)

    @field_validator('PROTECTION_PROCESS_PATH', mode='before')
    @classmethod
    def _parse_path(cls, value: object, info: ValidationInfo) -> Path | None:
        if value is None:
            return None
        if isinstance(value, Path):
            return value
        if isinstance(value, str):
            try:
                none_value, need_rewrite = custom_str_to_nonetype(value)
            except InvalidNoneTypeValueError:
                stripped = value.strip("\"'")
                if value != stripped:
                    msg = f'path has extraneous quotes: {value!r}'
                    raise ValueError(msg) from None
                return Path(stripped)
            if need_rewrite and isinstance(info.field_name, str):
                cls._record_rewrite(info, info.field_name, 'None')
            return none_value
        msg = f'expected path string, got {type(value).__name__}'
        raise ValueError(msg)

    @field_validator('PROTECTION_SUSPEND_PROCESS_MODE', mode='before')
    @classmethod
    def _parse_suspend_mode(cls, value: object) -> int | Literal['Auto', 'Adaptive']:
        """Parse suspend mode values, preserving readable fixed-duration manual values."""
        if isinstance(value, int):
            if value >= 0:
                return value
            msg = f'suspend process mode must be >= 0, got {value}'
            raise ValueError(msg)
        if isinstance(value, str):
            parsed = parse_duration_setting(value)
            if isinstance(parsed, int) or parsed in ('Auto', 'Adaptive'):
                return parsed
            msg = f'invalid suspend process mode: {value!r}'
            raise ValueError(msg)
        msg = f'expected suspend mode value, got {type(value).__name__}'
        raise ValueError(msg)

    @classmethod
    def validate_settings(cls, raw_settings: dict[str, str]) -> tuple[Self, dict[str, str]]:
        """Validate raw UserIP [Settings] key/value strings.

        Args:
            raw_settings: Mapping of setting names to raw string values.

        Returns:
            (validated_model, ini_rewrites) where ini_rewrites maps field names
            to their corrected string representations.

        Raises:
            pydantic.ValidationError: If any setting value is corrupted.
        """
        ctx = _UserIPValidatorContext()
        validated = cls.model_validate(raw_settings, context=ctx)
        return validated, dict(ctx.ini_rewrites)
