"""Pydantic model for combo detection rules."""

import logging
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

from session_sniffer.networking.ip_range import is_valid_ip_range_entry
from session_sniffer.text_utils import format_suspend_duration_setting, parse_suspend_duration_setting, parse_voice_notifications

logger = logging.getLogger(__name__)


class DetectionActionBase(BaseModel):
    """Shared action fields, validators, and serializers for detections and combo rules."""

    model_config = ConfigDict(extra='ignore')

    duration: int | Literal['Auto'] = 'Auto'
    voice_notifications: Literal['Male', 'Female'] | bool = False
    logging: bool = False
    message_box: bool = False

    @field_validator('duration', mode='before')
    @classmethod
    def _validate_duration(cls, value: object) -> int | Literal['Auto']:
        return parse_suspend_duration_setting(str(value) if value is not None else 'Auto')

    @field_validator('voice_notifications', mode='before')
    @classmethod
    def _validate_voice(cls, value: object) -> Literal['Male', 'Female'] | bool:
        return parse_voice_notifications(str(value) if value is not None else 'False')

    @field_serializer('duration')
    def _serialize_duration(self, duration: int | Literal['Auto']) -> str:
        return format_suspend_duration_setting(duration)

    @field_serializer('voice_notifications')
    def _serialize_voice(self, voice: object) -> str:
        return str(voice) if voice else 'False'


# Condition keys that accept a free-text string value
_STRING_CONDITIONS: frozenset[str] = frozenset({'country', 'city', 'region', 'org', 'isp', 'asn', 'as_name', 'ip_range'})
# Condition keys that are boolean flags
_BOOL_CONDITIONS: frozenset[str] = frozenset({'mobile', 'vpn', 'hosting'})
# The special event condition
EVENT_CONDITION: str = 'event'
_VALID_EVENTS: frozenset[str] = frozenset({'join', 'rejoin', 'leave'})

type ConditionValue = str | bool | list[str]


class ComboRule(DetectionActionBase):
    """A single combo detection rule with AND-combined conditions and per-rule action settings."""

    name: str = 'Unnamed Rule'
    enabled: bool = True
    conditions: dict[str, ConditionValue] = Field(default_factory=dict)

    # Action settings
    protection_enabled: bool = False

    @field_validator('conditions', mode='before')
    @classmethod
    def _validate_conditions(cls, value: object) -> dict[str, ConditionValue]:
        if not isinstance(value, dict):
            return {}

        conditions: dict[str, ConditionValue] = {}
        for key, raw_val in cast('dict[str, object]', value).items():
            if key in _STRING_CONDITIONS:
                if isinstance(raw_val, str) and raw_val.strip():
                    # Keep invalid IP ranges so the rule never matches instead of silently dropping the condition and broadening it.
                    if key == 'ip_range' and not is_valid_ip_range_entry(raw_val.strip()):
                        logger.warning('Invalid combo rule IP range %r: the rule will never match until it is fixed', raw_val.strip())
                    conditions[key] = raw_val.strip()
            elif key in _BOOL_CONDITIONS:
                if isinstance(raw_val, bool):
                    conditions[key] = raw_val
            elif key == EVENT_CONDITION and isinstance(raw_val, list):
                valid_events = [event for event in cast('list[object]', raw_val) if isinstance(event, str) and event in _VALID_EVENTS]
                if valid_events:
                    conditions[key] = valid_events
        if EVENT_CONDITION in conditions and len(conditions) == 1:
            msg = 'ComboRule with an event condition must include at least one IP-based condition'
            raise ValueError(msg)
        return conditions

    @property
    def has_event_condition(self) -> bool:
        """Return True if the rule has an event condition."""
        return EVENT_CONDITION in self.conditions

    def to_dict(self) -> dict[str, object]:
        """Serialize the rule to a JSON-compatible dictionary."""
        return cast('dict[str, object]', self.model_dump(mode='json'))
