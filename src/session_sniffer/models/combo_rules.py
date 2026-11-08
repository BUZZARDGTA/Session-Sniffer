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


# Prefix used on condition keys to represent the 'Is Not' (negated) operator
NEGATED_PREFIX: str = '!'
# Condition keys that accept a free-text string value (and support 'Is' / 'Is Not')
NEGATABLE_CONDITIONS: frozenset[str] = frozenset({'continent', 'country', 'city', 'region', 'org', 'isp', 'asn', 'as_name', 'ip_range'})
# Subset of negatable conditions (substring / range matchers) where having both 'Is' and 'Is Not' in the same AND rule is meaningful
DUAL_OPERATOR_CONDITIONS: frozenset[str] = frozenset({'org', 'isp', 'as_name', 'ip_range'})
# Condition keys that accept either a string or a list of strings
_MULTI_STRING_CONDITIONS: frozenset[str] = frozenset({'continent', 'country'})
# Condition keys that are boolean flags
_BOOL_CONDITIONS: frozenset[str] = frozenset({'mobile', 'vpn', 'hosting'})
# The special event condition
EVENT_CONDITION: str = 'event'
_VALID_EVENTS: frozenset[str] = frozenset({'join', 'rejoin', 'leave'})

type ConditionValue = str | bool | list[str]


def split_condition_key(key: str) -> tuple[str, bool]:
    """Return `(base_key, is_negated)` for a combo rule condition key."""
    if key.startswith(NEGATED_PREFIX):
        return key[len(NEGATED_PREFIX) :], True
    return key, False


def format_combo_conditions_summary(conditions: dict[str, ConditionValue], *, include_event: bool = True) -> str:
    """Format a combo rule's conditions dictionary into a human-readable summary string."""
    parts: list[str] = []
    for key, value in conditions.items():
        if not include_event and key == EVENT_CONDITION:
            continue
        base_key, is_negated = split_condition_key(key)
        operator = '!=' if is_negated else '='
        formatted_value = ' | '.join(value) if isinstance(value, list) else value
        parts.append(f'{base_key}{operator}{formatted_value}')
    return ', '.join(parts)


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
        seen_effective_keys: set[str] = set()
        seen_single_base_keys: set[str] = set()
        for key, raw_val in cast('dict[str, object]', value).items():
            base_key, is_negated = split_condition_key(key)
            if is_negated and base_key not in NEGATABLE_CONDITIONS:
                continue
            effective_key = f'{NEGATED_PREFIX}{base_key}' if is_negated else base_key
            if effective_key in seen_effective_keys or (base_key not in DUAL_OPERATOR_CONDITIONS and base_key in seen_single_base_keys):
                continue
            if base_key in _MULTI_STRING_CONDITIONS and isinstance(raw_val, list):
                valid_items = [item.strip() for item in cast('list[object]', raw_val) if isinstance(item, str) and item.strip()]
                if valid_items:
                    conditions[effective_key] = valid_items if len(valid_items) > 1 else valid_items[0]
                    seen_effective_keys.add(effective_key)
                    seen_single_base_keys.add(base_key)
            elif base_key in NEGATABLE_CONDITIONS:
                if isinstance(raw_val, str) and raw_val.strip():
                    # Keep invalid IP ranges so the rule never matches instead of silently dropping the condition and broadening it.
                    if base_key == 'ip_range' and not is_valid_ip_range_entry(raw_val.strip()):
                        logger.warning('Invalid combo rule IP range %r: the rule will never match until it is fixed', raw_val.strip())
                    conditions[effective_key] = raw_val.strip()
                    seen_effective_keys.add(effective_key)
                    seen_single_base_keys.add(base_key)
            elif base_key in _BOOL_CONDITIONS:
                if isinstance(raw_val, bool):
                    conditions[effective_key] = raw_val
                    seen_effective_keys.add(effective_key)
                    seen_single_base_keys.add(base_key)
            elif base_key == EVENT_CONDITION and isinstance(raw_val, list):
                valid_events = [event for event in cast('list[object]', raw_val) if isinstance(event, str) and event in _VALID_EVENTS]
                if valid_events:
                    conditions[effective_key] = valid_events
                    seen_effective_keys.add(effective_key)
                    seen_single_base_keys.add(base_key)
        if EVENT_CONDITION in conditions and len(conditions) == 1:
            msg = 'ComboRule with an event condition must include at least one IP-based condition'
            raise ValueError(msg)
        return conditions

    @property
    def has_event_condition(self) -> bool:
        """Return True if the rule has an event condition."""
        return EVENT_CONDITION in self.conditions
