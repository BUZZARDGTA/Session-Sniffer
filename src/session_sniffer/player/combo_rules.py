"""Combo protection rules — multi-condition AND rules with per-rule actions."""

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Literal, cast

from session_sniffer.logging_setup import get_logger
from session_sniffer.models.player import Player
from session_sniffer.text_utils import format_duration_setting, parse_duration_setting, parse_voice_notifications

logger = get_logger(__name__)

# Condition keys that accept a free-text string value
_STRING_CONDITIONS: frozenset[str] = frozenset({'country', 'city', 'region', 'org', 'isp', 'asn', 'as_name'})
# Condition keys that are boolean flags
_BOOL_CONDITIONS: frozenset[str] = frozenset({'mobile', 'vpn', 'hosting'})
# The special event condition
_EVENT_CONDITION: str = 'event'
_VALID_EVENTS: frozenset[str] = frozenset({'join', 'rejoin', 'leave'})

ALL_CONDITION_KEYS: frozenset[str] = _STRING_CONDITIONS | _BOOL_CONDITIONS | {_EVENT_CONDITION}

type ConditionValue = str | bool | list[str]
type ConditionMatcher = Callable[[ConditionValue, Player], bool]


@dataclass(kw_only=True, slots=True)
class ComboRule:
    """A single combo protection rule with AND-combined conditions and per-rule action settings."""

    name: str
    enabled: bool = True
    conditions: dict[str, ConditionValue] = field(default_factory=dict[str, ConditionValue])

    # Action settings
    protection_enabled: bool = False
    process_path: Path | None = None
    duration: int | Literal['Auto'] = 'Auto'
    voice_notifications: Literal['Male', 'Female'] | bool = False
    logging: bool = False
    message_box: bool = False

    @property
    def has_event_condition(self) -> bool:
        """Return True if the rule has an event condition."""
        return _EVENT_CONDITION in self.conditions

    @property
    def has_ip_condition(self) -> bool:
        """Return True if the rule has at least one IP-based condition."""
        return bool(self.conditions.keys() - {_EVENT_CONDITION})

    def to_dict(self) -> dict[str, object]:
        """Serialize the rule to a JSON-compatible dictionary."""
        return {
            'name': self.name,
            'enabled': self.enabled,
            'conditions': self.conditions,
            'protection_enabled': self.protection_enabled,
            'process_path': str(self.process_path) if self.process_path else '',
            'duration': format_duration_setting(self.duration),
            'voice_notifications': str(self.voice_notifications) if self.voice_notifications else 'False',
            'logging': self.logging,
            'message_box': self.message_box,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> ComboRule:
        """Deserialize a rule from a JSON-compatible dictionary."""
        conditions_raw = data.get('conditions', {})
        if not isinstance(conditions_raw, dict):
            conditions_raw = {}

        conditions: dict[str, ConditionValue] = {}

        for key, value in cast('dict[str, object]', conditions_raw).items():
            if key in _STRING_CONDITIONS:
                if isinstance(value, str) and value.strip():
                    conditions[key] = value.strip()

            elif key in _BOOL_CONDITIONS:
                if isinstance(value, bool):
                    conditions[key] = value

            elif key == _EVENT_CONDITION and isinstance(value, list):
                valid_events = [
                    event
                    for event in cast('list[object]', value)
                    if isinstance(event, str) and event in _VALID_EVENTS
                ]
                if valid_events:
                    conditions[key] = valid_events

        path_raw = data.get('process_path', '')
        path_str = path_raw.strip() if isinstance(path_raw, str) else ''

        return cls(
            name=str(data.get('name', 'Unnamed Rule')),
            enabled=bool(data.get('enabled', True)),
            conditions=conditions,
            protection_enabled=bool(data.get('protection_enabled', False)),
            process_path=Path(path_str) if path_str else None,
            duration=parse_duration_setting(str(data.get('duration', 'Auto'))),
            voice_notifications=parse_voice_notifications(str(data.get('voice_notifications', 'False'))),
            logging=bool(data.get('logging', False)),
            message_box=bool(data.get('message_box', False)),
        )


def _valid_lookup_value(value: object) -> bool:
    """Return True if an IP lookup value is meaningful."""
    return isinstance(value, str) and value not in ('', '...', 'N/A')


def _match_exact_lookup(value: str, *candidates: object) -> bool:
    """Return True if any meaningful lookup candidate exactly matches value."""
    return any(
        _valid_lookup_value(candidate) and candidate == value
        for candidate in candidates
    )


def _match_isp_condition(value: str, player: Player) -> bool:
    """Match ISP condition using the same logic as the existing ISP blocklist."""
    value_upper = value.upper().strip()

    if player.iplookup.ipapi.as_name and player.iplookup.ipapi.as_name not in ('...', 'N/A'):
        as_name_clean = player.iplookup.ipapi.as_name.upper().replace('AS', '', 1).strip()
        if as_name_clean and value_upper in as_name_clean:
            return True

    return bool(player.iplookup.ipapi.isp and player.iplookup.ipapi.isp not in ('...', 'N/A') and value_upper in player.iplookup.ipapi.isp.upper())


def _match_asn_condition(value: str, player: Player) -> bool:
    """Match ASN condition using normalized exact match."""
    value_upper = value.upper().strip()
    normalized = value_upper if value_upper.startswith('AS') else f'AS{value_upper}'

    if player.iplookup.ipapi.asn and player.iplookup.ipapi.asn not in ('...', 'N/A') and player.iplookup.ipapi.asn.upper() == normalized:
        return True

    return bool(player.iplookup.geolite2.asn and player.iplookup.geolite2.asn not in ('...', 'N/A') and player.iplookup.geolite2.asn.upper() == normalized)


def _match_as_name_condition(value: str, player: Player) -> bool:
    """Match AS Name condition using substring match."""
    return bool(player.iplookup.ipapi.as_name and player.iplookup.ipapi.as_name not in ('...', 'N/A') and value.upper().strip() in player.iplookup.ipapi.as_name.upper())


def _match_country_condition(value: ConditionValue, player: Player) -> bool:
    """Match country condition against GeoLite2 and ip-api country values."""
    return isinstance(value, str) and _match_exact_lookup(
        value,
        player.iplookup.geolite2.country,
        player.iplookup.ipapi.country,
    )


def _match_city_condition(value: ConditionValue, player: Player) -> bool:
    """Match city condition against GeoLite2 and ip-api city values."""
    return isinstance(value, str) and _match_exact_lookup(
        value,
        player.iplookup.geolite2.city,
        player.iplookup.ipapi.city,
    )


def _match_region_condition(value: ConditionValue, player: Player) -> bool:
    """Match region condition against ip-api region value."""
    return isinstance(value, str) and _match_exact_lookup(
        value,
        player.iplookup.ipapi.region,
    )


def _match_org_condition(value: ConditionValue, player: Player) -> bool:
    """Match organization condition using substring match."""
    return isinstance(value, str) and _valid_lookup_value(player.iplookup.ipapi.org) and value.upper() in player.iplookup.ipapi.org.upper()


def _match_isp_condition_wrapper(value: ConditionValue, player: Player) -> bool:
    """Match ISP condition after narrowing the condition value."""
    return isinstance(value, str) and _match_isp_condition(value, player)


def _match_asn_condition_wrapper(value: ConditionValue, player: Player) -> bool:
    """Match ASN condition after narrowing the condition value."""
    return isinstance(value, str) and _match_asn_condition(value, player)


def _match_as_name_condition_wrapper(value: ConditionValue, player: Player) -> bool:
    """Match AS name condition after narrowing the condition value."""
    return isinstance(value, str) and _match_as_name_condition(value, player)


def _match_mobile_condition(value: ConditionValue, player: Player) -> bool:
    """Match mobile flag condition."""
    return isinstance(value, bool) and isinstance(player.iplookup.ipapi.mobile, bool) and player.iplookup.ipapi.mobile == value


def _match_vpn_condition(value: ConditionValue, player: Player) -> bool:
    """Match VPN/proxy flag condition."""
    return isinstance(value, bool) and isinstance(player.iplookup.ipapi.proxy, bool) and player.iplookup.ipapi.proxy == value


def _match_hosting_condition(value: ConditionValue, player: Player) -> bool:
    """Match hosting/datacenter flag condition."""
    return isinstance(value, bool) and isinstance(player.iplookup.ipapi.hosting, bool) and player.iplookup.ipapi.hosting == value


_CONDITION_MATCHERS: dict[str, ConditionMatcher] = {
    'country': _match_country_condition,
    'city': _match_city_condition,
    'region': _match_region_condition,
    'org': _match_org_condition,
    'isp': _match_isp_condition_wrapper,
    'asn': _match_asn_condition_wrapper,
    'as_name': _match_as_name_condition_wrapper,
    'mobile': _match_mobile_condition,
    'vpn': _match_vpn_condition,
    'hosting': _match_hosting_condition,
}


def _check_condition(
    key: str,
    value: ConditionValue,
    player: Player,
) -> bool:
    """Check whether a single non-event condition matches the player."""
    matcher = _CONDITION_MATCHERS.get(key)
    return matcher(value, player) if matcher is not None else False


def _evaluate_rule(rule: ComboRule, player: Player, event_type: str | None) -> bool:
    """Check if all conditions in a rule match the given player and event.

    Rules without an event condition fire only when event_type is None.
    Rules with an event condition fire only when event_type matches one of the listed events.
    """
    if not rule.enabled or not rule.conditions:
        return False

    event_cond = rule.conditions.get(_EVENT_CONDITION)

    if event_cond is not None:
        if event_type is None:
            return False
        if not isinstance(event_cond, list) or event_type not in event_cond:
            return False
    elif event_type is not None:
        return False

    return all(
        _check_condition(key, value, player)
        for key, value in rule.conditions.items()
        if key != _EVENT_CONDITION
    )


@dataclass(kw_only=True, slots=True)
class ComboRulesManager:
    """Singleton manager for combo protection rules."""

    rules: ClassVar[list[ComboRule]] = []

    @classmethod
    def load_from_file(cls, file_path: Path) -> None:
        """Load combo rules from a JSON file. Starts with empty rules if file is missing or invalid."""
        cls.rules = []

        if not file_path.exists():
            return

        try:
            data: object = json.loads(file_path.read_text(encoding='utf-8'))
        except (json.JSONDecodeError, OSError):
            logger.warning('Failed to load combo rules from %s, starting with empty rules', file_path)
            return

        if not isinstance(data, list):
            return

        for entry in cast('list[object]', data):
            if isinstance(entry, dict):
                cls.rules.append(ComboRule.from_dict(cast('dict[str, object]', entry)))

    @classmethod
    def save_to_file(cls, file_path: Path) -> None:
        """Save all combo rules to a JSON file."""
        file_path.parent.mkdir(parents=True, exist_ok=True)

        data = [rule.to_dict() for rule in cls.rules]
        tmp_path = file_path.with_suffix('.tmp')
        tmp_path.write_text(json.dumps(data, indent=4), encoding='utf-8')
        tmp_path.replace(file_path)

    @classmethod
    def evaluate(cls, player: Player, event_type: str | None = None) -> list[ComboRule]:
        """Return all enabled combo rules whose conditions match the given player and event."""
        return [rule for rule in cls.rules if _evaluate_rule(rule, player, event_type)]

    @classmethod
    def export_rules(cls) -> list[dict[str, object]]:
        """Export rules as a list of dicts for inclusion in protection settings export."""
        return [rule.to_dict() for rule in cls.rules]

    @classmethod
    def import_rules(cls, rules_data: list[object]) -> None:
        """Import rules from a list of dicts from protection settings import."""
        cls.rules = []

        for entry in rules_data:
            if isinstance(entry, dict):
                cls.rules.append(ComboRule.from_dict(cast('dict[str, object]', entry)))
