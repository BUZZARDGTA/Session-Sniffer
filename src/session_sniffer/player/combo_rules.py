"""Combo protection rules — multi-condition AND rules with per-rule actions."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Literal, cast

from session_sniffer.logging_setup import get_logger
from session_sniffer.text_utils import parse_voice_notifications

if TYPE_CHECKING:
    from session_sniffer.models.player import Player

logger = get_logger(__name__)

# Condition keys that accept a free-text string value
_STRING_CONDITIONS: frozenset[str] = frozenset({'country', 'city', 'region', 'org', 'isp', 'asn', 'as_name'})
# Condition keys that are boolean flags (presence means "must be True")
_BOOL_CONDITIONS: frozenset[str] = frozenset({'mobile', 'vpn', 'hosting'})
# The special event condition (list of event strings)
_EVENT_CONDITION: str = 'event'
_VALID_EVENTS: frozenset[str] = frozenset({'join', 'rejoin', 'leave'})

ALL_CONDITION_KEYS: frozenset[str] = _STRING_CONDITIONS | _BOOL_CONDITIONS | {_EVENT_CONDITION}


def _parse_duration(raw: str) -> int | Literal['Auto', 'Manual', 'Adaptive']:
    try:
        return int(raw)
    except ValueError:
        if raw == 'Manual':
            return 'Manual'
        if raw == 'Adaptive':
            return 'Adaptive'
        return 'Auto'


@dataclass(kw_only=True, slots=True)
class ComboRule:
    """A single combo protection rule with AND-combined conditions and per-rule action settings."""

    name: str
    enabled: bool = True
    conditions: dict[str, str | bool | list[str]] = field(default_factory=dict)  # pyright: ignore[reportUnknownVariableType]

    # Action settings (same types as existing protections)
    protection_enabled: bool = False
    process_path: Path | None = None
    duration: int | Literal['Auto', 'Manual', 'Adaptive'] = 'Auto'
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
            'duration': str(self.duration),
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

        # Validate and normalize conditions
        conditions: dict[str, str | bool | list[str]] = {}
        for key, value in conditions_raw.items():  # pyright: ignore[reportUnknownVariableType]
            if not isinstance(key, str):
                continue
            if key in _STRING_CONDITIONS:
                if isinstance(value, str) and value.strip():
                    conditions[key] = value.strip()
            elif key in _BOOL_CONDITIONS:
                if isinstance(value, bool):
                    conditions[key] = value
            elif key == _EVENT_CONDITION and isinstance(value, list):
                valid_events: list[str] = [e for e in value if isinstance(e, str) and e in _VALID_EVENTS]  # pyright: ignore[reportUnknownVariableType]
                if valid_events:
                    conditions[key] = valid_events

        path_str = str(data.get('process_path', ''))

        return cls(
            name=str(data.get('name', 'Unnamed Rule')),
            enabled=bool(data.get('enabled', True)),
            conditions=conditions,
            protection_enabled=bool(data.get('protection_enabled', False)),
            process_path=Path(path_str) if path_str else None,
            duration=_parse_duration(str(data.get('duration', 'Auto'))),
            voice_notifications=parse_voice_notifications(str(data.get('voice_notifications', 'False'))),
            logging=bool(data.get('logging', False)),
            message_box=bool(data.get('message_box', False)),
        )


def _match_isp_condition(value: str, player: Player) -> bool:
    """Match ISP condition using the same logic as the existing ISP blocklist in check_global_protections."""
    value_upper = value.upper().strip()
    as_name = str(player.iplookup.ipapi.as_name)
    isp = str(player.iplookup.ipapi.isp)

    if as_name and as_name not in ('...', 'N/A'):
        as_name_clean = as_name.upper().replace('AS', '', 1).strip()
        if as_name_clean and value_upper in as_name_clean:
            return True

    return bool(isp and isp not in ('...', 'N/A') and value_upper in isp.upper())


def _match_asn_condition(value: str, player: Player) -> bool:
    """Match ASN condition using normalized exact match (same logic as existing ASN blocklist)."""
    value_upper = value.upper().strip()
    normalized = value_upper if value_upper.startswith('AS') else f'AS{value_upper}'

    asn_ipapi = str(player.iplookup.ipapi.asn)
    asn_geolite2 = str(player.iplookup.geolite2.asn)

    if asn_ipapi and asn_ipapi not in ('...', 'N/A') and asn_ipapi.upper() == normalized:
        return True
    return bool(asn_geolite2 and asn_geolite2 not in ('...', 'N/A') and asn_geolite2.upper() == normalized)


def _match_as_name_condition(value: str, player: Player) -> bool:
    """Match AS Name condition (asname from ip-api) using substring match."""
    as_name = str(player.iplookup.ipapi.as_name)
    return bool(as_name and as_name not in ('...', 'N/A') and value.upper().strip() in as_name.upper())


def _check_condition(key: str, value: str | bool | list[str], player: Player) -> bool:  # noqa: FBT001, PLR0911  # pylint: disable=too-many-return-statements
    """Check whether a single non-event condition matches the player."""
    if key == 'country':
        country_geolite2 = str(player.iplookup.geolite2.country)
        country_ipapi = str(player.iplookup.ipapi.country)
        return (
            bool(country_geolite2 and country_geolite2 not in ('...', 'N/A') and country_geolite2 == value)
            or bool(country_ipapi and country_ipapi not in ('...', 'N/A') and country_ipapi == value)
        )

    if key == 'city':
        city_geolite2 = str(player.iplookup.geolite2.city)
        city_ipapi = str(player.iplookup.ipapi.city)
        return (
            bool(city_geolite2 and city_geolite2 not in ('...', 'N/A') and city_geolite2 == value)
            or bool(city_ipapi and city_ipapi not in ('...', 'N/A') and city_ipapi == value)
        )

    if key == 'region':
        region = str(player.iplookup.ipapi.region)
        return bool(region and region not in ('...', 'N/A') and region == value)

    if key == 'org':
        org = str(player.iplookup.ipapi.org)
        return bool(org and org not in ('...', 'N/A') and isinstance(value, str) and value.upper() in org.upper())

    if key == 'isp':
        return isinstance(value, str) and _match_isp_condition(value, player)

    if key == 'asn':
        return isinstance(value, str) and _match_asn_condition(value, player)

    if key == 'as_name':
        return isinstance(value, str) and _match_as_name_condition(value, player)

    if key == 'mobile':
        mobile = player.iplookup.ipapi.mobile
        if not isinstance(mobile, bool):
            return False
        return mobile == value

    if key == 'vpn':
        proxy = player.iplookup.ipapi.proxy
        if not isinstance(proxy, bool):
            return False
        return proxy == value

    if key == 'hosting':
        hosting = player.iplookup.ipapi.hosting
        if not isinstance(hosting, bool):
            return False
        return hosting == value

    return False


def _evaluate_rule(rule: ComboRule, player: Player, event_type: str | None) -> bool:
    """Check if all conditions in a rule match the given player and event.

    Returns True only when every condition is satisfied (AND logic).

    Dispatch rules:
    - Rules WITHOUT an event condition fire only when event_type is None
      (i.e. from check_global_protections at join-time).
    - Rules WITH an event condition fire only when event_type matches
      one of the listed events (i.e. from handle_detection_notification).
    """
    if not rule.enabled or not rule.conditions:
        return False

    # Event dispatch gating
    event_cond = rule.conditions.get(_EVENT_CONDITION)
    if event_cond is not None:
        # Rule has an event condition — only fire from event handler
        if event_type is None:
            return False
        if not isinstance(event_cond, list) or event_type not in event_cond:
            return False
    elif event_type is not None:
        # Rule has no event condition — only fire from global check
        return False

    # Check all non-event conditions
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
        """Load combo rules from a JSON file. Silently starts with empty rules if file is missing or invalid."""
        cls.rules = []
        if not file_path.exists():
            return
        try:
            data = json.loads(file_path.read_text(encoding='utf-8'))
            if isinstance(data, list):
                for entry in data:  # pyright: ignore[reportUnknownVariableType]
                    if isinstance(entry, dict):
                        cls.rules.append(ComboRule.from_dict(entry))  # pyright: ignore[reportUnknownArgumentType]
        except (json.JSONDecodeError, OSError):
            logger.warning('Failed to load combo rules from %s, starting with empty rules', file_path)

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
        """Return all enabled combo rules whose conditions match the given player and event.

        Args:
            player: The player to evaluate conditions against.
            event_type: ``None`` when called from ``check_global_protections`` (join-time).
                ``'join'``, ``'rejoin'``, or ``'leave'`` when called from
                ``handle_detection_notification``.

        Returns:
            List of matching ComboRule instances.
        """
        return [rule for rule in cls.rules if _evaluate_rule(rule, player, event_type)]

    @classmethod
    def export_rules(cls) -> list[dict[str, object]]:
        """Export rules as a list of dicts (for inclusion in protection settings export)."""
        return [rule.to_dict() for rule in cls.rules]

    @classmethod
    def import_rules(cls, rules_data: list[object]) -> None:
        """Import rules from a list of dicts (from protection settings import)."""
        cls.rules = []
        for entry in rules_data:
            if isinstance(entry, dict):
                cls.rules.append(ComboRule.from_dict(cast('dict[str, object]', entry)))  # pyright: ignore[reportUnknownArgumentType]
