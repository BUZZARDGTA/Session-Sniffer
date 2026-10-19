"""Combo detection rules — multi-condition AND rules with per-rule actions."""

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, ClassVar

from pydantic import TypeAdapter, ValidationError

from session_sniffer.models.combo_rules import EVENT_CONDITION, ComboRule, ConditionValue
from session_sniffer.models.player import Player
from session_sniffer.networking.ip_range import IPRange, check_ip_against_ranges, parse_ip_range_entry

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

type ConditionMatcher = Callable[[ConditionValue, Player], bool]


def _valid_lookup_value(value: object) -> bool:
    """Return True if an IP lookup value is meaningful."""
    return isinstance(value, str) and value not in ('', '...', 'N/A')


def _match_exact_lookup(value: str, *candidates: object) -> bool:
    """Return True if any meaningful lookup candidate exactly matches value."""
    return any(_valid_lookup_value(candidate) and candidate == value for candidate in candidates)


def _match_isp_condition(value: ConditionValue, player: Player) -> bool:
    """Match ISP condition using the same logic as the existing ISP detection."""
    if not isinstance(value, str):
        return False
    value_upper = value.upper().strip()

    if player.iplookup.ipapi.as_name and player.iplookup.ipapi.as_name not in ('...', 'N/A'):
        as_name_clean = player.iplookup.ipapi.as_name.upper().replace('AS', '', 1).strip()
        if as_name_clean and value_upper in as_name_clean:
            return True

    if player.iplookup.ipapi.isp and player.iplookup.ipapi.isp not in ('...', 'N/A') and value_upper in player.iplookup.ipapi.isp.upper():
        return True

    return bool(player.iplookup.geolite2.asn and player.iplookup.geolite2.asn not in ('...', 'N/A') and value_upper in player.iplookup.geolite2.asn.upper())


def _match_asn_condition(value: ConditionValue, player: Player) -> bool:
    """Match ASN condition using normalized exact match."""
    if not isinstance(value, str):
        return False
    value_upper = value.upper().strip()
    normalized = value_upper if value_upper.startswith('AS') else f'AS{value_upper}'

    if player.iplookup.ipapi.asn and player.iplookup.ipapi.asn not in ('...', 'N/A'):
        ipapi_asn_upper = player.iplookup.ipapi.asn.upper()
        if ipapi_asn_upper in (value_upper, normalized) or (ipapi_asn_upper.split() and ipapi_asn_upper.split()[0] == normalized):
            return True

    return bool(
        player.iplookup.geolite2.asn
        and player.iplookup.geolite2.asn not in ('...', 'N/A')
        and player.iplookup.geolite2.asn.upper() in (value_upper, normalized),
    )


def _match_as_name_condition(value: ConditionValue, player: Player) -> bool:
    """Match AS Name condition using substring match."""
    return isinstance(value, str) and bool(
        player.iplookup.ipapi.as_name and player.iplookup.ipapi.as_name not in ('...', 'N/A') and value.upper().strip() in player.iplookup.ipapi.as_name.upper(),
    )


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


def _match_mobile_condition(value: ConditionValue, player: Player) -> bool:
    """Match mobile flag condition."""
    return isinstance(value, bool) and isinstance(player.iplookup.ipapi.mobile, bool) and player.iplookup.ipapi.mobile == value


def _match_vpn_condition(value: ConditionValue, player: Player) -> bool:
    """Match VPN/proxy flag condition."""
    return isinstance(value, bool) and isinstance(player.iplookup.ipapi.proxy, bool) and player.iplookup.ipapi.proxy == value


def _match_hosting_condition(value: ConditionValue, player: Player) -> bool:
    """Match hosting/datacenter flag condition."""
    return isinstance(value, bool) and isinstance(player.iplookup.ipapi.hosting, bool) and player.iplookup.ipapi.hosting == value


@lru_cache(maxsize=256)
def _parse_ip_ranges_cached(raw_range: str) -> tuple[IPRange, ...]:
    """Parse comma-separated IP ranges with caching."""
    return tuple(parse_ip_range_entry(raw_range))


def _match_ip_range_condition(value: ConditionValue, player: Player) -> bool:
    """Match player IP address against IP range condition."""
    if not isinstance(value, str):
        return False
    try:
        ranges = _parse_ip_ranges_cached(value)
    except ValueError:
        return False
    return check_ip_against_ranges(player.ip, ranges) is not None


_CONDITION_MATCHERS: dict[str, ConditionMatcher] = {
    'country': _match_country_condition,
    'city': _match_city_condition,
    'region': _match_region_condition,
    'org': _match_org_condition,
    'isp': _match_isp_condition,
    'asn': _match_asn_condition,
    'as_name': _match_as_name_condition,
    'ip_range': _match_ip_range_condition,
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

    event_cond = rule.conditions.get(EVENT_CONDITION)

    if event_cond is not None:
        if event_type is None:
            return False
        if not isinstance(event_cond, list) or event_type not in event_cond:
            return False
    elif event_type is not None:
        return False

    return all(_check_condition(key, value, player) for key, value in rule.conditions.items() if key != EVENT_CONDITION)


@dataclass(kw_only=True, slots=True)
class ComboRulesManager:
    """Singleton manager for combo detection rules."""

    rules: ClassVar[list[ComboRule]] = []

    @classmethod
    def load_from_file(cls, file_path: Path) -> None:
        """Load combo rules from a JSON file. Starts with empty rules if file is missing or invalid."""
        cls.rules = []

        if not file_path.exists():
            return

        try:
            content = file_path.read_text(encoding='utf-8')
            cls.rules = TypeAdapter(list[ComboRule]).validate_json(content)
        except ValidationError, json.JSONDecodeError, OSError:
            logger.exception('Failed to load combo rules from %s, starting with empty rules', file_path)
            cls.rules = []

    @classmethod
    def save_to_file(cls, file_path: Path) -> None:
        """Save all combo rules to a JSON file."""
        file_path.parent.mkdir(parents=True, exist_ok=True)

        json_str = TypeAdapter(list[ComboRule]).dump_json(cls.rules, indent=4).decode('utf-8')
        tmp_path = file_path.with_suffix('.tmp')
        tmp_path.write_text(json_str, encoding='utf-8')
        tmp_path.replace(file_path)

    @classmethod
    def evaluate(cls, player: Player, event_type: str | None = None) -> list[ComboRule]:
        """Return all enabled combo rules whose conditions match the given player and event."""
        return [rule for rule in cls.rules if _evaluate_rule(rule, player, event_type)]
