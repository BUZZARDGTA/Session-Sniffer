"""ISP and ASN filtering utilities for hiding players based on provider metadata."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from session_sniffer.models.player import Player

__all__ = [
    'get_player_primary_isp',
    'is_player_isp_filtered',
]

_INVALID_ISP_VALUES: frozenset[str] = frozenset({'', '...', 'N/A', 'None'})


def get_player_primary_isp(player: Player) -> str | None:
    """Return the primary resolved ISP or ASN name for a player, or `None` if unresolved."""
    ipapi_isp = player.iplookup.ipapi.isp.strip()
    if ipapi_isp and ipapi_isp not in _INVALID_ISP_VALUES:
        return ipapi_isp

    geolite2_asn = player.iplookup.geolite2.asn.strip()
    if geolite2_asn and geolite2_asn not in _INVALID_ISP_VALUES:
        return geolite2_asn

    ipapi_org = player.iplookup.ipapi.org.strip()
    if ipapi_org and ipapi_org not in _INVALID_ISP_VALUES:
        return ipapi_org

    ipapi_as_name = player.iplookup.ipapi.as_name.strip()
    if ipapi_as_name and ipapi_as_name not in _INVALID_ISP_VALUES:
        return ipapi_as_name

    return None


def is_player_isp_filtered(player: Player, filtered_isps: tuple[str, ...]) -> bool:
    """Return `True` if any resolved ISP or ASN for *player* matches any entry in *filtered_isps*."""
    if not filtered_isps:
        return False

    candidates: list[str] = []

    geolite2_asn = player.iplookup.geolite2.asn.strip()
    if geolite2_asn and geolite2_asn not in _INVALID_ISP_VALUES:
        candidates.append(geolite2_asn.upper())

    ipapi = player.iplookup.ipapi
    for raw_value in (ipapi.isp, ipapi.org, ipapi.as_name, ipapi.asn):
        text = raw_value.strip()
        if text and text not in _INVALID_ISP_VALUES:
            candidates.append(text.upper())

    if not candidates:
        return False

    for target in filtered_isps:
        target_upper = target.strip().upper()
        if not target_upper:
            continue
        for candidate in candidates:
            if target_upper in candidate:
                return True

    return False
