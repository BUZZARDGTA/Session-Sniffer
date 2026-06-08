"""Right-click Detections menu helpers for session tables."""

from contextlib import suppress
from typing import TYPE_CHECKING

from session_sniffer.guis.detections_manager import open_combo_rule_editor, open_combo_rule_editor_for_player
from session_sniffer.player.detections import GUIDetectionSettings

if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtGui import QAction
    from PyQt6.QtWidgets import QMenu, QWidget

    from session_sniffer.models.player import Player

_PLACEHOLDER = '...'


def _toggle_detection_list(target_list: list[str], value: str, *, add: bool) -> None:
    """Add or remove *value* from a GUIDetectionSettings list and persist."""
    if add:
        if value not in target_list:
            target_list.append(value)
    else:
        with suppress(ValueError):
            target_list.remove(value)
    GUIDetectionSettings.save_to_settings()


def _safe_str(value: str) -> str | None:
    """Return `value` if it is a non-empty, non-placeholder string, else `None`."""
    if value and value != _PLACEHOLDER:
        return value
    return None


def build_detections_menu(
    menu: QMenu,
    add_action: Callable[..., QAction],
    player: Player,
    parent: QWidget,
) -> None:
    """Build a Detections submenu for a single player."""
    country_name = _safe_str(player.iplookup.geolite2.country)
    isp = _safe_str(player.iplookup.ipapi.isp)
    as_name = _safe_str(player.iplookup.ipapi.as_name)
    asn_geolite2 = _safe_str(player.iplookup.geolite2.asn)

    # --- Country ---
    if country_name:
        country_in_list = country_name in GUIDetectionSettings.country_detection_list
        if country_in_list:
            add_action(
                menu,
                f'\u2705 Remove Country ({country_name})',
                tooltip=f'Remove {country_name} from the country detection list.',
                handler=lambda: _toggle_detection_list(GUIDetectionSettings.country_detection_list, country_name, add=False),
            )
        else:
            add_action(
                menu,
                f'Add Country ({country_name})',
                tooltip=f'Add {country_name} to the country detection list.',
                handler=lambda: _toggle_detection_list(GUIDetectionSettings.country_detection_list, country_name, add=True),
            )

    # --- ISP ---
    if isp:
        isp_in_list = isp in GUIDetectionSettings.isp_detection_list
        if isp_in_list:
            add_action(
                menu,
                f'\u2705 Remove ISP ({isp})',
                tooltip=f'Remove ISP "{isp}" from the ISP detection list.',
                handler=lambda: _toggle_detection_list(GUIDetectionSettings.isp_detection_list, isp, add=False),
            )
        else:
            add_action(
                menu,
                f'Add ISP ({isp})',
                tooltip=f'Add ISP "{isp}" to the ISP detection list.',
                handler=lambda: _toggle_detection_list(GUIDetectionSettings.isp_detection_list, isp, add=True),
            )

    # --- ASN ---
    asn_value = as_name or asn_geolite2
    if asn_value:
        asn_in_list = asn_value in GUIDetectionSettings.asn_detection_list
        if asn_in_list:
            add_action(
                menu,
                f'\u2705 Remove ASN ({asn_value})',
                tooltip=f'Remove ASN "{asn_value}" from the ASN detection list.',
                handler=lambda: _toggle_detection_list(GUIDetectionSettings.asn_detection_list, asn_value, add=False),
            )
        else:
            add_action(
                menu,
                f'Add ASN ({asn_value})',
                tooltip=f'Add ASN "{asn_value}" to the ASN detection list.',
                handler=lambda: _toggle_detection_list(GUIDetectionSettings.asn_detection_list, asn_value, add=True),
            )

    menu.addSeparator()
    add_action(
        menu,
        '\U0001f517 Create Combo Rule...',
        tooltip="Open the combo rule editor pre-filled with this player's Country, ISP and ASN.",
        handler=lambda: open_combo_rule_editor_for_player(parent, player),
    )


def build_detections_menu_multi(
    menu: QMenu,
    add_action: Callable[..., QAction],
    players: list[Player],
    parent: QWidget,
) -> None:
    """Build a Detections submenu for multiple selected players."""
    # Collect unique values from all players
    countries: list[str] = sorted({
        cn
        for p in players
        if (cn := _safe_str(p.iplookup.geolite2.country))
    })
    isps: list[str] = sorted({
        i
        for p in players
        if (i := _safe_str(p.iplookup.ipapi.isp))
    })
    asns: list[str] = sorted({
        a
        for p in players
        if (a := _safe_str(p.iplookup.ipapi.as_name) or _safe_str(p.iplookup.geolite2.asn))
    })

    has_items = False

    # --- Country ---
    new_countries = [c for c in countries if c not in GUIDetectionSettings.country_detection_list]
    existing_countries = [c for c in countries if c in GUIDetectionSettings.country_detection_list]
    if new_countries or existing_countries:
        has_items = True
    if new_countries:
        def _add_countries(names: list[str] = new_countries) -> None:
            for c in names:
                if c not in GUIDetectionSettings.country_detection_list:
                    GUIDetectionSettings.country_detection_list.append(c)
            GUIDetectionSettings.save_to_settings()

        add_action(
            menu,
            f'Add {len(new_countries)} Country/Countries to Detection List',
            tooltip=f'Add {", ".join(new_countries)} to the country detection list.',
            handler=_add_countries,
        )
    if existing_countries:
        def _remove_countries(names: list[str] = existing_countries) -> None:
            for c in names:
                with suppress(ValueError):
                    GUIDetectionSettings.country_detection_list.remove(c)
            GUIDetectionSettings.save_to_settings()

        add_action(
            menu,
            f'\u2705 Remove {len(existing_countries)} Country/Countries from Detection List',
            tooltip=f'Remove {", ".join(existing_countries)} from the country detection list.',
            handler=_remove_countries,
        )

    # --- ISP ---
    new_isps = [i for i in isps if i not in GUIDetectionSettings.isp_detection_list]
    existing_isps = [i for i in isps if i in GUIDetectionSettings.isp_detection_list]
    if new_isps or existing_isps:
        if has_items:
            menu.addSeparator()
        has_items = True
    if new_isps:
        def _add_isps(isp_list: list[str] = new_isps) -> None:
            for i in isp_list:
                if i not in GUIDetectionSettings.isp_detection_list:
                    GUIDetectionSettings.isp_detection_list.append(i)
            GUIDetectionSettings.save_to_settings()

        add_action(
            menu,
            f'Add {len(new_isps)} ISP(s) to Detection List',
            tooltip=f'Add {", ".join(new_isps)} to the ISP detection list.',
            handler=_add_isps,
        )
    if existing_isps:
        def _remove_isps(isp_list: list[str] = existing_isps) -> None:
            for i in isp_list:
                with suppress(ValueError):
                    GUIDetectionSettings.isp_detection_list.remove(i)
            GUIDetectionSettings.save_to_settings()

        add_action(
            menu,
            f'\u2705 Remove {len(existing_isps)} ISP(s) from Detection List',
            tooltip=f'Remove {", ".join(existing_isps)} from the ISP detection list.',
            handler=_remove_isps,
        )

    # --- ASN ---
    new_asns = [a for a in asns if a not in GUIDetectionSettings.asn_detection_list]
    existing_asns = [a for a in asns if a in GUIDetectionSettings.asn_detection_list]
    if (new_asns or existing_asns) and has_items:
        menu.addSeparator()
    if new_asns:
        def _add_asns(asn_list: list[str] = new_asns) -> None:
            for a in asn_list:
                if a not in GUIDetectionSettings.asn_detection_list:
                    GUIDetectionSettings.asn_detection_list.append(a)
            GUIDetectionSettings.save_to_settings()

        add_action(
            menu,
            f'Add {len(new_asns)} ASN(s) to Detection List',
            tooltip=f'Add {", ".join(new_asns)} to the ASN detection list.',
            handler=_add_asns,
        )
    if existing_asns:
        def _remove_asns(asn_list: list[str] = existing_asns) -> None:
            for a in asn_list:
                with suppress(ValueError):
                    GUIDetectionSettings.asn_detection_list.remove(a)
            GUIDetectionSettings.save_to_settings()

        add_action(
            menu,
            f'\u2705 Remove {len(existing_asns)} ASN(s) from Detection List',
            tooltip=f'Remove {", ".join(existing_asns)} from the ASN detection list.',
            handler=_remove_asns,
        )

    menu.addSeparator()
    add_action(
        menu,
        '\U0001f517 Create Combo Rule...',
        tooltip='Open the combo rule editor to create a new combo rule.',
        handler=lambda: open_combo_rule_editor(parent),
    )
