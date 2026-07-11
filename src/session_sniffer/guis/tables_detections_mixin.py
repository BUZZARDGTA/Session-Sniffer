"""Right-click Detections menu helpers for session tables."""

from contextlib import suppress
from typing import TYPE_CHECKING

from session_sniffer.guis.detections_manager import open_combo_rule_editor, open_combo_rule_editor_for_player
from session_sniffer.player.detections import GUIDetectionSettings
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtGui import QAction
    from PySide6.QtWidgets import QMenu, QWidget

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
                f'➖ Remove Country ({country_name})',  # noqa: RUF001
                tooltip=f'Remove {country_name} from the country detection list.',
                handler=lambda: _toggle_detection_list(GUIDetectionSettings.country_detection_list, country_name, add=False),
            )
        else:
            add_action(
                menu,
                f'➕ Add Country ({country_name})',  # noqa: RUF001
                tooltip=f'Add {country_name} to the country detection list.',
                handler=lambda: _toggle_detection_list(GUIDetectionSettings.country_detection_list, country_name, add=True),
            )

    # --- ISP ---
    if isp:
        isp_in_list = isp in GUIDetectionSettings.isp_detection_list
        if isp_in_list:
            add_action(
                menu,
                f'➖ Remove ISP ({isp})',  # noqa: RUF001
                tooltip=f'Remove ISP "{isp}" from the ISP detection list.',
                handler=lambda: _toggle_detection_list(GUIDetectionSettings.isp_detection_list, isp, add=False),
            )
        else:
            add_action(
                menu,
                f'➕ Add ISP ({isp})',  # noqa: RUF001
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
                f'➖ Remove ASN ({asn_value})',  # noqa: RUF001
                tooltip=f'Remove ASN "{asn_value}" from the ASN detection list.',
                handler=lambda: _toggle_detection_list(GUIDetectionSettings.asn_detection_list, asn_value, add=False),
            )
        else:
            add_action(
                menu,
                f'➕ Add ASN ({asn_value})',  # noqa: RUF001
                tooltip=f'Add ASN "{asn_value}" to the ASN detection list.',
                handler=lambda: _toggle_detection_list(GUIDetectionSettings.asn_detection_list, asn_value, add=True),
            )

    menu.addSeparator()
    add_action(
        menu,
        '🔗 Create Combo Rule...',
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
    countries: list[str] = sorted({country for player in players if (country := _safe_str(player.iplookup.geolite2.country))})
    isps: list[str] = sorted({isp for player in players if (isp := _safe_str(player.iplookup.ipapi.isp))})
    asns: list[str] = sorted({asn for player in players if (asn := _safe_str(player.iplookup.ipapi.as_name) or _safe_str(player.iplookup.geolite2.asn))})

    has_items = False

    # --- Country ---
    new_countries = [country for country in countries if country not in GUIDetectionSettings.country_detection_list]
    existing_countries = [country for country in countries if country in GUIDetectionSettings.country_detection_list]
    if new_countries or existing_countries:
        has_items = True
    if new_countries:

        def _add_countries(country_names: list[str] = new_countries) -> None:
            for country_name in country_names:
                if country_name not in GUIDetectionSettings.country_detection_list:
                    GUIDetectionSettings.country_detection_list.append(country_name)
            GUIDetectionSettings.save_to_settings()

        add_action(
            menu,
            f'➕ Add {len(new_countries)} Countr{pluralize(len(new_countries), "y", "ies")} to Detection List',  # noqa: RUF001
            tooltip=f'Add {", ".join(new_countries)} to the country detection list.',
            handler=_add_countries,
        )
    if existing_countries:

        def _remove_countries(country_names: list[str] = existing_countries) -> None:
            for country_name in country_names:
                with suppress(ValueError):
                    GUIDetectionSettings.country_detection_list.remove(country_name)
            GUIDetectionSettings.save_to_settings()

        add_action(
            menu,
            f'➖ Remove {len(existing_countries)} Countr{pluralize(len(existing_countries), "y", "ies")} from Detection List',  # noqa: RUF001
            tooltip=f'Remove {", ".join(existing_countries)} from the country detection list.',
            handler=_remove_countries,
        )

    # --- ISP ---
    new_isps = [isp for isp in isps if isp not in GUIDetectionSettings.isp_detection_list]
    existing_isps = [isp for isp in isps if isp in GUIDetectionSettings.isp_detection_list]
    if new_isps or existing_isps:
        if has_items:
            menu.addSeparator()
        has_items = True
    if new_isps:

        def _add_isps(isp_list: list[str] = new_isps) -> None:
            for isp in isp_list:
                if isp not in GUIDetectionSettings.isp_detection_list:
                    GUIDetectionSettings.isp_detection_list.append(isp)
            GUIDetectionSettings.save_to_settings()

        add_action(
            menu,
            f'➕ Add {len(new_isps)} ISP{pluralize(len(new_isps))} to Detection List',  # noqa: RUF001
            tooltip=f'Add {", ".join(new_isps)} to the ISP detection list.',
            handler=_add_isps,
        )
    if existing_isps:

        def _remove_isps(isp_list: list[str] = existing_isps) -> None:
            for isp in isp_list:
                with suppress(ValueError):
                    GUIDetectionSettings.isp_detection_list.remove(isp)
            GUIDetectionSettings.save_to_settings()

        add_action(
            menu,
            f'➖ Remove {len(existing_isps)} ISP{pluralize(len(existing_isps))} from Detection List',  # noqa: RUF001
            tooltip=f'Remove {", ".join(existing_isps)} from the ISP detection list.',
            handler=_remove_isps,
        )

    # --- ASN ---
    new_asns = [asn for asn in asns if asn not in GUIDetectionSettings.asn_detection_list]
    existing_asns = [asn for asn in asns if asn in GUIDetectionSettings.asn_detection_list]
    if (new_asns or existing_asns) and has_items:
        menu.addSeparator()
    if new_asns:

        def _add_asns(asn_list: list[str] = new_asns) -> None:
            for asn in asn_list:
                if asn not in GUIDetectionSettings.asn_detection_list:
                    GUIDetectionSettings.asn_detection_list.append(asn)
            GUIDetectionSettings.save_to_settings()

        add_action(
            menu,
            f'➕ Add {len(new_asns)} ASN{pluralize(len(new_asns))} to Detection List',  # noqa: RUF001
            tooltip=f'Add {", ".join(new_asns)} to the ASN detection list.',
            handler=_add_asns,
        )
    if existing_asns:

        def _remove_asns(asn_list: list[str] = existing_asns) -> None:
            for asn in asn_list:
                with suppress(ValueError):
                    GUIDetectionSettings.asn_detection_list.remove(asn)
            GUIDetectionSettings.save_to_settings()

        add_action(
            menu,
            f'➖ Remove {len(existing_asns)} ASN{pluralize(len(existing_asns))} from Detection List',  # noqa: RUF001
            tooltip=f'Remove {", ".join(existing_asns)} from the ASN detection list.',
            handler=_remove_asns,
        )

    menu.addSeparator()
    add_action(
        menu,
        '🔗 Create Combo Rule...',
        tooltip='Open the combo rule editor to create a new combo rule.',
        handler=lambda: open_combo_rule_editor(parent),
    )
