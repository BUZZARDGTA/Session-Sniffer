"""Looky System context menu builder for `SessionTableView`."""

from typing import TYPE_CHECKING

from PySide6.QtCore import QUrl
from PySide6.QtGui import QAction, QDesktopServices, QIcon

from session_sniffer.constants.standalone import LOOKY_BASE_HOST
from session_sniffer.guis.looky_text import configure_looky_action, get_looky_restriction
from session_sniffer.guis.tables_player_actions import show_crawler_request, show_looky_lookup, show_proxy_join_request
from session_sniffer.guis.tables_player_actions._userip_dialog import (
    get_player_looky_username_lists,
    looky_remove_usernames_for_player,
    looky_restore_usernames_for_player,
)
from session_sniffer.guis.tables_player_actions.looky_system._looky_helpers import open_looky_profile_by_username
from session_sniffer.guis.tables_userip_menu import add_action, add_menu
from session_sniffer.guis.tables_userip_mixin import resolve_usernames_for_player
from session_sniffer.guis.theming import ICONS_DIR_PATH
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.networking.looky_system import get_looky_user_url
from session_sniffer.player.looky_rids import resolve_player_rockstar_ids
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtWidgets import QMenu, QWidget

    from session_sniffer.models.player import Player


def _make_url_opener(url: str) -> Callable[[], None]:
    """Return a zero-arg handler opening *url* in the default browser."""

    def _open() -> None:
        QDesktopServices.openUrl(QUrl(url))

    return _open


def build_looky_system_menu(parent_menu: QMenu, players: list[Player], parent_widget: QWidget) -> None:
    """Append the `Looky System` submenu for *players* to *parent_menu* when GTA V local capture allows it."""
    if not Settings.is_gta5_feature_set() or not CaptureState.is_local_capture() or not players or any(player.is_third_party_server for player in players):
        return

    restriction = get_looky_restriction(players)

    def _apply_looky_gating(action: QAction) -> None:
        configure_looky_action(action, default_tooltip=action.toolTip(), restriction=restriction)

    globe_icon = QIcon(str(ICONS_DIR_PATH / 'globe.svg'))
    looky_menu = add_menu(
        parent_menu,
        tr('Looky System'),
        tr('Looky System tools and shortcuts.'),
        icon=QIcon(str(ICONS_DIR_PATH / 'scan-eye.svg')),
    )
    add_action(
        looky_menu,
        tr('Open Website'),
        tooltip=tr('Open the Looky System website in your default browser.'),
        handler=_make_url_opener(LOOKY_BASE_HOST),
        icon=globe_icon,
    )

    if len(players) == 1:
        _populate_single_player_looky_menu(looky_menu, players[0], parent_widget, globe_icon, _apply_looky_gating)
        return

    all_selected_rockstar_ids: list[int] = []
    for player in players:
        for _, rockstar_id in resolve_player_rockstar_ids(player):
            if rockstar_id not in all_selected_rockstar_ids:
                all_selected_rockstar_ids.append(rockstar_id)

    if all_selected_rockstar_ids:

        def _open_all_selected_profiles() -> None:
            for rockstar_id in all_selected_rockstar_ids:
                QDesktopServices.openUrl(QUrl(get_looky_user_url(rockstar_id)))

        add_action(
            looky_menu,
            tr('View on Website (All Selected)'),
            tooltip=tr_plural(
                'Open {count} player profile on the Looky System website.',
                'Open {count} player profiles on the Looky System website.',
                len(all_selected_rockstar_ids),
            ),
            handler=_open_all_selected_profiles,
            icon=globe_icon,
        )

    looky_menu.addSeparator()

    def _show_looky_lookup_for_all() -> None:
        for player in players:
            show_looky_lookup(parent_widget, player)

    lookup_all_action = add_action(
        looky_menu,
        tr('Lookup (All Selected)'),
        tooltip=tr('Query the Looky System API for each selected player IP.'),
        handler=_show_looky_lookup_for_all,
        icon=QIcon(str(ICONS_DIR_PATH / 'user-round.svg')),
    )
    _apply_looky_gating(lookup_all_action)


def _populate_single_player_looky_menu(
    looky_menu: QMenu,
    target_player: Player,
    parent_widget: QWidget,
    globe_icon: QIcon,
    apply_looky_gating: Callable[[QAction], None],
) -> None:
    """Populate the single-player `Looky System` submenu items."""
    resolved_rids = resolve_player_rockstar_ids(target_player)
    if resolved_rids:
        if len(resolved_rids) == 1:
            target_name, target_rockstar_id = resolved_rids[0]
            display_target_name = target_name or str(target_rockstar_id)
            profile_url = get_looky_user_url(target_rockstar_id)
            add_action(
                looky_menu,
                tr('View on Website'),
                tooltip=tr("Open {name}'s profile on the Looky System website ({url}).", name=display_target_name, url=profile_url),
                handler=_make_url_opener(profile_url),
                icon=globe_icon,
            )
        else:
            view_website_menu = add_menu(
                looky_menu,
                tr('View on Website'),
                tr("Open this player's profile on the Looky System website."),
                icon=globe_icon,
            )

            all_profile_urls: list[str] = []
            for user_name, target_rockstar_id in resolved_rids:
                label = f'{user_name} ({target_rockstar_id})' if user_name else str(target_rockstar_id)
                target_name = user_name or str(target_rockstar_id)
                profile_url = get_looky_user_url(target_rockstar_id)
                all_profile_urls.append(profile_url)
                add_action(
                    view_website_menu,
                    label,
                    tooltip=tr("Open {name}'s profile on the Looky System website ({url}).", name=target_name, url=profile_url),
                    handler=_make_url_opener(profile_url),
                    icon=globe_icon,
                )
            view_website_menu.addSeparator()

            def _open_all_player_profiles() -> None:
                for profile_url in all_profile_urls:
                    QDesktopServices.openUrl(QUrl(profile_url))

            add_action(
                view_website_menu,
                tr('Open All ({count})', count=len(resolved_rids)),
                tooltip=tr('Open all {count} player profiles on the Looky System website.', count=len(resolved_rids)),
                handler=_open_all_player_profiles,
                icon=globe_icon,
            )
    elif player_usernames := resolve_usernames_for_player(target_player, include_relay_mod_menus=True):

        def _make_username_profile_opener(username: str) -> Callable[[], None]:
            def _open() -> None:
                open_looky_profile_by_username(parent_widget, target_player, username)

            return _open

        if len(player_usernames) == 1:
            single_name = player_usernames[0]
            view_action = add_action(
                looky_menu,
                tr('View on Website'),
                tooltip=tr("Resolve and open {name}'s profile on the Looky System website.", name=single_name),
                handler=_make_username_profile_opener(single_name),
                icon=globe_icon,
            )
            apply_looky_gating(view_action)
        else:
            view_website_menu = add_menu(
                looky_menu,
                tr('View on Website'),
                tr("Open this player's profile on the Looky System website."),
                icon=globe_icon,
            )
            for username in player_usernames:
                user_view_action = add_action(
                    view_website_menu,
                    username,
                    tooltip=tr("Resolve and open {name}'s profile on the Looky System website.", name=username),
                    handler=_make_username_profile_opener(username),
                    icon=globe_icon,
                )
                apply_looky_gating(user_view_action)

    looky_menu.addSeparator()

    lookup_action = add_action(
        looky_menu,
        tr('Lookup'),
        tooltip=tr('Query the Looky System API to find players associated with this IP.'),
        handler=lambda: show_looky_lookup(parent_widget, target_player),
        icon=QIcon(str(ICONS_DIR_PATH / 'user-round.svg')),
    )
    apply_looky_gating(lookup_action)

    if resolved_rids:
        crawler_action = add_action(
            looky_menu,
            tr('Call Crawler'),
            tooltip=tr('Call the crawler bot to resolve usernames for players in the session associated with this IP.'),
            handler=lambda: show_crawler_request(parent_widget, target_player),
            icon=QIcon(str(ICONS_DIR_PATH / 'bot.svg')),
        )
        apply_looky_gating(crawler_action)

        proxy_join_action = add_action(
            looky_menu,
            tr('Proxy Join'),
            tooltip=tr("Call the Looky System proxy bot to join this player's session."),
            handler=lambda: show_proxy_join_request(parent_widget, target_player),
            icon=QIcon(str(ICONS_DIR_PATH / 'user-plus.svg')),
        )
        apply_looky_gating(proxy_join_action)

    active_looky_names, removed_looky_names = get_player_looky_username_lists(target_player)
    if active_looky_names or removed_looky_names:
        looky_menu.addSeparator()
    if active_looky_names:
        add_action(
            looky_menu,
            tr('Remove Looky Usernames…'),
            tooltip=tr('Hide selected Looky System usernames on this IP (useful for VPN or shared IPs).'),
            handler=lambda: looky_remove_usernames_for_player(parent_widget, target_player, active_looky_names),
            icon=QIcon(str(ICONS_DIR_PATH / 'remove.svg')),
        )
    if removed_looky_names:
        add_action(
            looky_menu,
            tr('Restore Removed Looky Usernames…'),
            tooltip=tr('Re-add previously removed Looky System usernames on this IP.'),
            handler=lambda: looky_restore_usernames_for_player(parent_widget, target_player, removed_looky_names),
            icon=QIcon(str(ICONS_DIR_PATH / 'rotate-ccw.svg')),
        )
