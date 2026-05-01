"""Right-click Protections menu helpers for manual process suspension."""

from typing import TYPE_CHECKING, cast

from session_sniffer.background.suspend_manager import ProcessSuspendManager
from session_sniffer.player.protections import GUIProtectionSettings

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from PyQt6.QtGui import QAction
    from PyQt6.QtWidgets import QMenu

    from session_sniffer.models.player import Player

_CTX_REASON_PREFIX = 'manual_ctx:'


def _manual_reason_key(ip: str) -> str:
    return f'{_CTX_REASON_PREFIX}{ip}'


def _get_any_process_path() -> Path | None:
    for attr in (
        'player_join_process_path',
        'player_rejoin_process_path',
        'player_leave_process_path',
        'mobile_suspend_process_path',
        'vpn_suspend_process_path',
        'hosting_suspend_process_path',
        'country_block_process_path',
        'isp_block_process_path',
        'asn_block_process_path',
        'gta5_relay_process_path',
    ):
        path = cast('Path | None', getattr(GUIProtectionSettings, attr, None))
        if path is not None:
            return path
    return None


def build_protections_menu(
    menu: QMenu,
    add_action: Callable[..., QAction],
    player: Player,
) -> None:
    """Build a Protections submenu for a single player."""
    process_path = _get_any_process_path()
    if process_path is None:
        action = add_action(
            menu,
            'No process path configured',
            tooltip='Configure a process path in the Detections Manager to enable protections.',
            handler=None,
        )
        action.setEnabled(False)
        return

    reason_key = _manual_reason_key(player.ip)
    is_suspended = ProcessSuspendManager.has_reason(reason_key)

    if is_suspended:
        add_action(
            menu,
            '\u2705 Release Suspension',
            tooltip=f'Remove the manual suspension for {player.ip}.',
            handler=lambda: ProcessSuspendManager.release_reason_global(reason_key),
        )
    else:
        add_action(
            menu,
            '\U0001f6e1\ufe0f Suspend Process (Manual)',
            tooltip=f'Manually suspend the game process for player {player.ip}.',
            handler=lambda: ProcessSuspendManager.request_suspend(
                process_path=process_path,
                reason_key=reason_key,
                left_event=player.left_event,
                duration='Manual',
            ),
        )


def build_protections_menu_multi(
    menu: QMenu,
    add_action: Callable[..., QAction],
    players: list[Player],
) -> None:
    """Build a Protections submenu for multiple selected players."""
    process_path = _get_any_process_path()
    if process_path is None:
        action = add_action(
            menu,
            'No process path configured',
            tooltip='Configure a process path in the Detections Manager to enable protections.',
            handler=None,
        )
        action.setEnabled(False)
        return

    not_suspended = [p for p in players if not ProcessSuspendManager.has_reason(_manual_reason_key(p.ip))]
    suspended = [p for p in players if ProcessSuspendManager.has_reason(_manual_reason_key(p.ip))]

    if not_suspended:
        def _suspend_all() -> None:
            for p in not_suspended:
                ProcessSuspendManager.request_suspend(
                    process_path=process_path,
                    reason_key=_manual_reason_key(p.ip),
                    left_event=p.left_event,
                    duration='Manual',
                )

        add_action(
            menu,
            f'\U0001f6e1\ufe0f Suspend {len(not_suspended)} Player(s) (Manual)',
            tooltip='Manually suspend the game process for the selected players.',
            handler=_suspend_all,
        )

    if not_suspended and suspended:
        menu.addSeparator()

    if suspended:
        def _release_all(ps: list[Player] = suspended) -> None:
            for p in ps:
                ProcessSuspendManager.release_reason_global(_manual_reason_key(p.ip))

        add_action(
            menu,
            f'\u2705 Release Suspension for {len(suspended)} Player(s)',
            tooltip='Remove manual suspension for the selected suspended players.',
            handler=_release_all,
        )
