"""Game process presence and socket-port monitor thread.

Polls for running supported PC games at 1-second intervals, updates `CaptureState`
on state changes, and logs meaningful transitions via `_log_game_status_transition`.
"""

from threading import Thread
from threading import enumerate as enumerate_threads
from typing import TYPE_CHECKING

from session_sniffer.background.events import gui_closed__event
from session_sniffer.capture.game_process import ActiveGameStatus, find_running_game_process
from session_sniffer.gta5.process import GTA5Status, find_running_gta5_path
from session_sniffer.logging_setup import get_logger
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    import psutil

logger = get_logger(__name__)

_GAME_PROCESS_MONITOR_THREAD_NAME = 'GameProcessMonitor'


def _log_game_status_transition(previous: ActiveGameStatus, current: ActiveGameStatus) -> None:
    """Info-log meaningful game state changes (detect/exit/PID change/ports), never steady-state polls."""
    if current.is_running != previous.is_running:
        if current.is_running:
            logger.info('[GameMonitor] %s process detected: "%s" (PID: %s)', current.game_name, current.path, current.pid)
            if current.udp_ports:
                logger.info('[GameMonitor] %s UDP ports bound (PID %s): %s', current.game_name, current.pid, sorted(current.udp_ports))
        else:
            logger.info('[GameMonitor] %s process exited (was PID: %s)', previous.game_name, previous.pid)
    elif current.pid != previous.pid:
        logger.info('[GameMonitor] %s process changed (PID: %s -> %s)', current.game_name, previous.pid, current.pid)
        if current.udp_ports:
            logger.info('[GameMonitor] %s UDP ports bound (PID %s): %s', current.game_name, current.pid, sorted(current.udp_ports))
    elif current.udp_ports != previous.udp_ports:
        logger.info('[GameMonitor] %s UDP ports updated (PID %s): %s', current.game_name, current.pid, sorted(current.udp_ports))


def _game_process_monitor() -> None:
    """Poll for running supported game processes and update `CaptureState`.

    Each poll reuses the cached process handle to re-query only the known PID,
    skipping the expensive full process scan until the process actually dies or its
    PID is reused.

    Exits as soon as neither exclusive game process filtering nor the GTA5 feature set
    is active.
    """
    last_game_status = ActiveGameStatus(game_name=None, path=None)
    last_gta5_status = GTA5Status(path=None)
    cached_game_proc: psutil.Process | None = None
    cached_gta5_proc: psutil.Process | None = None

    while not gui_closed__event.is_set():
        if not (Settings.capture_filter_exclusive_game_process or Settings.is_gta5_feature_set()):
            CaptureState.update_active_game_status(ActiveGameStatus(game_name=None, path=None))
            CaptureState.update_gta5_status(GTA5Status(path=None))
            return

        target_game_name = 'Grand Theft Auto Online' if Settings.is_gta5_feature_set() else None
        previous_game_status = last_game_status
        last_game_status, cached_game_proc = find_running_game_process(
            cached_process=cached_game_proc,
            cached_status=last_game_status,
            target_game_name=target_game_name,
        )
        _log_game_status_transition(previous_game_status, last_game_status)
        CaptureState.update_active_game_status(last_game_status)

        # Update GTA5 status for GTA5-specific features (suspend manager, Looky)
        if Settings.is_gta5_feature_set() or last_game_status.game_name == 'Grand Theft Auto Online':
            last_gta5_status, cached_gta5_proc = find_running_gta5_path(cached_gta5_proc, last_gta5_status)
            CaptureState.update_gta5_status(last_gta5_status)
        elif last_gta5_status.is_running:
            last_gta5_status = GTA5Status(path=None)
            cached_gta5_proc = None
            CaptureState.update_gta5_status(last_gta5_status)

        gui_closed__event.wait(1.0)


def ensure_game_process_monitor_running() -> None:
    """Start the game process monitor thread if needed and it is not already running."""
    if not (Settings.capture_filter_exclusive_game_process or Settings.is_gta5_feature_set()):
        return
    for thread in enumerate_threads():
        if thread.name == _GAME_PROCESS_MONITOR_THREAD_NAME and thread.is_alive():
            return
    Thread(target=_game_process_monitor, name=_GAME_PROCESS_MONITOR_THREAD_NAME, daemon=True).start()
