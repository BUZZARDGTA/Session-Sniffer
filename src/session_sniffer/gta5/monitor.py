"""GTA5 process-presence monitor thread.

Polls the running GTA5 process at 1-second intervals, updates `CaptureState`
on every state change, and logs meaningful transitions via `_log_gta5_status_transition`.
"""

from threading import Thread
from threading import enumerate as enumerate_threads
from typing import TYPE_CHECKING

from session_sniffer.background.events import gui_closed__event
from session_sniffer.gta5.process import GTA5Status, find_running_gta5_path
from session_sniffer.logging_setup import get_logger
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    import psutil

logger = get_logger(__name__)

_GTA5_PROCESS_MONITOR_THREAD_NAME = 'GTA5ProcessMonitor'


def _log_gta5_status_transition(previous: GTA5Status, current: GTA5Status) -> None:
    """Info-log the meaningful GTA5 state changes (detect/exit/PID change/suspend), never steady-state polls."""
    if current.is_running != previous.is_running:
        if current.is_running:
            logger.info('[GTA5Monitor] GTA5 process detected: "%s" (PID: %s)', current.path, current.pid)
        else:
            logger.info('[GTA5Monitor] GTA5 process exited (was PID: %s)', previous.pid)
    elif current.pid != previous.pid:
        logger.info('[GTA5Monitor] GTA5 process changed (PID: %s -> %s)', previous.pid, current.pid)
    elif current.is_suspended != previous.is_suspended:
        logger.info('[GTA5Monitor] GTA5 process (PID: %s) %s', current.pid, 'suspended' if current.is_suspended else 'resumed')


def _gta5_process_monitor() -> None:
    """Poll for GTA5 process presence and update `CaptureState.gta5_is_running`.

    Each poll reuses the cached process handle to re-query only the known GTA5 PID,
    skipping the expensive full process scan and Authenticode signature check until the
    process actually dies or its PID is reused. Process presence and the suspended state
    stay current; a fresh scan runs only when the cached process is gone.

    Exits as soon as the GTA5 feature set is no longer active, so the thread does
    not linger when the user switches feature sets.
    """
    last_status = GTA5Status(path=None)
    cached_proc: psutil.Process | None = None
    while not gui_closed__event.is_set():
        if not Settings.is_gta5_feature_set():
            CaptureState.update_gta5_status(GTA5Status(path=None))
            return
        previous_status = last_status
        last_status, cached_proc = find_running_gta5_path(cached_proc, last_status)
        _log_gta5_status_transition(previous_status, last_status)
        CaptureState.update_gta5_status(last_status)
        gui_closed__event.wait(1.0)


def ensure_gta5_process_monitor_running() -> None:
    """Start the GTA5 process monitor thread if the GTA5 feature set is active and it is not already running."""
    if not Settings.is_gta5_feature_set():
        return
    for thread in enumerate_threads():
        if thread.name == _GTA5_PROCESS_MONITOR_THREAD_NAME and thread.is_alive():
            return
    Thread(target=_gta5_process_monitor, name=_GTA5_PROCESS_MONITOR_THREAD_NAME, daemon=True).start()
