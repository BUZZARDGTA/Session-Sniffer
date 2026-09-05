"""Target process presence and socket-port monitor thread.

Polls for the configured target process PID at 1-second intervals, updates `CaptureState`
on state changes, and logs meaningful transitions via `_log_process_status_transition`.
"""

from threading import Thread
from threading import enumerate as enumerate_threads
from typing import TYPE_CHECKING

from session_sniffer.background.events import gui_closed__event
from session_sniffer.capture.process import TargetProcessStatus, inspect_target_process
from session_sniffer.gta5.process import GTA5Status, find_running_gta5_path
from session_sniffer.logging_setup import get_logger
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    import psutil

logger = get_logger(__name__)

_PROCESS_MONITOR_THREAD_NAME = 'ProcessMonitor'


def _log_process_status_transition(previous: TargetProcessStatus, current: TargetProcessStatus) -> None:
    """Log meaningful target process state changes (detect/exit/PID change at INFO, port updates at DEBUG)."""
    process_identifier = f'{current.name} (PID: {current.pid})' if current.name else f'PID {current.pid}'
    previous_identifier = f'{previous.name} (PID: {previous.pid})' if previous.name else f'PID {previous.pid}'

    if current.is_running != previous.is_running:
        if current.is_running:
            logger.info('[ProcessMonitor] Target process detected: %s at "%s"', process_identifier, current.path)
            if current.udp_ports:
                logger.info('[ProcessMonitor] %s UDP ports bound: %s', process_identifier, sorted(current.udp_ports))
        else:
            logger.info('[ProcessMonitor] Target process exited: %s; resetting to capture all traffic', previous_identifier)
    elif current.is_running and current.pid != previous.pid:
        logger.info('[ProcessMonitor] Target process changed (%s -> %s)', previous_identifier, process_identifier)
        if current.udp_ports:
            logger.info('[ProcessMonitor] %s UDP ports bound: %s', process_identifier, sorted(current.udp_ports))
    elif current.is_running and current.udp_ports != previous.udp_ports:
        logger.debug('[ProcessMonitor] %s UDP ports updated: %s', process_identifier, sorted(current.udp_ports))


def _process_monitor() -> None:
    """Poll for the configured target PID and update `CaptureState`.

    Exits as soon as neither process PID filtering nor the GTA5 feature set is active.
    """
    last_process_status = TargetProcessStatus()
    last_gta5_status = GTA5Status(path=None)
    cached_process: psutil.Process | None = None
    cached_gta5_process: psutil.Process | None = None

    while not gui_closed__event.is_set():
        target_pid = Settings.capture_filter_process_pid
        if target_pid <= 0 and not Settings.is_gta5_feature_set():
            CaptureState.update_target_process_status(TargetProcessStatus())
            CaptureState.update_gta5_status(GTA5Status(path=None))
            return

        if target_pid > 0:
            previous_process_status = last_process_status
            last_process_status, cached_process = inspect_target_process(target_pid, cached_process)
            if not last_process_status.is_running:
                if previous_process_status.is_running:
                    _log_process_status_transition(previous_process_status, last_process_status)
                else:
                    logger.info('[ProcessMonitor] Target process (PID %d) is not running; resetting to capture all traffic', target_pid)
                Settings.capture_filter_process_pid = 0
                Settings.rewrite_settings_file()
                last_process_status = TargetProcessStatus()
                cached_process = None
            else:
                _log_process_status_transition(previous_process_status, last_process_status)
            CaptureState.update_target_process_status(last_process_status)
        elif last_process_status.is_running or last_process_status.pid is not None:
            last_process_status = TargetProcessStatus()
            cached_process = None
            CaptureState.update_target_process_status(last_process_status)

        # Update GTA5 status for GTA5-specific features (suspend manager, Looky)
        if Settings.is_gta5_feature_set():
            last_gta5_status, cached_gta5_process = find_running_gta5_path(cached_gta5_process, last_gta5_status)
            CaptureState.update_gta5_status(last_gta5_status)
        elif last_gta5_status.is_running:
            last_gta5_status = GTA5Status(path=None)
            cached_gta5_process = None
            CaptureState.update_gta5_status(last_gta5_status)

        gui_closed__event.wait(1.0)


def ensure_process_monitor_running() -> None:
    """Start the process monitor thread if needed and it is not already running."""
    if Settings.capture_filter_process_pid <= 0 and not Settings.is_gta5_feature_set():
        return
    for thread in enumerate_threads():
        if thread.name == _PROCESS_MONITOR_THREAD_NAME and thread.is_alive():
            return
    Thread(target=_process_monitor, name=_PROCESS_MONITOR_THREAD_NAME, daemon=True).start()
