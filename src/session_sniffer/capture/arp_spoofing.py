"""ARP spoofing background task utilities."""

import subprocess
import time
from dataclasses import dataclass
from threading import Event, Thread
from typing import TYPE_CHECKING, ClassVar

from session_sniffer import msgbox
from session_sniffer.background.events import gui_closed__event
from session_sniffer.constants.local import BIN_DIR_PATH
from session_sniffer.error_messages import format_arp_spoofing_failed_message
from session_sniffer.logging_setup import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.capture.packet_capture import CaptureHolder
    from session_sniffer.networking.interface import SelectedInterfaceRow

logger = get_logger(__name__)

ARPSPOOF_PATH = BIN_DIR_PATH / 'arpspoof.exe'


@dataclass(frozen=True, slots=True)
class _ArpControllerConfig:
    """App-wide wiring for `ArpSpoofingController`."""

    capture_holder: CaptureHolder
    on_failed: Callable[[], None]


class ArpSpoofingController:
    """App-wide owner of the single ARP spoofing thread + arpspoof.exe process.

    Class-level service: there is at most one ARP thread alive at any time.
    Call `configure()` once at startup, then `start()` / `stop()` as needed.
    Safe to call `stop()` when nothing is running.
    """

    _config: ClassVar[_ArpControllerConfig | None] = None
    _stop_event: ClassVar[Event] = Event()
    _thread: ClassVar[Thread | None] = None

    @classmethod
    def configure(cls, capture_holder: CaptureHolder, on_failed: Callable[[], None]) -> None:
        """Wire the controller to the app-wide capture holder and failure callback."""
        cls._config = _ArpControllerConfig(capture_holder=capture_holder, on_failed=on_failed)

    @classmethod
    def start(cls, interface: SelectedInterfaceRow) -> None:
        """Start ARP spoofing on `interface`. Caller must ensure no thread is currently active."""
        if cls._config is None:
            message = 'ArpSpoofingController.start() called before configure()'
            raise RuntimeError(message)
        if cls._thread is not None:
            message = 'ArpSpoofingController.start() called while a previous thread is still alive'
            raise RuntimeError(message)
        cls._stop_event.clear()
        cls._thread = Thread(
            target=arp_spoofing_task,
            name='ARPSpoofingTask',
            args=(interface, cls._config.capture_holder, cls._stop_event, cls._config.on_failed),
            daemon=True,
        )
        cls._thread.start()

    @classmethod
    def stop(cls) -> None:
        """Signal the running thread to exit and wait for it (and `arpspoof.exe`) to die."""
        if cls._thread is None:
            return
        cls._stop_event.set()
        cls._thread.join()
        cls._thread = None


def arp_spoofing_task(
    selected_interface: SelectedInterfaceRow,
    capture_holder: CaptureHolder,
    stop_event: Event,
    on_failed: Callable[[], None],
) -> None:
    """Manage ARP spoofing process lifecycle synchronized with packet capture state.

    Exits when *stop_event* is set (interface switch) or *gui_closed__event* is set (app close).

    Credit: https://github.com/alandau/arpspoof
    """
    if not ARPSPOOF_PATH.is_file():
        logger.warning('Executable not found at: %s', ARPSPOOF_PATH)
        return

    # Validate required interface fields
    if selected_interface.device_name is None:
        logger.error('ARP spoofing cannot start: device_name is None')
        return

    proc: subprocess.Popen[str] | None = None
    startup_probe_timeout = 3.0

    def terminate_process(proc: subprocess.Popen[str]) -> None:
        """Terminate the ARP spoofing process."""
        proc.terminate()
        proc.wait()

    def report_failure(
        stage: str,
        *,
        exit_code: int | None,
        error_output: str | None,
        msgbox_style: msgbox.Style,
        spawn_msgbox_thread: bool,
    ) -> None:
        """Log, notify, and terminate the ARP spoofing task on failure."""
        if exit_code is not None:
            logger.error('%s. Exit code: %s.', stage.capitalize(), exit_code)
        else:
            logger.error('%s.', stage.capitalize())
        if error_output:
            logger.error('Error: %s', error_output)

        message = format_arp_spoofing_failed_message(
            selected_interface=selected_interface,
            exit_code=exit_code,
            error_details=error_output,
        )

        def show_msgbox() -> None:
            msgbox.show(
                title='ARP Spoofing Failed',
                text=message,
                style=msgbox_style,
            )

        if spawn_msgbox_thread:
            Thread(
                target=show_msgbox,
                name=f'ARPSpoof-{stage}-msgbox',
                daemon=True,
            ).start()
        else:
            show_msgbox()
        logger.info('Task terminated due to %s.', stage)

    def _should_exit() -> bool:
        return gui_closed__event.is_set() or stop_event.is_set()

    while not _should_exit():
        # Wait for capture to be running
        while not capture_holder.is_running() and not _should_exit():
            time.sleep(0.5)

        if _should_exit():
            break

        # Start arpspoof process
        if proc is None or proc.poll() is not None:
            cmd: list[str] = [str(ARPSPOOF_PATH), '-i', selected_interface.device_name, selected_interface.ip_address]
            if selected_interface.gateway_ip is not None:
                cmd.append(selected_interface.gateway_ip)
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            log_message = f'Started spoofing on interface {selected_interface.ip_address}'
            if selected_interface.gateway_ip:
                log_message += f' (gateway: {selected_interface.gateway_ip})'
            logger.info(log_message)

            try:
                proc.wait(timeout=startup_probe_timeout)
            except subprocess.TimeoutExpired:
                pass  # Process continues to run
            else:
                exit_code = proc.returncode
                stdout_data, stderr_data = proc.communicate()
                error_output = (stderr_data or stdout_data or '').strip() or None
                proc = None
                report_failure(
                    'startup failure',
                    exit_code=exit_code,
                    error_output=error_output,
                    msgbox_style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONERROR | msgbox.Style.MB_TOPMOST,
                    spawn_msgbox_thread=False,
                )
                on_failed()
                return

        # Wait for capture to stop or process to die
        while proc and capture_holder.is_running() and not _should_exit():
            try:
                proc.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                continue  # Process still healthy; keep monitoring

            exit_code = proc.returncode
            stdout_data, stderr_data = proc.communicate()
            error_output = (stderr_data or stdout_data or '').strip() or None
            proc = None

            if exit_code:
                report_failure(
                    'unexpected process exit',
                    exit_code=exit_code,
                    error_output=error_output,
                    msgbox_style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_TOPMOST,
                    spawn_msgbox_thread=False,
                )
                on_failed()
                return

            logger.info('Process died unexpectedly, respawning...')
            break

        # Stop the process if capture stopped
        if proc and proc.poll() is None:
            terminate_process(proc)
            logger.info('Stopped spoofing.')
            proc = None

    # Final cleanup
    if proc and proc.poll() is None:
        terminate_process(proc)
    logger.info('Task terminated.')
