"""ARP spoofing background task utilities."""

import subprocess
import time
from threading import Thread

from session_sniffer import msgbox
from session_sniffer.background import gui_closed__event
from session_sniffer.capture.tshark_capture import PacketCapture
from session_sniffer.constants.local import BIN_DIR_PATH
from session_sniffer.core import ThreadsExceptionHandler
from session_sniffer.error_messages import format_arp_spoofing_failed_message
from session_sniffer.logging_setup import get_logger
from session_sniffer.networking.interface import SelectedInterface

logger = get_logger(__name__)

ARPSPOOF_PATH = BIN_DIR_PATH / 'arpspoof.exe'


def arp_spoofing_task(
    selected_interface: SelectedInterface,
    capture_obj: PacketCapture,
) -> None:
    """Manage ARP spoofing process lifecycle synchronized with packet capture state.

    Credit: https://github.com/alandau/arpspoof
    """
    with ThreadsExceptionHandler():
        if not ARPSPOOF_PATH.is_file():
            logger.warning('Executable not found at: %s', ARPSPOOF_PATH)
            return

        # Validate required interface fields
        if selected_interface.device_name is None:
            logger.error('ARP spoofing cannot start: device_name is None')
            return
        if selected_interface.ip_address is None:
            logger.error('ARP spoofing cannot start: ip_address is None')
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

            error_message = format_arp_spoofing_failed_message(
                selected_interface=selected_interface,
                exit_code=exit_code,
                error_details=error_output,
            )

            def show_msgbox() -> None:
                msgbox.show(
                    title='ARP Spoofing Failed',
                    text=error_message,
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

        while not gui_closed__event.is_set():
            # Wait for capture to be running
            while not capture_obj.is_running() and not gui_closed__event.is_set():
                time.sleep(0.5)

            if gui_closed__event.is_set():
                break

            # Start arpspoof process
            if proc is None or proc.poll() is not None:
                proc = subprocess.Popen(  # pylint: disable=consider-using-with
                    [str(ARPSPOOF_PATH), '-i', selected_interface.device_name, selected_interface.ip_address],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                logger.info('Started spoofing on interface %s', selected_interface.ip_address)

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
                    return

            # Wait for capture to stop or process to die
            while proc and capture_obj.is_running() and not gui_closed__event.is_set():
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
                        spawn_msgbox_thread=True,
                    )

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
