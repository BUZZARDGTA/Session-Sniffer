"""
Module for packet capture using TShark, including packet processing and handling of TShark crashes.
"""

# Standard Python Libraries
import subprocess
from pathlib import Path
from typing import Callable, NamedTuple, Optional


class PacketFields(NamedTuple):
    frame_time: str
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str


class TSharkCrashException(Exception):
    pass


class Frame:
    def __init__(self, time_epoch: str):
        self.datetime = converts_tshark_packet_timestamp_to_datetime_object(time_epoch)


class IP:
    def __init__(self, src: str, dst: str):
        self.src = src
        self.dst = dst


class UDP:
    def __init__(self, srcport: str, dstport: str):
        self.srcport = int(srcport) if srcport else None
        self.dstport = int(dstport) if dstport else None


class Packet:
    def __init__(self, fields: PacketFields):
        self.frame = Frame(fields.frame_time)
        self.ip = IP(fields.src_ip, fields.dst_ip)
        self.udp = UDP(fields.src_port, fields.dst_port)


class PacketCapture:
    def __init__(
        self,
        interface: str,
        tshark_path: Path,
        tshark_version: str,
        capture_filter: Optional[str] = None,
        display_filter: Optional[str] = None
    ):
        from modules.constants.standard import RE_WIRESHARK_VERSION_PATTERN

        self.interface = interface
        self.tshark_path = tshark_path
        self.tshark_version = tshark_version
        self.capture_filter = capture_filter
        self.display_filter = display_filter

        # Extract Wireshark version
        if not (match := RE_WIRESHARK_VERSION_PATTERN.search(tshark_version)):
            raise ValueError("Could not extract Wireshark version")

        extracted_version = match.group("version")
        if not isinstance(extracted_version, str):
            raise TypeError(f'Expected "str", got "{type(extracted_version).__name__}"')

        self.extracted_tshark_version = extracted_version

        # Build TShark command
        self._tshark_command = [
            str(tshark_path),
            '-l', '-n', '-Q',
            '--log-level', 'critical',
            '-B', '1',
            '-i', interface,
            *(['-f', capture_filter] if capture_filter else []),
            *(['-Y', display_filter] if display_filter else []),
            '-T', 'fields',
            '-E', 'separator=|',
            '-e', 'frame.time_epoch',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
        ]
        self._tshark_process: Optional[subprocess.Popen[str]] = None

    def apply_on_packets(self, callback: Callable[[Packet], None]):
        for packet in self._capture_packets():
            callback(packet)

    def _capture_packets(self):
        def process_tshark_stdout(line: str):
            fields = line.rstrip().split('|', 4)
            return PacketFields(*fields) if len(fields) == 5 else None

        with subprocess.Popen(
            self._tshark_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        ) as process:
            self._tshark_process = process

            if process.stdout:
                # Iterate over stdout line by line as it is being produced
                for line in process.stdout:
                    if (packet_fields := process_tshark_stdout(line)) and all([
                        packet_fields.src_ip, packet_fields.dst_ip, packet_fields.src_port, packet_fields.dst_port
                    ]):
                        yield Packet(packet_fields)

            # After stdout is done, check if there were any errors in stderr
            if process.stderr:
                stderr_output = process.stderr.read()
                if process.returncode != 0:
                    raise TSharkCrashException(f"TShark exited with error code {process.returncode}:\n{stderr_output.strip()}")


def converts_tshark_packet_timestamp_to_datetime_object(packet_frame_time_epoch: str):
    from datetime import datetime

    return datetime.fromtimestamp(timestamp=float(packet_frame_time_epoch))
