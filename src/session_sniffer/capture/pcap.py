r"""Direct ctypes wrapper for Npcap and WinPcap (wpcap.dll).

This module provides low-level packet capture bindings to `wpcap.dll` without
requiring any third-party packet manipulation frameworks.
"""

import ctypes
import ctypes.util
import logging
import os
import sys
import threading
from ctypes import byref, c_char_p, c_int, c_long, c_ubyte, c_uint, c_uint32, c_void_p
from dataclasses import dataclass
from pathlib import Path
from typing import Self, final

from session_sniffer.capture.exceptions import (
    PcapClosedError,
    PcapFilterError,
    PcapOpenError,
    PcapReadError,
    PcapSendError,
)

PCAP_ERRBUF_SIZE = 256
PCAP_NETMASK_UNKNOWN = 0xFFFFFFFF
DLT_EN10MB = 1
DLT_NULL = 0
DLT_RAW = 12

logger = logging.getLogger(__name__)

_PCAP_READ_SUCCESS = 1
_PCAP_READ_TIMEOUT = 0
_PCAP_READ_LOOP_BROKEN = -2


def _get_pcap_error_message(library: ctypes.CDLL, handle: c_void_p) -> str:
    """Retrieve and decode the last pcap error message safely."""
    raw_error = library.pcap_geterr(handle)
    if not isinstance(raw_error, bytes):
        return 'Unknown pcap error'
    return raw_error.decode('utf-8', errors='replace')


class BpfProgram(ctypes.Structure):
    """BPF program filter structure."""

    _fields_ = [
        ('bf_len', c_uint),
        ('bf_insns', c_void_p),
    ]


class PcapPkthdr(ctypes.Structure):
    """Packet header containing timestamp and length metadata."""

    _fields_ = [
        ('tv_sec', c_long),
        ('tv_usec', c_long),
        ('caplen', c_uint32),
        ('len', c_uint32),
    ]


class PcapStat(ctypes.Structure):
    """Capture statistics structure."""

    _fields_ = [
        ('ps_recv', c_uint),
        ('ps_drop', c_uint),
        ('ps_ifdrop', c_uint),
        ('ps_capt', c_uint),
    ]


@dataclass(frozen=True, slots=True)
class RawCapturedPacket:
    """Raw packet received from pcap handle."""

    timestamp_epoch: float
    data: bytes
    datalink_type: int


class _PcapLibrary:  # pylint: disable=too-few-public-methods
    """Lazy loader for wpcap.dll and Packet.dll."""

    _instance: ctypes.CDLL | None = None

    @classmethod
    def get(cls) -> ctypes.CDLL:
        """Load and return the wpcap DLL instance."""
        if cls._instance is not None:
            return cls._instance

        if sys.platform == 'win32':
            system_root = os.environ.get('WINDIR', 'C:\\Windows')
            npcap_directory = Path(system_root) / 'System32' / 'Npcap'

            if npcap_directory.is_dir():
                ctypes.windll.kernel32.SetDllDirectoryW(str(npcap_directory))
                packet_path = npcap_directory / 'Packet.dll'
                wpcap_path = npcap_directory / 'wpcap.dll'
                if packet_path.is_file():
                    ctypes.cdll.LoadLibrary(str(packet_path))
                library = ctypes.cdll.LoadLibrary(str(wpcap_path))
            else:
                library = ctypes.CDLL('wpcap.dll')
        else:
            library = None
            for lib_name in ('libpcap.so.0.8', 'libpcap.so.1', 'libpcap.so'):
                try:
                    library = ctypes.cdll.LoadLibrary(lib_name)
                    break
                except OSError as e:
                    logger.debug('Failed to load libpcap candidate %s: %s', lib_name, e)
                    continue
            if library is None:
                pcap_path = ctypes.util.find_library('pcap')
                if pcap_path:
                    library = ctypes.cdll.LoadLibrary(pcap_path)
                else:
                    error_message = 'libpcap library not found on the system'
                    raise OSError(error_message)

        # Define function signatures
        library.pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]
        library.pcap_open_live.restype = c_void_p

        library.pcap_compile.argtypes = [c_void_p, ctypes.POINTER(BpfProgram), c_char_p, c_int, c_uint32]
        library.pcap_compile.restype = c_int

        library.pcap_setfilter.argtypes = [c_void_p, ctypes.POINTER(BpfProgram)]
        library.pcap_setfilter.restype = c_int

        library.pcap_freecode.argtypes = [ctypes.POINTER(BpfProgram)]
        library.pcap_freecode.restype = None

        library.pcap_next_ex.argtypes = [
            c_void_p,
            ctypes.POINTER(ctypes.POINTER(PcapPkthdr)),
            ctypes.POINTER(ctypes.POINTER(c_ubyte)),
        ]
        library.pcap_next_ex.restype = c_int

        library.pcap_stats.argtypes = [c_void_p, ctypes.POINTER(PcapStat)]
        library.pcap_stats.restype = c_int

        library.pcap_breakloop.argtypes = [c_void_p]
        library.pcap_breakloop.restype = None

        library.pcap_close.argtypes = [c_void_p]
        library.pcap_close.restype = None

        library.pcap_geterr.argtypes = [c_void_p]
        library.pcap_geterr.restype = c_char_p

        library.pcap_datalink.argtypes = [c_void_p]
        library.pcap_datalink.restype = c_int

        library.pcap_sendpacket.argtypes = [c_void_p, ctypes.POINTER(c_ubyte), c_int]
        library.pcap_sendpacket.restype = c_int

        if hasattr(library, 'pcap_setbuff'):
            library.pcap_setbuff.argtypes = [c_void_p, c_int]
            library.pcap_setbuff.restype = c_int

        if hasattr(library, 'pcap_setmintocopy'):
            library.pcap_setmintocopy.argtypes = [c_void_p, c_int]
            library.pcap_setmintocopy.restype = c_int

        cls._instance = library
        return library


def is_pcap_library_available() -> bool:
    """Return `True` if the underlying pcap library can be loaded successfully."""
    try:
        _PcapLibrary.get()
    except (OSError, RuntimeError) as e:
        logger.debug('Pcap library unavailable: %s', e)
        return False
    return True


@final
class PcapHandle:
    """Wrapper managing a live pcap handle lifecycle."""

    def __init__(self, handle: c_void_p, datalink_type: int, *, snaplen: int = 65535) -> None:
        """Initialize with an open pcap handle pointer."""
        self._handle = handle
        self._datalink_type = datalink_type
        self._snaplen = snaplen
        self._is_closed = False
        self._lock = threading.Lock()
        self._header_pointer = ctypes.POINTER(PcapPkthdr)()
        self._data_pointer = ctypes.POINTER(c_ubyte)()

    @classmethod
    def open_live(
        cls,
        device_name: str,
        *,
        snaplen: int = 65535,
        promiscuous: bool = True,
        timeout_milliseconds: int = 100,
        buffer_size: int = 33_554_432,
    ) -> Self:
        r"""Open a live capture handle on the specified network adapter.

        Args:
            device_name: The device path, e.g. `\Device\NPF_{GUID}`.
            snaplen: Maximum bytes to capture per packet.
            promiscuous: Whether to open adapter in promiscuous mode.
            timeout_milliseconds: Read timeout in milliseconds.
            buffer_size: Driver ring buffer size in bytes (default 32 MiB).

        Returns:
            An open `PcapHandle` instance.

        Raises:
            PcapOpenError: If `pcap_open_live` fails.
        """
        library = _PcapLibrary.get()
        error_buffer = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        device_bytes = device_name.encode('utf-8')
        handle = library.pcap_open_live(
            device_bytes,
            c_int(snaplen),
            c_int(1 if promiscuous else 0),
            c_int(timeout_milliseconds),
            error_buffer,
        )

        if not handle:
            error_message = error_buffer.value.decode('utf-8', errors='replace')
            if sys.platform != 'win32' and ('Operation not permitted' in error_message or 'permission' in error_message.lower()):
                permission_hint = (
                    ' (Session Sniffer requires root privileges or CAP_NET_RAW capability: '
                    'try running with sudo or setcap cap_net_raw,cap_net_admin=eip on the python executable)'
                )
                error_message += permission_hint
            raise PcapOpenError(device_name, error_message)

        if buffer_size > 0 and hasattr(library, 'pcap_setbuff'):
            library.pcap_setbuff(handle, c_int(buffer_size))

        if hasattr(library, 'pcap_setmintocopy'):
            library.pcap_setmintocopy(handle, c_int(1))

        datalink_type = library.pcap_datalink(handle)
        return cls(handle, datalink_type, snaplen=snaplen)

    @property
    def datalink_type(self) -> int:
        """Return the datalink type of the capture interface."""
        return self._datalink_type

    def set_filter(self, filter_string: str) -> None:
        """Compile and set a BPF filter on this capture handle.

        Args:
            filter_string: BPF filter string.

        Raises:
            PcapClosedError: If handle is closed.
            PcapFilterError: If BPF compilation or setting fails.
        """
        if self._is_closed:
            raise PcapClosedError

        library = _PcapLibrary.get()
        bpf_program = BpfProgram()
        filter_bytes = filter_string.encode('utf-8')

        compile_result = library.pcap_compile(
            self._handle,
            byref(bpf_program),
            filter_bytes,
            1,  # optimize
            c_uint32(PCAP_NETMASK_UNKNOWN),
        )

        if compile_result:
            error_message = _get_pcap_error_message(library, self._handle)
            raise PcapFilterError(filter_string, error_message)

        try:
            setfilter_result = library.pcap_setfilter(self._handle, byref(bpf_program))
            if setfilter_result:
                error_message = _get_pcap_error_message(library, self._handle)
                raise PcapFilterError(filter_string, error_message)
        finally:
            library.pcap_freecode(byref(bpf_program))

    def test_filter_compilation(self, filter_string: str) -> bool:
        """Test whether a BPF filter string compiles successfully on this handle."""
        if self._is_closed:
            return False

        library = _PcapLibrary.get()
        bpf_program = BpfProgram()
        filter_bytes = filter_string.encode('utf-8')

        compile_result = library.pcap_compile(
            self._handle,
            byref(bpf_program),
            filter_bytes,
            1,  # optimize
            c_uint32(PCAP_NETMASK_UNKNOWN),
        )

        if not compile_result:
            library.pcap_freecode(byref(bpf_program))
            return True
        return False

    def next_packet(self) -> RawCapturedPacket | None:
        """Read the next packet from the capture handle.

        Returns:
            A `RawCapturedPacket` if a packet was captured, or `None` if read timed out.

        Raises:
            PcapReadError: If a non-recoverable capture read error occurs.
        """
        if self._is_closed:
            return None

        library = _PcapLibrary.get()

        result = library.pcap_next_ex(
            self._handle,
            byref(self._header_pointer),
            byref(self._data_pointer),
        )

        if result == _PCAP_READ_SUCCESS:
            if not self._header_pointer or not self._data_pointer:
                return None

            header = self._header_pointer.contents
            captured_length = int(header.caplen)
            if not 0 < captured_length <= self._snaplen:
                return None

            epoch_seconds = float(header.tv_sec) + (float(header.tv_usec) / 1_000_000.0)
            packet_bytes = ctypes.string_at(self._data_pointer, captured_length)

            return RawCapturedPacket(
                timestamp_epoch=epoch_seconds,
                data=packet_bytes,
                datalink_type=self._datalink_type,
            )

        if result in (_PCAP_READ_TIMEOUT, _PCAP_READ_LOOP_BROKEN):
            return None

        error_message = _get_pcap_error_message(library, self._handle)
        raise PcapReadError(error_message)

    def next_raw_frame(self) -> bytes | None:
        """Read the next packet data from the capture handle without metadata overhead.

        Returns:
            The complete raw frame bytes if a packet was captured, or `None` if read timed out or loop was broken.

        Raises:
            PcapReadError: If a non-recoverable capture read error occurs.
        """
        if self._is_closed:
            return None

        library = _PcapLibrary.get()

        result = library.pcap_next_ex(
            self._handle,
            byref(self._header_pointer),
            byref(self._data_pointer),
        )

        if result == _PCAP_READ_SUCCESS:
            if not self._header_pointer or not self._data_pointer:
                return None

            header = self._header_pointer.contents
            captured_length = int(header.caplen)
            total_length = int(header.len)
            if captured_length != total_length or not 0 < captured_length <= self._snaplen:
                return None

            return ctypes.string_at(self._data_pointer, captured_length)

        if result in (_PCAP_READ_TIMEOUT, _PCAP_READ_LOOP_BROKEN):
            return None

        error_message = _get_pcap_error_message(library, self._handle)
        raise PcapReadError(error_message)

    def get_drop_count(self) -> int | None:
        """Return cumulative packet drop statistics (`ps_drop` + `ps_ifdrop`)."""
        if self._is_closed:
            return None

        library = _PcapLibrary.get()
        stats = PcapStat()
        if library.pcap_stats(self._handle, byref(stats)):
            return None
        return int(stats.ps_drop) + int(stats.ps_ifdrop)

    def break_loop(self) -> None:
        """Break the capture read loop."""
        if not self._is_closed:
            library = _PcapLibrary.get()
            library.pcap_breakloop(self._handle)

    def send_packet(self, data: bytes) -> None:
        """Inject a raw packet onto the network via this capture handle.

        Args:
            data: The complete link-layer frame to send.

        Raises:
            PcapClosedError: If handle is closed.
            PcapSendError: If packet injection fails.
        """
        if self._is_closed:
            raise PcapClosedError

        if not data:
            return

        library = _PcapLibrary.get()
        packet_buffer = (c_ubyte * len(data)).from_buffer_copy(data)
        result = library.pcap_sendpacket(self._handle, packet_buffer, len(data))
        if result:
            error_message = _get_pcap_error_message(library, self._handle)
            raise PcapSendError(error_message)

    def close(self) -> None:
        """Close the underlying pcap handle."""
        with self._lock:
            if not self._is_closed:
                self._is_closed = True
                library = _PcapLibrary.get()
                library.pcap_close(self._handle)
