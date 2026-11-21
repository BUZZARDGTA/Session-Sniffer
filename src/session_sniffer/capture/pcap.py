r"""Direct ctypes wrapper for Npcap and WinPcap (wpcap.dll).

This module provides low-level packet capture bindings to `wpcap.dll` without
requiring any third-party packet manipulation frameworks.
"""

import ctypes
import ctypes.util
import functools
import logging
import os
import selectors
import sys
import threading
from ctypes import byref, c_char_p, c_int, c_long, c_ubyte, c_uint, c_uint32, c_void_p
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self, cast, final

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


def _get_pcap_status_message(library: ctypes.CDLL, status: int) -> str:
    """Decode a libpcap status code via `pcap_statustostr`."""
    raw_status = library.pcap_statustostr(c_int(status))
    if not isinstance(raw_status, bytes):
        return f'pcap error code {status}'
    return raw_status.decode('utf-8', errors='replace')


@dataclass(slots=True)
class _PosixPollState:
    """Non-blocking POSIX selector and wakeup pipe for a `PcapHandle`."""

    selector: selectors.BaseSelector
    wake_read_fd: int
    wake_write_fd: int
    timeout_seconds: float
    wake_lock: threading.Lock = field(default_factory=threading.Lock)


class BpfProgram(ctypes.Structure):
    """BPF program filter structure."""

    _fields_ = [
        ('bf_len', c_uint),
        ('bf_insns', c_void_p),
    ]


if sys.platform == 'darwin':

    class _Timeval(ctypes.Structure):
        """macOS LP64 timeval structure (`time_t` + `suseconds_t`)."""

        _fields_ = [
            ('tv_sec', c_long),
            ('tv_usec', ctypes.c_int32),
        ]
else:

    class _Timeval(ctypes.Structure):
        """Win32 and Linux timeval structure."""

        _fields_ = [
            ('tv_sec', c_long),
            ('tv_usec', c_long),
        ]


class PcapPkthdr(ctypes.Structure):
    """Packet header containing timestamp and length metadata."""

    _fields_ = [
        ('ts', _Timeval),
        ('caplen', c_uint32),
        ('len', c_uint32),
    ]


class PcapStat(ctypes.Structure):
    """Capture statistics structure (includes Win32 Npcap trailing fields)."""

    _fields_ = [
        ('ps_recv', c_uint),
        ('ps_drop', c_uint),
        ('ps_ifdrop', c_uint),
        ('ps_capt', c_uint),
        ('ps_sent', c_uint),
        ('ps_netdrop', c_uint),
    ]


@dataclass(frozen=True, slots=True)
class RawCapturedPacket:
    """Raw packet received from pcap handle."""

    timestamp_epoch: float
    data: bytes
    datalink_type: int


@functools.cache
def _load_pcap_library() -> ctypes.CDLL:
    """Load the pcap library (wpcap.dll and Packet.dll, or libpcap) once and return the configured instance."""
    if sys.platform == 'win32':
        system_root = os.environ.get('WINDIR', 'C:\\Windows')
        npcap_directory = Path(system_root) / 'System32' / 'Npcap'

        if npcap_directory.is_dir():
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel32.SetDllDirectoryW.argtypes = [ctypes.c_wchar_p]
            kernel32.SetDllDirectoryW.restype = c_int
            kernel32.SetDllDirectoryW(str(npcap_directory))
            packet_path = npcap_directory / 'Packet.dll'
            wpcap_path = npcap_directory / 'wpcap.dll'
            if packet_path.is_file():
                ctypes.cdll.LoadLibrary(str(packet_path))
            library = ctypes.cdll.LoadLibrary(str(wpcap_path))
        else:
            library = ctypes.CDLL('wpcap.dll')
    else:
        library: ctypes.CDLL | None = None
        candidates = ('libpcap.dylib', '/usr/lib/libpcap.dylib') if sys.platform == 'darwin' else ('libpcap.so.0.8', 'libpcap.so.1', 'libpcap.so')
        for lib_name in candidates:
            try:
                library = ctypes.cdll.LoadLibrary(lib_name)
                break
            except OSError as e:
                logger.debug('Failed to load libpcap candidate %s: %s', lib_name, e)
                continue
        if library is None:
            pcap_path = ctypes.util.find_library('pcap')
            if pcap_path is not None and pcap_path:
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

    if sys.platform != 'win32':
        library.pcap_create.argtypes = [c_char_p, c_char_p]
        library.pcap_create.restype = c_void_p

        library.pcap_set_snaplen.argtypes = [c_void_p, c_int]
        library.pcap_set_snaplen.restype = c_int

        library.pcap_set_promisc.argtypes = [c_void_p, c_int]
        library.pcap_set_promisc.restype = c_int

        library.pcap_set_timeout.argtypes = [c_void_p, c_int]
        library.pcap_set_timeout.restype = c_int

        library.pcap_set_immediate_mode.argtypes = [c_void_p, c_int]
        library.pcap_set_immediate_mode.restype = c_int

        library.pcap_activate.argtypes = [c_void_p]
        library.pcap_activate.restype = c_int

        library.pcap_statustostr.argtypes = [c_int]
        library.pcap_statustostr.restype = c_char_p

        library.pcap_setnonblock.argtypes = [c_void_p, c_int, c_char_p]
        library.pcap_setnonblock.restype = c_int

        library.pcap_get_selectable_fd.argtypes = [c_void_p]
        library.pcap_get_selectable_fd.restype = c_int

    return library


def is_pcap_library_available() -> bool:
    """Return `True` if the underlying pcap library can be loaded successfully."""
    try:
        _load_pcap_library()
    except (OSError, RuntimeError) as e:
        logger.debug('Pcap library unavailable: %s', e)
        return False
    return True


def can_open_pcap_device(device_name: str) -> bool:
    """Return whether the specified pcap device can currently be opened for live capture."""
    try:
        library = _load_pcap_library()
    except (OSError, RuntimeError):
        return False
    error_buffer = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    handle = library.pcap_open_live(
        device_name.encode('utf-8'),
        c_int(65535),
        c_int(0),
        c_int(100),
        error_buffer,
    )
    if not handle:
        return False
    library.pcap_close(handle)
    return True


def _open_posix_handle(
    library: ctypes.CDLL,
    device_name: str,
    *,
    snaplen: int,
    promiscuous: bool,
    timeout_milliseconds: int,
) -> tuple[c_void_p, _PosixPollState | None]:
    """Open, activate, and configure a non-blocking immediate-mode libpcap handle on POSIX."""
    error_buffer = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    handle = library.pcap_create(device_name.encode('utf-8'), error_buffer)
    if not handle:
        error_message = error_buffer.value.decode('utf-8', errors='replace')
        raise PcapOpenError(device_name, error_message)

    library.pcap_set_snaplen(handle, c_int(snaplen))
    library.pcap_set_promisc(handle, c_int(1 if promiscuous else 0))
    library.pcap_set_timeout(handle, c_int(timeout_milliseconds))
    library.pcap_set_immediate_mode(handle, c_int(1))

    activate_status = int(library.pcap_activate(handle))
    if activate_status < 0:
        status_message = _get_pcap_status_message(library, activate_status)
        detail_message = _get_pcap_error_message(library, handle)
        library.pcap_close(handle)
        error_message = (
            f'{status_message}: {detail_message}'
            if detail_message and detail_message not in status_message and detail_message != 'Unknown pcap error'
            else status_message
        )
        raise PcapOpenError(device_name, error_message)
    if activate_status > 0:
        logger.debug('pcap_activate warning on %s: %s', device_name, _get_pcap_status_message(library, activate_status))

    poll_state: _PosixPollState | None = None
    if sys.platform != 'win32':
        nonblock_err = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        if not library.pcap_setnonblock(handle, c_int(1), nonblock_err):
            selectable_fd = int(library.pcap_get_selectable_fd(handle))
            if selectable_fd >= 0:
                wake_read_fd, wake_write_fd = os.pipe()
                os.set_blocking(wake_read_fd, False)
                os.set_blocking(wake_write_fd, False)
                selector = selectors.DefaultSelector()
                selector.register(selectable_fd, selectors.EVENT_READ, data=False)
                selector.register(wake_read_fd, selectors.EVENT_READ, data=True)
                poll_state = _PosixPollState(
                    selector=selector,
                    wake_read_fd=wake_read_fd,
                    wake_write_fd=wake_write_fd,
                    timeout_seconds=max(0.001, timeout_milliseconds / 1000.0),
                )
        else:
            logger.debug(
                'Failed to enable non-blocking mode on %s: %s',
                device_name,
                nonblock_err.value.decode('utf-8', errors='replace'),
            )
    return cast('c_void_p', handle), poll_state


@final
class PcapHandle:
    """Wrapper managing a live pcap handle lifecycle."""

    def __init__(
        self,
        handle: c_void_p,
        datalink_type: int,
        *,
        snaplen: int = 65535,
        poll_state: _PosixPollState | None = None,
    ) -> None:
        """Initialize with an open pcap handle pointer."""
        self._handle = handle
        self._datalink_type = datalink_type
        self._snaplen = snaplen
        self._is_closed = False
        self._loop_broken = False
        self._poll_state = poll_state
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
    ) -> Self:
        r"""Open a live capture handle on the specified network adapter.

        Args:
            device_name: The device path, e.g. `\Device\NPF_{GUID}`.
            snaplen: Maximum bytes to capture per packet.
            promiscuous: Whether to open adapter in promiscuous mode.
            timeout_milliseconds: Read timeout in milliseconds.

        Returns:
            An open `PcapHandle` instance.

        Raises:
            PcapOpenError: If opening or activating the pcap handle fails.
        """
        library = _load_pcap_library()
        poll_state: _PosixPollState | None = None
        if sys.platform == 'win32':
            error_buffer = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
            handle = library.pcap_open_live(
                device_name.encode('utf-8'),
                c_int(snaplen),
                c_int(1 if promiscuous else 0),
                c_int(timeout_milliseconds),
                error_buffer,
            )
            if not handle:
                error_message = error_buffer.value.decode('utf-8', errors='replace')
                raise PcapOpenError(device_name, error_message)

            if hasattr(library, 'pcap_setbuff'):
                library.pcap_setbuff(handle, c_int(33_554_432))

            if hasattr(library, 'pcap_setmintocopy'):
                library.pcap_setmintocopy(handle, c_int(1))
        else:
            handle, poll_state = _open_posix_handle(
                library,
                device_name,
                snaplen=snaplen,
                promiscuous=promiscuous,
                timeout_milliseconds=timeout_milliseconds,
            )

        datalink_type = library.pcap_datalink(handle)
        return cls(handle, datalink_type, snaplen=snaplen, poll_state=poll_state)

    @property
    def datalink_type(self) -> int:
        """Return the datalink type of the capture interface."""
        return self._datalink_type

    def _compile_bpf_locked(self, library: ctypes.CDLL, filter_string: str) -> BpfProgram | None:
        """Compile *filter_string* into a `BpfProgram` (caller must hold `self._lock`)."""
        bpf_program = BpfProgram()
        compile_result = library.pcap_compile(
            self._handle,
            byref(bpf_program),
            filter_string.encode('utf-8'),
            1,  # optimize
            c_uint32(PCAP_NETMASK_UNKNOWN),
        )
        return bpf_program if not compile_result else None

    def set_filter(self, filter_string: str) -> None:
        """Compile and set a BPF filter on this capture handle.

        Args:
            filter_string: BPF filter string.

        Raises:
            PcapClosedError: If handle is closed.
            PcapFilterError: If BPF compilation or setting fails.
        """
        with self._lock:
            if self._is_closed:
                raise PcapClosedError

            library = _load_pcap_library()
            bpf_program = self._compile_bpf_locked(library, filter_string)
            if bpf_program is None:
                error_message = _get_pcap_error_message(library, self._handle)
                raise PcapFilterError(filter_string, error_message)

            try:
                if library.pcap_setfilter(self._handle, byref(bpf_program)):
                    error_message = _get_pcap_error_message(library, self._handle)
                    raise PcapFilterError(filter_string, error_message)
            finally:
                library.pcap_freecode(byref(bpf_program))

    def test_filter_compilation(self, filter_string: str) -> bool:
        """Test whether a BPF filter string compiles successfully on this handle."""
        with self._lock:
            if self._is_closed:
                return False

            library = _load_pcap_library()
            bpf_program = self._compile_bpf_locked(library, filter_string)
            if bpf_program is not None:
                library.pcap_freecode(byref(bpf_program))
                return True
            return False

    def _read_next_packet_header_locked(self) -> PcapPkthdr | None:
        """Read the next packet header via `pcap_next_ex` (caller must hold `self._lock`)."""
        if self._is_closed or self._loop_broken:
            return None

        library = _load_pcap_library()
        result = library.pcap_next_ex(
            self._handle,
            byref(self._header_pointer),
            byref(self._data_pointer),
        )
        if result == _PCAP_READ_SUCCESS:
            if not self._header_pointer or not self._data_pointer:
                return None
            return self._header_pointer.contents

        if result in (_PCAP_READ_TIMEOUT, _PCAP_READ_LOOP_BROKEN):
            return None

        error_message = _get_pcap_error_message(library, self._handle)
        raise PcapReadError(error_message)

    def _wait_for_packet_ready(self) -> bool:
        """Wait for the non-blocking POSIX pcap fd to become readable, wake on `break_loop`, or time out.

        Must be called without holding `self._lock`.
        """
        poll_state = self._poll_state
        if poll_state is None or self._is_closed or self._loop_broken:
            return False

        try:
            ready_events = poll_state.selector.select(poll_state.timeout_seconds)
        except (OSError, ValueError):
            return False

        is_pcap_ready = False
        for key, _mask in ready_events:
            if key.data:
                return False
            is_pcap_ready = True
        return is_pcap_ready

    def _try_read_packet_locked(self) -> RawCapturedPacket | None:
        """Attempt a single packet read while holding `self._lock`."""
        header = self._read_next_packet_header_locked()
        if header is None:
            return None

        captured_length = int(header.caplen)
        if not 0 < captured_length <= self._snaplen:
            return None

        epoch_seconds = float(header.ts.tv_sec) + (float(header.ts.tv_usec) / 1_000_000.0)
        packet_bytes = ctypes.string_at(self._data_pointer, captured_length)

        return RawCapturedPacket(
            timestamp_epoch=epoch_seconds,
            data=packet_bytes,
            datalink_type=self._datalink_type,
        )

    def _try_read_raw_frame_locked(self) -> bytes | None:
        """Attempt a single raw frame read while holding `self._lock`."""
        header = self._read_next_packet_header_locked()
        if header is None:
            return None

        captured_length = int(header.caplen)
        total_length = int(header.len)
        if captured_length != total_length or not 0 < captured_length <= self._snaplen:
            return None

        return ctypes.string_at(self._data_pointer, captured_length)

    def next_packet(self) -> RawCapturedPacket | None:
        """Read the next packet from the capture handle.

        Returns:
            A `RawCapturedPacket` if a packet was captured, or `None` if read timed out.

        Raises:
            PcapReadError: If a non-recoverable capture read error occurs.
        """
        with self._lock:
            packet = self._try_read_packet_locked()
        if packet is not None or self._poll_state is None:
            return packet

        if not self._wait_for_packet_ready():
            return None

        with self._lock:
            return self._try_read_packet_locked()

    def next_raw_frame(self) -> bytes | None:
        """Read the next packet data from the capture handle without metadata overhead.

        Returns:
            The complete raw frame bytes if a packet was captured, or `None` if read timed out or loop was broken.

        Raises:
            PcapReadError: If a non-recoverable capture read error occurs.
        """
        with self._lock:
            frame = self._try_read_raw_frame_locked()
        if frame is not None or self._poll_state is None:
            return frame

        if not self._wait_for_packet_ready():
            return None

        with self._lock:
            return self._try_read_raw_frame_locked()

    def get_drop_count(self) -> int | None:
        """Return cumulative packet drop statistics (`ps_drop` + `ps_ifdrop`)."""
        with self._lock:
            if self._is_closed:
                return None

            library = _load_pcap_library()
            stats = PcapStat()
            if library.pcap_stats(self._handle, byref(stats)):
                return None
            return int(stats.ps_drop) + int(stats.ps_ifdrop)

    def break_loop(self) -> None:
        """Break the capture read loop and wake any blocked POSIX poll immediately."""
        self._loop_broken = True
        poll_state = self._poll_state
        if poll_state is not None:
            with poll_state.wake_lock:
                if poll_state.wake_write_fd >= 0:
                    try:
                        os.write(poll_state.wake_write_fd, b'\x01')
                    except OSError as e:
                        logger.debug('Failed writing to pcap wakeup pipe: %s', e)
        if not self._is_closed:
            library = _load_pcap_library()
            library.pcap_breakloop(self._handle)

    def send_packet(self, data: bytes) -> None:
        """Inject a raw packet onto the network via this capture handle.

        Args:
            data: The complete link-layer frame to send.

        Raises:
            PcapClosedError: If handle is closed.
            PcapSendError: If packet injection fails.
        """
        with self._lock:
            if self._is_closed:
                raise PcapClosedError

            if not data:
                return

            library = _load_pcap_library()
            packet_buffer = (c_ubyte * len(data)).from_buffer_copy(data)
            result = library.pcap_sendpacket(self._handle, packet_buffer, len(data))
            if result:
                error_message = _get_pcap_error_message(library, self._handle)
                raise PcapSendError(error_message)

    def close(self) -> None:
        """Close the underlying pcap handle and release any POSIX wakeup pipe descriptors."""
        with self._lock:
            if not self._is_closed:
                self._is_closed = True
                self._loop_broken = True
                library = _load_pcap_library()
                library.pcap_close(self._handle)
                poll_state = self._poll_state
                if poll_state is not None:
                    with poll_state.wake_lock:
                        try:
                            poll_state.selector.close()
                        except OSError as e:
                            logger.debug('Failed to close pcap selector: %s', e)
                        for fd in (poll_state.wake_read_fd, poll_state.wake_write_fd):
                            if fd >= 0:
                                try:
                                    os.close(fd)
                                except OSError as e:
                                    logger.debug('Failed to close pcap wakeup fd %d: %s', fd, e)
                        poll_state.wake_read_fd = -1
                        poll_state.wake_write_fd = -1
