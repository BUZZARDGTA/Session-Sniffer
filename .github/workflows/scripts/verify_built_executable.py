"""Verify built PyInstaller executables: archive integrity, platform setup commands, and live smoke test."""

import argparse
import json
import os
import posixpath
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path

_PYI_ARCHIVE_MAGIC = b'MEI\014\013\012\013\016'
_PYI_COOKIE_FORMAT = '!8sIIII64s'
_PYI_COOKIE_SIZE = struct.calcsize(_PYI_COOKIE_FORMAT)
_PYI_TOC_ENTRY_FORMAT = '!IIIIBB'
_PYI_TOC_ENTRY_HEADER_SIZE = struct.calcsize(_PYI_TOC_ENTRY_FORMAT)
_PYI_SYMLINK_TYPECODE = ord('n')
_MAX_SYMLINK_HOPS = 8
_SMOKE_TEST_TIMEOUT_SECONDS = 120
_MACOS_QUARANTINE_VALUE = '0081;00000000;Safari;'
_LINUX_REQUIRED_CAPABILITIES = 'cap_net_raw,cap_net_admin,cap_sys_ptrace=eip'


@dataclass(frozen=True)
class _TocEntry:
    """Parsed PyInstaller CArchive table-of-contents entry."""

    name: str
    dpos: int
    dlen: int
    ulen: int
    cflag: int
    typecode: int


def _resolve_tool(name: str) -> str:
    """Resolve an external command on PATH (including POSIX sbin directories) or fail with a clear error."""
    search_path = os.environ.get('PATH', '')
    if sys.platform != 'win32':
        search_path = os.pathsep.join(part for part in (search_path, '/usr/sbin', '/sbin') if part)
    resolved = shutil.which(name, path=search_path)
    if resolved is None:
        message = f'Required verification command not found on PATH: {name}'
        raise FileNotFoundError(message)
    return resolved


def _run_checked(command: list[str], *, cwd: Path | None = None, timeout: int = _SMOKE_TEST_TIMEOUT_SECONDS) -> subprocess.CompletedProcess[str]:
    """Run a verification command and raise with captured output on failure."""
    sys.stdout.write(f'+ {" ".join(command)}\n')
    sys.stdout.flush()
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    sys.stdout.flush()
    sys.stderr.flush()
    if result.returncode:
        message = f'Command failed with exit code {result.returncode}: {" ".join(command)}'
        raise RuntimeError(message)
    return result


def _parse_carchive_toc(data: bytes) -> tuple[int, list[_TocEntry]]:
    """Locate and parse the embedded PyInstaller CArchive PKG table of contents."""
    cookie_offset = data.rfind(_PYI_ARCHIVE_MAGIC)
    if cookie_offset < 0:
        message = 'Could not locate PyInstaller embedded PKG archive cookie.'
        raise ValueError(message)

    cookie_end = cookie_offset + _PYI_COOKIE_SIZE
    if cookie_end > len(data):
        message = 'Truncated PyInstaller PKG archive cookie.'
        raise ValueError(message)

    _magic, pkg_len, toc_off, toc_len, _pyver, _pylibname = struct.unpack(
        _PYI_COOKIE_FORMAT,
        data[cookie_offset:cookie_end],
    )
    pkg_start = cookie_end - pkg_len
    if pkg_start < 0 or pkg_start + toc_off + toc_len > len(data):
        message = f'Invalid PyInstaller PKG offsets (pkg_start={pkg_start}, toc_off={toc_off}, toc_len={toc_len}).'
        raise ValueError(message)

    entries: list[_TocEntry] = []
    pos = pkg_start + toc_off
    end = pos + toc_len
    while pos < end:
        if pos + _PYI_TOC_ENTRY_HEADER_SIZE > end:
            message = 'Truncated PyInstaller TOC entry header.'
            raise ValueError(message)
        entry_len, dpos, dlen, ulen, cflag, typecode = struct.unpack(
            _PYI_TOC_ENTRY_FORMAT,
            data[pos : pos + _PYI_TOC_ENTRY_HEADER_SIZE],
        )
        if entry_len < _PYI_TOC_ENTRY_HEADER_SIZE or pos + entry_len > end:
            message = f'Invalid PyInstaller TOC entry length: {entry_len}'
            raise ValueError(message)
        raw_name = data[pos + _PYI_TOC_ENTRY_HEADER_SIZE : pos + entry_len]
        name = raw_name.rstrip(b'\x00').decode('utf-8')
        entries.append(_TocEntry(name=name, dpos=dpos, dlen=dlen, ulen=ulen, cflag=cflag, typecode=typecode))
        pos += entry_len

    return pkg_start, entries


def _resolve_toc_symlink(link_name: str, target: str, symlinks: dict[str, str]) -> str:
    """Resolve a TOC symlink path across chained internal symlinks."""
    parent_dir = posixpath.dirname(link_name)
    resolved = posixpath.normpath(posixpath.join(parent_dir, target)) if parent_dir else posixpath.normpath(target)
    for _ in range(_MAX_SYMLINK_HOPS):
        parts = resolved.split('/')
        expanded = False
        for prefix_len in range(1, len(parts) + 1):
            prefix = '/'.join(parts[:prefix_len])
            if prefix in symlinks:
                prefix_parent = posixpath.dirname(prefix)
                link_target = symlinks[prefix]
                new_prefix = posixpath.normpath(posixpath.join(prefix_parent, link_target)) if prefix_parent else posixpath.normpath(link_target)
                remainder = parts[prefix_len:]
                resolved = posixpath.normpath('/'.join([new_prefix, *remainder])) if remainder else new_prefix
                expanded = True
                break
        if not expanded:
            break
    return resolved


def verify_pyinstaller_archive(executable_path: Path, *, check_symlinks: bool = True) -> None:
    """Decompress and verify every entry and internal symlink in the embedded PyInstaller PKG archive."""
    data = executable_path.read_bytes()
    if not data:
        message = f'Built executable is empty: {executable_path}'
        raise ValueError(message)

    pkg_start, entries = _parse_carchive_toc(data)
    if not entries:
        message = f'Embedded PyInstaller archive has no TOC entries: {executable_path}'
        raise ValueError(message)

    compressed_count = 0
    symlinks: dict[str, str] = {}
    all_paths: set[str] = set()

    for entry in entries:
        normalized_name = entry.name.replace('\\', '/')
        all_paths.add(normalized_name)
        parent = posixpath.dirname(normalized_name)
        while parent and parent not in all_paths:
            all_paths.add(parent)
            parent = posixpath.dirname(parent)

        entry_start = pkg_start + entry.dpos
        entry_end = entry_start + entry.dlen
        if entry_start < pkg_start or entry_end > len(data):
            message = f'Archive entry out of bounds: {entry.name}'
            raise ValueError(message)

        raw_payload = data[entry_start:entry_end]
        if entry.cflag == 1:
            compressed_count += 1
            decompressor = zlib.decompressobj()
            decompressed = decompressor.decompress(raw_payload) + decompressor.flush()
            if not decompressor.eof:
                message = f'Compressed archive entry did not reach Z_STREAM_END (EOF): {entry.name}'
                raise ValueError(message)
            if decompressor.unused_data:
                message = f'Compressed archive entry has {len(decompressor.unused_data)} unexpected trailing bytes: {entry.name}'
                raise ValueError(message)
            if len(decompressed) != entry.ulen:
                message = f'Decompressed length mismatch for {entry.name}: expected {entry.ulen}, got {len(decompressed)}'
                raise ValueError(message)
            payload = decompressed
        else:
            if len(raw_payload) != entry.ulen:
                message = f'Uncompressed length mismatch for {entry.name}: expected {entry.ulen}, got {len(raw_payload)}'
                raise ValueError(message)
            payload = raw_payload

        if entry.typecode == _PYI_SYMLINK_TYPECODE:
            target = payload.rstrip(b'\x00').decode('utf-8')
            symlinks[normalized_name] = target

    if check_symlinks:
        dangling_symlinks: list[str] = []
        for link_name, target in sorted(symlinks.items()):
            if target.startswith('/'):
                continue
            resolved = _resolve_toc_symlink(link_name, target, symlinks)
            if resolved not in all_paths:
                dangling_symlinks.append(f'{link_name} -> {target} (resolved: {resolved})')
        if dangling_symlinks:
            details = '\n  '.join(dangling_symlinks)
            message = f'Dangling internal symlinks found in PyInstaller archive:\n  {details}'
            raise ValueError(message)

    sys.stdout.write(
        f'Archive integrity OK: {executable_path.name} '
        f'({len(data):,} bytes, {len(entries)} TOC entries, {compressed_count} compressed, {len(symlinks)} symlinks)\n',
    )
    sys.stdout.flush()


def _verify_macos_codesign(executable_path: Path) -> None:
    """Verify the Mach-O code signature on macOS."""
    codesign = _resolve_tool('codesign')
    _run_checked([codesign, '--verify', '--strict', '--verbose=2', str(executable_path)])


def _prepare_and_build_launch_command(
    copied_executable: Path,
    result_path: Path,
) -> tuple[list[str], bool]:
    """Run documented OS setup commands on a temporary copy and return (command, require_capture_permissions)."""
    smoke_args = ['--smoke-test', f'--smoke-test-output={result_path}']

    if sys.platform == 'darwin':
        chmod = _resolve_tool('chmod')
        xattr = _resolve_tool('xattr')
        sudo = _resolve_tool('sudo')

        _run_checked([chmod, '+x', str(copied_executable)])
        # Exercise the documented Gatekeeper quarantine removal command on the temporary copy.
        _run_checked([xattr, '-w', 'com.apple.quarantine', _MACOS_QUARANTINE_VALUE, str(copied_executable)])
        _run_checked([xattr, '-d', 'com.apple.quarantine', str(copied_executable)])

        bpf_devices = sorted(str(path) for path in Path('/dev').glob('bpf*'))
        if not bpf_devices:
            message = 'No /dev/bpf* devices found on macOS runner.'
            raise RuntimeError(message)
        _run_checked([sudo, chmod, '666', *bpf_devices])
        return [str(copied_executable), *smoke_args, '--require-capture-permissions'], True

    if sys.platform == 'linux':
        chmod = _resolve_tool('chmod')
        sudo = _resolve_tool('sudo')
        setcap = _resolve_tool('setcap')
        xvfb_run = _resolve_tool('xvfb-run')

        _run_checked([chmod, '+x', str(copied_executable)])
        _run_checked([sudo, setcap, _LINUX_REQUIRED_CAPABILITIES, str(copied_executable)])
        return [xvfb_run, '--auto-servernum', str(copied_executable), *smoke_args, '--require-capture-permissions'], True

    return [str(copied_executable), *smoke_args], False


def verify_live_execution(executable_path: Path) -> None:
    """Run platform setup commands and execute the packaged binary in smoke-test mode."""
    if sys.platform == 'darwin':
        _verify_macos_codesign(executable_path)

    with tempfile.TemporaryDirectory(prefix='session_sniffer_verify_') as temp_dir:
        temp_root = Path(temp_dir)
        copied_executable = temp_root / executable_path.name
        shutil.copy2(executable_path, copied_executable)
        result_path = temp_root / 'smoke_test_result.json'

        command, require_capture_permissions = _prepare_and_build_launch_command(copied_executable, result_path)
        _run_checked(command, cwd=temp_root)

        if not result_path.is_file():
            message = f'Smoke test did not produce expected result file: {result_path}'
            raise RuntimeError(message)

        raw_result = json.loads(result_path.read_text(encoding='utf-8'))
        if not isinstance(raw_result, dict):
            message = f'Unexpected smoke-test output payload: {raw_result!r}'
            raise TypeError(message)

        if raw_result.get('status') != 'ok':
            message = f'Smoke test reported non-ok status: {raw_result!r}'
            raise RuntimeError(message)
        if raw_result.get('frozen') is not True:
            message = f'Smoke test did not run inside frozen PyInstaller executable: {raw_result!r}'
            raise RuntimeError(message)
        if raw_result.get('platform') != sys.platform:
            message = f'Smoke test platform mismatch: expected {sys.platform!r}, got {raw_result.get("platform")!r}'
            raise RuntimeError(message)
        if not raw_result.get('qt_platform'):
            message = f'Smoke test Qt platform plugin is empty: {raw_result!r}'
            raise RuntimeError(message)
        if require_capture_permissions and raw_result.get('capture_ready') is not True:
            message = f'Smoke test capture permissions check failed: {raw_result!r}'
            raise RuntimeError(message)

        sys.stdout.write(f'Live executable smoke test OK: {json.dumps(raw_result)}\n')
        sys.stdout.flush()


def main() -> None:
    """Parse arguments and verify a built PyInstaller executable."""
    parser = argparse.ArgumentParser(description='Verify a built Session Sniffer PyInstaller executable.')
    parser.add_argument('executable', type=Path, help='Path to the built PyInstaller executable')
    parser.add_argument(
        '--archive-only',
        action='store_true',
        help='Only verify the embedded PyInstaller PKG archive without executing the binary',
    )
    parser.add_argument(
        '--allow-dangling-symlinks',
        action='store_true',
        help='Skip failing on dangling internal TOC symlinks during archive inspection',
    )
    args = parser.parse_args()

    executable_path = Path(args.executable).resolve()
    if not executable_path.is_file():
        message = f'Built executable not found: {executable_path}'
        raise FileNotFoundError(message)

    verify_pyinstaller_archive(executable_path, check_symlinks=not args.allow_dangling_symlinks)
    if not args.archive_only:
        verify_live_execution(executable_path)


if __name__ == '__main__':
    main()
