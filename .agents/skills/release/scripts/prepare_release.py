"""Automate Session Sniffer release version computation, lockfile sync, and CRLF enforcement."""

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

EXPECTED_LS_REMOTE_COLUMNS = 2
VERSION_PATTERN = re.compile(
    r'^(?P<prefix>v(?P<base>\d+\.\d+\.\d+)(?:rc\.(?P<rc>\d+))?)\+(?P<build>\d{8}\.\d{4})$',
)
PYPROJECT_VERSION_LINE_PATTERN = re.compile(r'^(version\s*=\s*)"[^"]+"', re.MULTILINE)


@dataclass(frozen=True, slots=True)
class ParsedReleaseVersion:
    """Structured representation of a Session Sniffer version string."""

    full_version: str
    version_prefix: str
    base_version: str
    rc_number: int | None
    build_timestamp: str


def get_repo_root() -> Path:
    """Return the repository root directory."""
    return Path(__file__).resolve().parents[4]


def parse_release_version(version_string: str) -> ParsedReleaseVersion:
    """Parse and validate a Session Sniffer version string from `pyproject.toml`."""
    match = VERSION_PATTERN.match(version_string.strip())
    if match is None:
        message = f'Invalid Session Sniffer version format: {version_string!r}'
        raise ValueError(message)

    rc_raw = match.group('rc')
    return ParsedReleaseVersion(
        full_version=version_string.strip(),
        version_prefix=match.group('prefix'),
        base_version=match.group('base'),
        rc_number=int(rc_raw) if rc_raw is not None else None,
        build_timestamp=match.group('build'),
    )


def read_current_version(repo_root: Path) -> ParsedReleaseVersion:
    """Read and parse the current version from `pyproject.toml`."""
    pyproject_path = repo_root / 'pyproject.toml'
    pyproject_data = tomllib.loads(pyproject_path.read_text(encoding='utf-8'))
    raw_version = pyproject_data['project']['version']
    if not isinstance(raw_version, str):
        message = 'pyproject.toml project.version must be a string.'
        raise TypeError(message)
    return parse_release_version(raw_version)


def fetch_published_tags(repo_root: Path) -> list[str]:
    """Return all published Git tags from `origin` (falling back to local tags if offline)."""
    git_executable = shutil.which('git') or 'git'
    tags: set[str] = set()

    remote_result = subprocess.run(
        [git_executable, 'ls-remote', '--tags', '--refs', 'origin'],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if not remote_result.returncode:
        for line in remote_result.stdout.splitlines():
            parts = line.strip().split('\t')
            if len(parts) == EXPECTED_LS_REMOTE_COLUMNS and parts[1].startswith('refs/tags/'):
                tags.add(parts[1].removeprefix('refs/tags/'))

    local_result = subprocess.run(
        [git_executable, 'tag', '--list'],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if not local_result.returncode:
        for line in local_result.stdout.splitlines():
            if stripped := line.strip():
                tags.add(stripped)

    return sorted(tags)


def is_prefix_published(version_prefix: str, published_tags: list[str]) -> bool:
    """Return True if any published tag matches the given version prefix."""
    return any(
        tag == version_prefix or tag.startswith(f'{version_prefix}+')
        for tag in published_tags
    )


def compute_next_version(
    current: ParsedReleaseVersion,
    mode: str,
    build_timestamp: str,
    target_base_version: str | None = None,
) -> str:
    """Compute the new version string for the requested release mode."""
    base_version = target_base_version or current.base_version

    if mode == 'timestamp':
        return f'{current.version_prefix}+{build_timestamp}'

    if mode == 'rc':
        next_rc = 1 if current.rc_number is None else current.rc_number + 1
        return f'v{base_version}rc.{next_rc}+{build_timestamp}'

    if mode == 'final':
        return f'v{base_version}+{build_timestamp}'

    message = f'Unsupported release mode: {mode!r}'
    raise ValueError(message)


def format_release_title(new_version: str) -> str:
    """Format the GitHub Release Title from a full Session Sniffer version string."""
    parsed = parse_release_version(new_version)
    date_part, time_part = parsed.build_timestamp.split('.', maxsplit=1)
    formatted_date = f'{date_part[:4]}/{date_part[4:6]}/{date_part[6:8]}'
    formatted_time = f'{time_part[:2]}:{time_part[2:4]}'
    return f'{parsed.version_prefix} - {formatted_date} ({formatted_time})'


def enforce_crlf(file_path: Path) -> None:
    r"""Ensure a file uses CRLF (`\r\n`) line endings."""
    raw_bytes = file_path.read_bytes()
    normalized_bytes = raw_bytes.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
    if normalized_bytes != raw_bytes:
        file_path.write_bytes(normalized_bytes)
    if b'\n' in normalized_bytes.replace(b'\r\n', b''):
        message = f'LF line endings remain in {file_path}'
        raise RuntimeError(message)


def update_pyproject_version(repo_root: Path, new_version: str) -> None:
    """Update `version` in `pyproject.toml` and enforce CRLF line endings."""
    pyproject_path = repo_root / 'pyproject.toml'
    original_text = pyproject_path.read_text(encoding='utf-8')
    updated_text, count = PYPROJECT_VERSION_LINE_PATTERN.subn(rf'\1"{new_version}"', original_text, count=1)
    if count != 1:
        message = 'Failed to locate single project version assignment in pyproject.toml.'
        raise RuntimeError(message)

    pyproject_path.write_bytes(updated_text.replace('\r\n', '\n').replace('\n', '\r\n').encode('utf-8'))
    enforce_crlf(pyproject_path)


def synchronize_uv_lock(repo_root: Path) -> None:
    """Run `uv lock`, enforce CRLF on `uv.lock`, and verify with `uv lock --check`."""
    uv_executable = shutil.which('uv') or 'uv'
    lock_result = subprocess.run([uv_executable, 'lock'], cwd=repo_root, check=False)
    if lock_result.returncode:
        message = f'`uv lock` failed with exit code {lock_result.returncode}.'
        raise RuntimeError(message)

    uv_lock_path = repo_root / 'uv.lock'
    enforce_crlf(uv_lock_path)

    check_result = subprocess.run([uv_executable, 'lock', '--check'], cwd=repo_root, check=False)
    if check_result.returncode:
        message = f'`uv lock --check` failed with exit code {check_result.returncode}.'
        raise RuntimeError(message)


def main() -> None:
    """Execute the release version check or update workflow."""
    parser = argparse.ArgumentParser(description='Inspect or update the Session Sniffer release version.')
    parser.add_argument(
        '--check',
        action='store_true',
        help='Only inspect current version and published tag status without modifying files.',
    )
    parser.add_argument(
        '--mode',
        choices=('auto', 'timestamp', 'rc', 'final'),
        default='auto',
        help='Version update mode: auto (timestamp if unpublished), timestamp, rc, or final.',
    )
    parser.add_argument(
        '--base-version',
        help='Optional X.Y.Z base version override (e.g. 1.5.0).',
    )
    args = parser.parse_args()

    repo_root = get_repo_root()
    current = read_current_version(repo_root)
    published_tags = fetch_published_tags(repo_root)
    already_published = is_prefix_published(current.version_prefix, published_tags)

    now_utc = dt.datetime.now(dt.UTC)
    build_timestamp = now_utc.strftime('%Y%m%d.%H%M')
    iso_utc = now_utc.strftime('%Y-%m-%dT%H:%M:%SZ')

    if args.check:
        status_payload = {
            'current_version': current.full_version,
            'version_prefix': current.version_prefix,
            'base_version': current.base_version,
            'rc_number': current.rc_number,
            'is_published_on_github': already_published,
            'utc_build_timestamp': build_timestamp,
            'utc_iso_timestamp': iso_utc,
            'candidate_timestamp_only': compute_next_version(current, 'timestamp', build_timestamp, args.base_version),
            'candidate_next_rc': compute_next_version(current, 'rc', build_timestamp, args.base_version),
            'candidate_final': compute_next_version(current, 'final', build_timestamp, args.base_version),
        }
        sys.stdout.write(json.dumps(status_payload, indent=2) + '\n')
        return

    resolved_mode = args.mode
    if resolved_mode == 'auto':
        if already_published:
            message = (
                f'Version prefix {current.version_prefix!r} is already published/tagged on GitHub. '
                'Ask the user whether this is a new RC (--mode rc) or a final release (--mode final).'
            )
            raise SystemExit(message)
        resolved_mode = 'timestamp'

    new_version = compute_next_version(current, resolved_mode, build_timestamp, args.base_version)
    update_pyproject_version(repo_root, new_version)
    synchronize_uv_lock(repo_root)

    result_payload = {
        'previous_version': current.full_version,
        'new_version': new_version,
        'mode_used': resolved_mode,
        'utc_iso_timestamp': iso_utc,
        'github_release_tag': new_version,
        'github_release_title': format_release_title(new_version),
        'changed_files': ['pyproject.toml', 'uv.lock'],
    }
    sys.stdout.write(json.dumps(result_payload, indent=2) + '\n')


if __name__ == '__main__':
    main()
