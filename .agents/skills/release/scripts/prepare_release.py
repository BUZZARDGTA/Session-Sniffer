"""Automate Session Sniffer release preparation: Wireshark manuf update, version bump, lockfile sync, and CRLF enforcement."""

import argparse
import datetime as dt
import email.utils
import gzip
import http.client
import io
import json
import re
import shutil
import ssl
import subprocess
import sys
import tomllib
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

EXPECTED_LS_REMOTE_COLUMNS = 2
VERSION_PATTERN = re.compile(
    r'^(?P<prefix>v(?P<base>\d+\.\d+\.\d+)(?:rc\.(?P<rc>\d+))?)\+(?P<build>\d{8}\.\d{4})$',
)
PYPROJECT_VERSION_LINE_PATTERN = re.compile(r'^(version\s*=\s*)"[^"]+"', re.MULTILINE)

MANUF_RELATIVE_PATH = Path('resources/manuf')
MANUF_DOWNLOAD_URL = 'https://www.wireshark.org/download/automated/data/manuf.gz'
MANUF_USER_AGENT = 'Session-Sniffer-Release-Helper'
MANUF_REQUEST_TIMEOUT_SECONDS = 30
MANUF_MAX_REDIRECTS = 5
MANUF_MAX_COMPRESSED_BYTES = 16 * 1024 * 1024
MANUF_MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024
MANUF_MIN_ENTRIES = 10_000
MANUF_ENTRY_PATTERN = re.compile(
    r'^(?:[0-9A-Fa-f]{2}:){2}[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){0,2}(?:/(?:24|28|36))?[ \t]+\S+[ \t]+[^\t]+$',
)

HTTP_STATUS_OK = 200
HTTP_STATUS_NOT_MODIFIED = 304
HTTP_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True, slots=True)
class ParsedReleaseVersion:
    """Structured representation of a Session Sniffer version string."""

    full_version: str
    version_prefix: str
    base_version: str
    rc_number: int | None
    build_timestamp: str


@dataclass(frozen=True, slots=True)
class HttpManufResponse:
    """HTTP response returned when querying Wireshark's canonical `manuf.gz` URL."""

    status: int
    reason: str
    body: bytes
    last_modified: str | None


@dataclass(frozen=True, slots=True)
class ManufCheckResult:
    """Read-only upstream status for `resources/manuf`."""

    local_commit_utc: str | None
    remote_last_modified: str | None
    update_available: bool | None
    error: str | None


@dataclass(frozen=True, slots=True)
class ManufUpdateResult:
    """Outcome summary for updating `resources/manuf`."""

    status: str
    changed: bool
    remote_last_modified: str | None
    previous_header: str | None
    new_header: str | None
    previous_entry_count: int | None
    entry_count: int | None
    verified_with_app_parser: bool


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


def get_manuf_last_commit_timestamp(repo_root: Path) -> dt.datetime | None:
    """Return the UTC commit timestamp for `resources/manuf` when clean in Git."""
    manuf_path = repo_root / MANUF_RELATIVE_PATH
    if not manuf_path.is_file():
        return None

    git_executable = shutil.which('git') or 'git'
    manuf_posix = MANUF_RELATIVE_PATH.as_posix()

    status_result = subprocess.run(
        [git_executable, 'status', '--porcelain', '--', manuf_posix],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if status_result.returncode or status_result.stdout.strip():
        return None

    log_result = subprocess.run(
        [git_executable, 'log', '-1', '--format=%ct', '--', manuf_posix],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    timestamp_text = log_result.stdout.strip()
    if log_result.returncode or not timestamp_text or not (timestamp_text.isascii() and timestamp_text.isdigit()):
        return None

    return dt.datetime.fromtimestamp(int(timestamp_text), tz=dt.UTC)


def read_bounded_http_body(response: http.client.HTTPResponse, max_bytes: int) -> bytes:
    """Read an HTTP response body while enforcing an upper byte limit."""
    payload = response.read(max_bytes + 1)
    if len(payload) > max_bytes:
        message = f'Wireshark manuf response exceeded maximum allowed size ({max_bytes} bytes).'
        raise ValueError(message)
    return payload


def request_manuf_url(method: str, *, if_modified_since: dt.datetime | None = None) -> HttpManufResponse:
    """Send an HTTPS `HEAD` or `GET` request to Wireshark's canonical `manuf.gz` URL."""
    current_url = MANUF_DOWNLOAD_URL
    headers: dict[str, str] = {
        'User-Agent': MANUF_USER_AGENT,
        'Accept-Encoding': 'identity',
    }
    if if_modified_since is not None:
        headers['If-Modified-Since'] = email.utils.format_datetime(if_modified_since.astimezone(dt.UTC), usegmt=True)

    ssl_context = ssl.create_default_context()
    for _ in range(MANUF_MAX_REDIRECTS + 1):
        parsed_url = urllib.parse.urlsplit(current_url)
        if parsed_url.scheme != 'https' or parsed_url.hostname is None or not parsed_url.hostname:
            message = f'Refusing non-HTTPS or invalid Wireshark manuf URL: {current_url!r}'
            raise ValueError(message)

        request_target = parsed_url.path or '/'
        if parsed_url.query:
            request_target = f'{request_target}?{parsed_url.query}'

        connection = http.client.HTTPSConnection(
            parsed_url.hostname,
            port=parsed_url.port,
            timeout=MANUF_REQUEST_TIMEOUT_SECONDS,
            context=ssl_context,
        )
        try:
            connection.request(method, request_target, headers=headers)
            response = connection.getresponse()
            status = response.status
            reason = response.reason
            location = response.getheader('Location')
            last_modified = response.getheader('Last-Modified')

            if status in HTTP_REDIRECT_STATUSES and location is not None and location:
                response.read()
                current_url = urllib.parse.urljoin(current_url, location)
                continue

            if method == 'HEAD' or status == HTTP_STATUS_NOT_MODIFIED:
                response.read()
                return HttpManufResponse(status=status, reason=reason, body=b'', last_modified=last_modified)

            body = read_bounded_http_body(response, MANUF_MAX_COMPRESSED_BYTES)
            return HttpManufResponse(status=status, reason=reason, body=body, last_modified=last_modified)
        finally:
            connection.close()

    message = f'Exceeded maximum redirects ({MANUF_MAX_REDIRECTS}) while fetching {MANUF_DOWNLOAD_URL}.'
    raise RuntimeError(message)


def decompress_manuf_gzip(compressed_bytes: bytes) -> str:
    """Decompress a gzipped Wireshark `manuf` payload with a size cap and decode as UTF-8."""
    with gzip.GzipFile(fileobj=io.BytesIO(compressed_bytes), mode='rb') as gzip_stream:
        decompressed_bytes = gzip_stream.read(MANUF_MAX_DECOMPRESSED_BYTES + 1)

    if len(decompressed_bytes) > MANUF_MAX_DECOMPRESSED_BYTES:
        message = f'Decompressed Wireshark manuf payload exceeded maximum allowed size ({MANUF_MAX_DECOMPRESSED_BYTES} bytes).'
        raise ValueError(message)
    if b'\x00' in decompressed_bytes:
        message = 'Decompressed Wireshark manuf payload contains NUL bytes.'
        raise ValueError(message)

    return decompressed_bytes.decode('utf-8')


def extract_manuf_header(manuf_text: str) -> str | None:
    """Return the first comment header line from a Wireshark `manuf` file."""
    for raw_line in manuf_text.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith('#'):
            return stripped
    return None


def extract_manuf_data_lines(manuf_text: str) -> list[str]:
    """Return all non-empty, non-comment MAC vendor entry lines from `manuf_text`."""
    return [stripped for raw_line in manuf_text.splitlines() if (stripped := raw_line.strip()) and not stripped.startswith('#')]


def validate_manuf_content(manuf_text: str) -> list[str]:
    """Validate every entry in `manuf_text` against the Session Sniffer `manuf` format and return entry lines."""
    data_lines: list[str] = []
    for line_number, raw_line in enumerate(manuf_text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if MANUF_ENTRY_PATTERN.match(stripped) is None:
            message = f'Downloaded Wireshark manuf database contains an unparseable line {line_number}: {stripped!r}'
            raise ValueError(message)
        data_lines.append(stripped)

    if len(data_lines) < MANUF_MIN_ENTRIES:
        message = f'Downloaded Wireshark manuf database has too few entries ({len(data_lines)} < {MANUF_MIN_ENTRIES}).'
        raise ValueError(message)

    return data_lines


def normalize_manuf_to_crlf_bytes(manuf_text: str) -> bytes:
    r"""Normalize `manuf_text` to UTF-8 with CRLF (`\r\n`) line endings and a trailing CRLF."""
    normalized_text = manuf_text.replace('\r\n', '\n').replace('\r', '\n')
    if not normalized_text.endswith('\n'):
        normalized_text = f'{normalized_text}\n'
    return normalized_text.replace('\n', '\r\n').encode('utf-8')


def verify_manuf_with_app_parser(repo_root: Path) -> bool:
    """Verify `resources/manuf` using Session Sniffer's `MacLookup.load()` when `.venv` is present."""
    venv_python = repo_root / '.venv' / ('Scripts/python.exe' if sys.platform == 'win32' else 'bin/python')
    if not venv_python.is_file():
        return False

    verification_result = subprocess.run(
        [
            str(venv_python),
            '-c',
            'from session_sniffer.networking.manuf_lookup import MacLookup; MacLookup.load()',
        ],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if verification_result.returncode:
        error_output = verification_result.stderr.strip() or verification_result.stdout.strip()
        message = f'MacLookup.load() failed to parse updated resources/manuf: {error_output}'
        raise RuntimeError(message)
    return True


def check_manuf_update_status(repo_root: Path, *, force: bool = False) -> ManufCheckResult:
    """Check via HTTP `HEAD` whether Wireshark has published a newer `manuf.gz`."""
    local_commit_timestamp = get_manuf_last_commit_timestamp(repo_root)
    local_commit_utc = local_commit_timestamp.strftime('%Y-%m-%dT%H:%M:%SZ') if local_commit_timestamp is not None else None
    if_modified_since = None if force else local_commit_timestamp

    try:
        response = request_manuf_url('HEAD', if_modified_since=if_modified_since)
    except (http.client.HTTPException, OSError, RuntimeError, ValueError) as e:
        return ManufCheckResult(
            local_commit_utc=local_commit_utc,
            remote_last_modified=None,
            update_available=None,
            error=str(e),
        )

    if response.status == HTTP_STATUS_NOT_MODIFIED:
        return ManufCheckResult(
            local_commit_utc=local_commit_utc,
            remote_last_modified=response.last_modified,
            update_available=False,
            error=None,
        )

    if response.status == HTTP_STATUS_OK:
        return ManufCheckResult(
            local_commit_utc=local_commit_utc,
            remote_last_modified=response.last_modified,
            update_available=True,
            error=None,
        )

    return ManufCheckResult(
        local_commit_utc=local_commit_utc,
        remote_last_modified=response.last_modified,
        update_available=None,
        error=f'Unexpected HTTP status: {response.status} {response.reason}',
    )


def update_manuf_database(repo_root: Path, *, force: bool = False) -> ManufUpdateResult:
    """Fetch, validate, and update `resources/manuf` from Wireshark's canonical `manuf.gz`."""
    manuf_path = repo_root / MANUF_RELATIVE_PATH
    existing_bytes = manuf_path.read_bytes() if manuf_path.is_file() else None
    existing_text = existing_bytes.decode('utf-8') if existing_bytes is not None else None
    previous_header = extract_manuf_header(existing_text) if existing_text is not None else None
    existing_data_lines = extract_manuf_data_lines(existing_text) if existing_text is not None else None
    previous_entry_count = len(existing_data_lines) if existing_data_lines is not None else None

    if_modified_since = None if force else get_manuf_last_commit_timestamp(repo_root)
    response = request_manuf_url('GET', if_modified_since=if_modified_since)

    if response.status == HTTP_STATUS_NOT_MODIFIED:
        return ManufUpdateResult(
            status='not_modified',
            changed=False,
            remote_last_modified=response.last_modified,
            previous_header=previous_header,
            new_header=previous_header,
            previous_entry_count=previous_entry_count,
            entry_count=previous_entry_count,
            verified_with_app_parser=False,
        )

    if response.status != HTTP_STATUS_OK:
        message = f'Failed to download Wireshark manuf database from {MANUF_DOWNLOAD_URL}: HTTP {response.status} {response.reason}'
        raise RuntimeError(message)

    decoded_text = decompress_manuf_gzip(response.body)
    downloaded_data_lines = validate_manuf_content(decoded_text)
    entry_count = len(downloaded_data_lines)
    new_header = extract_manuf_header(decoded_text)
    normalized_bytes = normalize_manuf_to_crlf_bytes(decoded_text)

    has_valid_crlf = existing_bytes is not None and b'\n' not in existing_bytes.replace(b'\r\n', b'')
    if existing_bytes == normalized_bytes or (has_valid_crlf and existing_data_lines == downloaded_data_lines):
        return ManufUpdateResult(
            status='unchanged',
            changed=False,
            remote_last_modified=response.last_modified,
            previous_header=previous_header,
            new_header=previous_header,
            previous_entry_count=previous_entry_count,
            entry_count=entry_count,
            verified_with_app_parser=False,
        )

    manuf_path.parent.mkdir(parents=True, exist_ok=True)
    manuf_path.write_bytes(normalized_bytes)
    try:
        enforce_crlf(manuf_path)
        verified_with_app_parser = verify_manuf_with_app_parser(repo_root)
    except (OSError, RuntimeError):
        if existing_bytes is not None:
            manuf_path.write_bytes(existing_bytes)
        elif manuf_path.is_file():
            manuf_path.unlink()
        raise

    return ManufUpdateResult(
        status='updated',
        changed=True,
        remote_last_modified=response.last_modified,
        previous_header=previous_header,
        new_header=new_header,
        previous_entry_count=previous_entry_count,
        entry_count=entry_count,
        verified_with_app_parser=verified_with_app_parser,
    )


def format_manuf_check_payload(check_result: ManufCheckResult) -> dict[str, object]:
    """Serialize a `ManufCheckResult` into a JSON-ready dictionary."""
    return {
        'path': MANUF_RELATIVE_PATH.as_posix(),
        'source_url': MANUF_DOWNLOAD_URL,
        'local_commit_utc': check_result.local_commit_utc,
        'remote_last_modified': check_result.remote_last_modified,
        'update_available': check_result.update_available,
        'error': check_result.error,
    }


def format_manuf_update_payload(update_result: ManufUpdateResult) -> dict[str, object]:
    """Serialize a `ManufUpdateResult` into a JSON-ready dictionary."""
    return {
        'path': MANUF_RELATIVE_PATH.as_posix(),
        'source_url': MANUF_DOWNLOAD_URL,
        'status': update_result.status,
        'changed': update_result.changed,
        'remote_last_modified': update_result.remote_last_modified,
        'previous_header': update_result.previous_header,
        'new_header': update_result.new_header,
        'previous_entry_count': update_result.previous_entry_count,
        'entry_count': update_result.entry_count,
        'verified_with_app_parser': update_result.verified_with_app_parser,
    }


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
    """Execute the release inspection, Wireshark `manuf` update, or version update workflow."""
    parser = argparse.ArgumentParser(description='Inspect or update the Session Sniffer release version and Wireshark manuf database.')
    parser.add_argument(
        '--check',
        action='store_true',
        help='Only inspect current version, published tag status, and upstream Wireshark manuf status without modifying files.',
    )
    parser.add_argument(
        '--mode',
        choices=('timestamp', 'rc', 'final'),
        help='Explicit version update mode: timestamp, rc, or final (required unless --check or --update-manuf-only is set).',
    )
    parser.add_argument(
        '--base-version',
        help='Optional X.Y.Z base version override (e.g. 1.5.0).',
    )
    parser.add_argument(
        '--skip-manuf-update',
        action='store_true',
        help='Skip checking and updating resources/manuf from Wireshark.',
    )
    parser.add_argument(
        '--force-manuf-update',
        action='store_true',
        help='Bypass HTTP If-Modified-Since and fetch resources/manuf unconditionally.',
    )
    parser.add_argument(
        '--update-manuf-only',
        action='store_true',
        help='Update and validate resources/manuf without modifying pyproject.toml or uv.lock.',
    )
    args = parser.parse_args()

    repo_root = get_repo_root()

    if args.update_manuf_only:
        if args.check or args.mode is not None or args.skip_manuf_update:
            parser.error('--update-manuf-only cannot be combined with --check, --mode, or --skip-manuf-update.')
        manuf_result = update_manuf_database(repo_root, force=args.force_manuf_update)
        manuf_only_payload = {
            'manuf_update': format_manuf_update_payload(manuf_result),
            'changed_files': [MANUF_RELATIVE_PATH.as_posix()] if manuf_result.changed else [],
        }
        sys.stdout.write(json.dumps(manuf_only_payload, indent=2) + '\n')
        return

    current = read_current_version(repo_root)
    published_tags = fetch_published_tags(repo_root)
    already_published = is_prefix_published(current.version_prefix, published_tags)

    if args.check:
        now_utc = dt.datetime.now(dt.UTC)
        build_timestamp = now_utc.strftime('%Y%m%d.%H%M')
        iso_utc = now_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
        manuf_check_payload: dict[str, object]
        if args.skip_manuf_update:
            manuf_check_payload = {
                'path': MANUF_RELATIVE_PATH.as_posix(),
                'source_url': MANUF_DOWNLOAD_URL,
                'status': 'skipped',
                'update_available': None,
            }
        else:
            manuf_check_payload = format_manuf_check_payload(
                check_manuf_update_status(repo_root, force=args.force_manuf_update),
            )

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
            'manuf_check': manuf_check_payload,
        }
        sys.stdout.write(json.dumps(status_payload, indent=2) + '\n')
        return

    if args.mode is None:
        parser.error('--mode (timestamp, rc, or final) is required unless --check or --update-manuf-only is specified.')

    if args.skip_manuf_update:
        manuf_result = ManufUpdateResult(
            status='skipped',
            changed=False,
            remote_last_modified=None,
            previous_header=None,
            new_header=None,
            previous_entry_count=None,
            entry_count=None,
            verified_with_app_parser=False,
        )
    else:
        manuf_result = update_manuf_database(repo_root, force=args.force_manuf_update)

    now_utc = dt.datetime.now(dt.UTC)
    build_timestamp = now_utc.strftime('%Y%m%d.%H%M')
    iso_utc = now_utc.strftime('%Y-%m-%dT%H:%M:%SZ')

    resolved_mode = args.mode
    new_version = compute_next_version(current, resolved_mode, build_timestamp, args.base_version)
    update_pyproject_version(repo_root, new_version)
    synchronize_uv_lock(repo_root)

    changed_files = ([MANUF_RELATIVE_PATH.as_posix()] if manuf_result.changed else []) + ['pyproject.toml', 'uv.lock']
    result_payload = {
        'previous_version': current.full_version,
        'new_version': new_version,
        'mode_used': resolved_mode,
        'utc_iso_timestamp': iso_utc,
        'github_release_tag': new_version,
        'github_release_title': format_release_title(new_version),
        'manuf_update': format_manuf_update_payload(manuf_result),
        'changed_files': changed_files,
    }
    sys.stdout.write(json.dumps(result_payload, indent=2) + '\n')


if __name__ == '__main__':
    main()
