"""Updater: GitHub version fetch + retry + UI + version comparison."""

import functools
import hashlib
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import webbrowser
from enum import Enum, auto
from pathlib import Path
from typing import TYPE_CHECKING

import requests
from packaging.version import Version

from session_sniffer import msgbox
from session_sniffer.constants.local import CURRENT_VERSION
from session_sniffer.constants.standalone import (
    GITHUB_RELEASES_URL,
    GITHUB_VERSIONS_URL,
    TITLE,
)
from session_sniffer.error_messages import format_failed_check_for_updates_message
from session_sniffer.guis.update_download_dialog import UpdateCandidate, UpdateDownloadDialog
from session_sniffer.models import GithubVersionsResponse, VersionInfo
from session_sniffer.networking.http_session import session
from session_sniffer.text_utils import format_triple_quoted_text
from session_sniffer.utils import format_project_version, is_pyinstaller_compiled

if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger(__name__)


class UpdateCheckOutcome(Enum):
    """Outcome of the update check process."""

    PROCEED = auto()
    IGNORE = auto()
    FAILED = auto()
    ABORT = auto()


def check_for_updates(*, updater_channel: str | None) -> tuple[UpdateCheckOutcome, Callable[[], None] | None]:
    """Fetch versions, handle failures, and prompt for update if needed.

    Returns a tuple of (outcome, pending_download) where `pending_download` is a
    callable that must be invoked on the main Qt thread if not None.
    """
    outcome, versions = _fetch_versions_with_retries()
    if outcome is UpdateCheckOutcome.PROCEED and versions is not None:
        return _handle_update_decision(updater_channel=updater_channel, versions=versions)
    if outcome is UpdateCheckOutcome.ABORT:
        return (outcome, None)
    return (UpdateCheckOutcome.IGNORE, None)


def _fetch_versions_with_retries(*, max_attempts: int = 3) -> tuple[UpdateCheckOutcome, GithubVersionsResponse | None]:
    """Fetch GitHub versions with user-driven retry/abort policy.

    Returns:
        tuple: (outcome, versions) where:
            - PROCEED: Successfully fetched version data
            - ABORT: User clicked Abort button
            - IGNORE: User clicked Ignore button
            - FAILED: All retry attempts exhausted
    """
    for attempt in range(1, max_attempts + 1):
        try:
            versions = _fetch_github_versions()
        except requests.exceptions.RequestException as e:
            http_code = e.response.status_code if e.response is not None else None
            http_str = str(http_code) if http_code is not None else 'no response'
            logger.warning(
                'Update check failed (attempt %d/%d): %s (HTTP %s)',
                attempt,
                max_attempts,
                type(e).__name__,
                http_str,
            )

            choice = msgbox.show(
                title=TITLE,
                text=format_triple_quoted_text(
                    format_failed_check_for_updates_message(
                        exception_name=type(e).__name__,
                        http_code=str(http_code) if http_code is not None else 'No response',
                    ),
                ),
                style=(msgbox.Style.MB_ABORTRETRYIGNORE | msgbox.Style.MB_ICONEXCLAMATION | msgbox.Style.MB_SETFOREGROUND),
            )

            if choice == msgbox.ReturnValues.IDABORT:
                webbrowser.open(GITHUB_RELEASES_URL)
                return (UpdateCheckOutcome.ABORT, None)

            if choice == msgbox.ReturnValues.IDIGNORE:
                return (UpdateCheckOutcome.IGNORE, None)

            if choice == msgbox.ReturnValues.IDRETRY and attempt < max_attempts:
                continue

            return (UpdateCheckOutcome.FAILED, None)

        return (UpdateCheckOutcome.PROCEED, versions)

    return (UpdateCheckOutcome.FAILED, None)


def _fetch_github_versions() -> GithubVersionsResponse:
    """Fetch and validate version metadata from GitHub."""
    response = session.get(GITHUB_VERSIONS_URL, timeout=10)
    response.raise_for_status()
    return GithubVersionsResponse.model_validate(response.json())


def _remove_file_if_possible(path: Path) -> None:
    """Remove `path`, logging any `OSError` (e.g. antivirus lock)."""
    try:
        path.unlink(missing_ok=True)
    except OSError as e:
        logger.debug('Failed to remove file %s: %s', path, e)


def _apply_update(new_exe: Path) -> None:
    """Replace the running executable with `new_exe`, relaunch it, and exit.

    Attempts to rename the currently running executable to `.old`, copies the new
    executable to the original path, launches the new process with a fresh
    PyInstaller environment, then exits immediately. The `.old` file is cleaned up
    on the next startup by `main()`.
    """
    current_exe = Path(sys.executable)
    old_exe = current_exe.with_name(f'{current_exe.name}.old')
    logger.info('Applying update: replacing %s', current_exe)

    try:
        old_exe.unlink(missing_ok=True)
    except OSError as e:
        logger.exception('Failed to remove stale backup executable before updating')
        _remove_file_if_possible(new_exe)
        msgbox.show(
            title=TITLE,
            text=format_triple_quoted_text(
                f'Failed to remove the stale backup executable before updating.\n\n{e}',
            ),
            style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONERROR | msgbox.Style.MB_SETFOREGROUND,
        )
        return

    try:
        current_exe.rename(old_exe)
    except OSError as e:
        logger.exception('Failed to rename current executable before updating')
        _remove_file_if_possible(new_exe)
        msgbox.show(
            title=TITLE,
            text=format_triple_quoted_text(
                f'Failed to rename the current executable before updating.\n\n{e}',
            ),
            style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONERROR | msgbox.Style.MB_SETFOREGROUND,
        )
        return

    try:
        shutil.copy2(new_exe, current_exe)
        if sys.platform != 'win32':
            current_exe.chmod(0o755)
    except OSError as e:
        logger.exception('Failed to write new executable')
        # Restore the original exe so the user can still run the app
        try:
            old_exe.rename(current_exe)
        except OSError as restore_error:
            logger.exception('Failed to restore previous executable')
            _remove_file_if_possible(new_exe)
            msgbox.show(
                title=TITLE,
                text=format_triple_quoted_text(
                    f'Failed to write the new executable, and failed to restore the previous version.\n\nWrite error: {e}\n\nRestore error: {restore_error}',
                ),
                style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONERROR | msgbox.Style.MB_SETFOREGROUND,
            )
            return
        _remove_file_if_possible(new_exe)
        msgbox.show(
            title=TITLE,
            text=format_triple_quoted_text(
                f'Failed to write the new executable. The previous version has been restored.\n\n{e}',
            ),
            style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONERROR | msgbox.Style.MB_SETFOREGROUND,
        )
        return

    _remove_file_if_possible(new_exe)
    # PyInstaller 6.10+ changed sub-process detection: a child process that inherits
    # _PYI_APPLICATION_HOME_DIR / _PYI_ARCHIVE_FILE env vars is treated as a worker
    # sub-process of the same app instance and reuses the parent's _MEI temp dir.
    # Setting PYINSTALLER_RESET_ENVIRONMENT=1 tells the bootloader that this is a
    # new independent application launch, so it extracts to its own fresh _MEI dir.
    subprocess.Popen(
        [str(current_exe)],
        cwd=str(current_exe.parent),
        env={**os.environ, 'PYINSTALLER_RESET_ENVIRONMENT': '1'},
        close_fds=True,
    )
    # os._exit bypasses atexit handlers and Qt/thread teardown, which is intentional:
    # background threads (capture, rendering, etc.) are still running at this point,
    # and sys.exit would attempt a full teardown after the exe has already been replaced.
    os._exit(0)


def _resolve_candidate_file_size(candidate_info: VersionInfo) -> int | None:
    """Resolve the candidate binary file size in bytes."""
    if candidate_info.platform_file_size is not None:
        return candidate_info.platform_file_size

    try:
        response = session.head(candidate_info.platform_download_url, allow_redirects=True, timeout=5)
        if response.status_code == requests.codes.ok and 'Content-Length' in response.headers:
            return int(response.headers['Content-Length'])
    except requests.exceptions.RequestException as e:
        logger.debug('Failed to resolve candidate file size: %s', e)
    return None


def _is_running_executable_identical(candidate_info: VersionInfo) -> bool:
    """Return whether the running PyInstaller executable matches the candidate SHA-256."""
    if not is_pyinstaller_compiled():
        return False
    current_executable_path = Path(sys.executable)
    if not current_executable_path.is_file():
        return False
    current_executable_sha256 = hashlib.sha256(current_executable_path.read_bytes()).hexdigest()
    return current_executable_sha256.lower() == candidate_info.platform_sha256.lower()


def _download_and_apply(
    candidate_info: VersionInfo,
    version_str: str,
    *,
    is_prerelease: bool,
) -> None:
    """Download the update exe, verify its SHA-256 hash, and apply it."""
    file_suffix = '.exe' if sys.platform == 'win32' else ''
    with tempfile.NamedTemporaryFile(suffix=file_suffix, prefix='Session_Sniffer_', delete=False) as tmp:
        dest = Path(tmp.name)

    candidate = UpdateCandidate(
        download_url=candidate_info.platform_download_url,
        version_label=version_str,
        sha256_hash=candidate_info.platform_sha256,
        size_bytes=_resolve_candidate_file_size(candidate_info),
        is_prerelease=is_prerelease,
        release_url=candidate_info.release_url,
    )
    dialog = UpdateDownloadDialog(candidate, dest)
    dialog.exec()
    if not dialog.success:
        _remove_file_if_possible(dest)
        if dialog.error_message:
            msgbox.show(
                title=TITLE,
                text=format_triple_quoted_text(
                    f'Failed to download the update.\n\n{dialog.error_message}',
                ),
                style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONERROR | msgbox.Style.MB_SETFOREGROUND,
            )
        return

    if not is_pyinstaller_compiled():
        _remove_file_if_possible(dest)
        return

    actual_hash = hashlib.sha256(dest.read_bytes()).hexdigest()
    if actual_hash.lower() != candidate_info.platform_sha256.lower():
        logger.warning('SHA-256 mismatch for update download: expected %s, got %s', candidate_info.platform_sha256, actual_hash)
        _remove_file_if_possible(dest)
        msgbox.show(
            title=TITLE,
            text=format_triple_quoted_text(
                f'Update verification failed: SHA-256 mismatch. The downloaded file has been removed.\n\nExpected: {candidate_info.platform_sha256}\nActual:   {actual_hash}',
            ),
            style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONERROR | msgbox.Style.MB_SETFOREGROUND,
        )
        return

    current_executable_hash = hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
    if actual_hash.lower() == current_executable_hash.lower():
        logger.info('Downloaded update is identical to running executable (%s); skipping replacement.', actual_hash)
        _remove_file_if_possible(dest)
        return

    _apply_update(dest)


def _handle_update_decision(
    *,
    updater_channel: str | None,
    versions: GithubVersionsResponse,
) -> tuple[UpdateCheckOutcome, Callable[[], None] | None]:
    """Compare versions and schedule update download if a newer version is available."""
    if CURRENT_VERSION.is_prerelease:
        return _handle_prerelease_update_decision(
            latest_stable_info=versions.latest_stable,
            latest_prerelease_info=versions.latest_prerelease,
        )

    is_prerelease_channel = updater_channel == 'Pre-release'
    if is_prerelease_channel:
        latest_stable = Version(versions.latest_stable.version)
        latest_prerelease = Version(versions.latest_prerelease.version)
        candidate_info = versions.latest_prerelease if latest_prerelease > latest_stable else versions.latest_stable
    else:
        candidate_info = versions.latest_stable

    candidate = Version(candidate_info.version)
    if candidate <= CURRENT_VERSION:
        return (UpdateCheckOutcome.PROCEED, None)

    if sys.platform.startswith('linux') and not candidate_info.linux_download_url:
        logger.info('Update available (%s) but no Linux binary was published; skipping update.', format_project_version(candidate))
        return (UpdateCheckOutcome.PROCEED, None)

    if _is_running_executable_identical(candidate_info):
        logger.info('Running executable SHA-256 matches candidate release (%s); already up to date.', candidate_info.platform_sha256)
        return (UpdateCheckOutcome.PROCEED, None)

    is_candidate_prerelease = candidate.is_prerelease or candidate_info.is_prerelease
    logger.info(
        'Update available (%s): %s -> %s',
        'pre-release' if is_candidate_prerelease else 'stable release',
        format_project_version(CURRENT_VERSION),
        format_project_version(candidate),
    )

    version_str = format_project_version(candidate)
    pending = functools.partial(_download_and_apply, candidate_info, version_str, is_prerelease=is_candidate_prerelease)
    return (UpdateCheckOutcome.PROCEED, pending)


def _handle_prerelease_update_decision(
    *,
    latest_stable_info: VersionInfo,
    latest_prerelease_info: VersionInfo,
) -> tuple[UpdateCheckOutcome, Callable[[], None] | None]:
    """Check for available updates when running a pre-release build.

    Checks both the latest stable and latest pre-release candidates independently.
    Any candidate strictly above CURRENT_VERSION is selected, preferring the higher version.
    """
    latest_stable = Version(latest_stable_info.version)
    latest_prerelease = Version(latest_prerelease_info.version)

    stable_newer = latest_stable > CURRENT_VERSION
    prerelease_newer = latest_prerelease > CURRENT_VERSION and latest_prerelease != latest_stable

    if not stable_newer and not prerelease_newer:
        return (UpdateCheckOutcome.PROCEED, None)

    if stable_newer and prerelease_newer:
        candidate_info = latest_prerelease_info if latest_prerelease > latest_stable else latest_stable_info
    elif stable_newer:
        candidate_info = latest_stable_info
    else:
        candidate_info = latest_prerelease_info

    candidate = Version(candidate_info.version)
    if sys.platform.startswith('linux') and not candidate_info.linux_download_url:
        logger.info('Pre-release build found newer %s but no Linux binary was published; skipping update.', format_project_version(candidate))
        return (UpdateCheckOutcome.PROCEED, None)

    if _is_running_executable_identical(candidate_info):
        logger.info('Running executable SHA-256 matches candidate release (%s); already up to date.', candidate_info.platform_sha256)
        return (UpdateCheckOutcome.PROCEED, None)

    is_candidate_prerelease = candidate.is_prerelease or candidate_info.is_prerelease
    logger.info(
        'Pre-release build found newer %s: %s -> %s',
        'pre-release' if is_candidate_prerelease else 'stable release',
        format_project_version(CURRENT_VERSION),
        format_project_version(candidate),
    )

    version_str = format_project_version(candidate)
    pending = functools.partial(_download_and_apply, candidate_info, version_str, is_prerelease=is_candidate_prerelease)
    return (UpdateCheckOutcome.PROCEED, pending)
