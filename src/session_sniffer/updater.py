"""Updater: GitHub version fetch + retry + UI + version comparison."""

import hashlib
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
from session_sniffer.guis.update_download_dialog import UpdateDownloadDialog
from session_sniffer.models import GithubVersionsResponse, VersionInfo
from session_sniffer.networking.http_session import session
from session_sniffer.text_utils import format_triple_quoted_text
from session_sniffer.utils import format_project_version

if TYPE_CHECKING:
    from collections.abc import Callable


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
        except requests.exceptions.RequestException as exc:
            response = exc.response
            http_code = response.status_code if response is not None else None

            choice = msgbox.show(
                title=TITLE,
                text=format_triple_quoted_text(
                    format_failed_check_for_updates_message(
                        exception_name=type(exc).__name__,
                        http_code=str(http_code) if http_code is not None else 'No response',
                    ),
                ),
                style=(
                    msgbox.Style.MB_ABORTRETRYIGNORE
                    | msgbox.Style.MB_ICONEXCLAMATION
                    | msgbox.Style.MB_SETFOREGROUND
                ),
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


def _is_frozen() -> bool:
    """Return True when running as a PyInstaller-compiled executable."""
    return getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')


def _apply_update(new_exe: Path) -> None:
    """Replace the running executable with `new_exe`, relaunch it, and exit.

    Renames the currently running exe to `.old` (Windows allows renaming open
    files on NTFS), copies the new exe to the original path, launches the new
    process, then exits the current one. The `.old` file is cleaned up on the
    next startup by `main()`.
    """
    current_exe = Path(sys.executable)
    old_exe = current_exe.with_suffix('.old')

    try:
        current_exe.rename(old_exe)
    except OSError as exc:
        new_exe.unlink(missing_ok=True)
        msgbox.show(
            title=TITLE,
            text=format_triple_quoted_text(
                f'Failed to rename the current executable before updating.\n\n{exc}',
            ),
            style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONERROR | msgbox.Style.MB_SETFOREGROUND,
        )
        return

    try:
        shutil.copy2(new_exe, current_exe)
    except OSError as exc:
        # Restore the original exe so the user can still run the app
        old_exe.rename(current_exe)
        new_exe.unlink(missing_ok=True)
        msgbox.show(
            title=TITLE,
            text=format_triple_quoted_text(
                f'Failed to write the new executable. The previous version has been restored.\n\n{exc}',
            ),
            style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONERROR | msgbox.Style.MB_SETFOREGROUND,
        )
        return

    new_exe.unlink(missing_ok=True)
    subprocess.Popen([str(current_exe)])
    sys.exit(0)


def _download_and_apply(candidate_info: VersionInfo, version_str: str) -> None:
    """Download the update exe, verify its SHA-256 hash, and apply it."""
    with tempfile.NamedTemporaryFile(suffix='.exe', prefix='Session_Sniffer_', delete=False) as tmp:
        dest = Path(tmp.name)

    dialog = UpdateDownloadDialog(
        download_url=candidate_info.download_url,
        dest_path=dest,
        version_label=version_str,
    )
    dialog.exec()
    if not dialog.success:
        dest.unlink(missing_ok=True)
        return

    actual_hash = hashlib.sha256(dest.read_bytes()).hexdigest()
    if actual_hash != candidate_info.sha256.lower():
        dest.unlink(missing_ok=True)
        msgbox.show(
            title=TITLE,
            text=format_triple_quoted_text(
                f'Update verification failed: SHA-256 mismatch. The downloaded file has been removed.'
                f'\n\nExpected: {candidate_info.sha256}'
                f'\nActual:   {actual_hash}',
            ),
            style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONERROR | msgbox.Style.MB_SETFOREGROUND,
        )
        return

    _apply_update(dest)


def _handle_update_decision(
    *,
    updater_channel: str | None,
    versions: GithubVersionsResponse,
) -> tuple[UpdateCheckOutcome, Callable[[], None] | None]:
    """Compare versions and optionally prompt user to update."""
    if CURRENT_VERSION.is_prerelease:
        return _handle_prerelease_update_decision(
            latest_stable_info=versions.latest_stable,
            latest_prerelease_info=versions.latest_prerelease,
        )

    is_rc_updater_channel = updater_channel == 'RC'
    candidate_info = versions.latest_prerelease if is_rc_updater_channel else versions.latest_stable
    candidate = Version(candidate_info.version)

    if candidate <= CURRENT_VERSION:
        return (UpdateCheckOutcome.PROCEED, None)

    label = 'pre-release' if is_rc_updater_channel else 'stable release'

    pending: Callable[[], None] | None = None
    if (
        msgbox.show(
            title=TITLE,
            text=format_triple_quoted_text(f"""
                New {label} version available. Do you want to update?

                Current version: {format_project_version(CURRENT_VERSION)}
                Latest version: {format_project_version(candidate)}
            """),
            style=msgbox.Style.MB_YESNO | msgbox.Style.MB_ICONQUESTION | msgbox.Style.MB_SETFOREGROUND,
        )
        == msgbox.ReturnValues.IDYES
    ):
        if _is_frozen():
            version_str = format_project_version(candidate)
            pending = lambda: _download_and_apply(candidate_info, version_str)  # noqa: E731
        else:
            webbrowser.open(candidate_info.release_url)

    return (UpdateCheckOutcome.PROCEED, pending)


def _handle_prerelease_update_decision(
    *,
    latest_stable_info: VersionInfo,
    latest_prerelease_info: VersionInfo,
) -> tuple[UpdateCheckOutcome, Callable[[], None] | None]:
    """Prompt the user about available updates when running a pre-release build.

    Checks both the latest stable and latest pre-release candidates independently.
    Any candidate strictly above CURRENT_VERSION is reported, regardless of the
    user's updater channel setting.
    """
    latest_stable = Version(latest_stable_info.version)
    latest_prerelease = Version(latest_prerelease_info.version)

    stable_newer = latest_stable > CURRENT_VERSION
    prerelease_newer = latest_prerelease > CURRENT_VERSION and latest_prerelease != latest_stable

    if not stable_newer and not prerelease_newer:
        return (UpdateCheckOutcome.PROCEED, None)

    current_str = format_project_version(CURRENT_VERSION)

    if stable_newer and prerelease_newer:
        message = format_triple_quoted_text(f"""
            You are running a pre-release version. Newer versions are available. Do you want to update?

            Current version: {current_str}
            Latest stable release: {format_project_version(latest_stable)}
            Latest pre-release: {format_project_version(latest_prerelease)}
        """)
        open_info = latest_prerelease_info if latest_prerelease > latest_stable else latest_stable_info
    elif stable_newer:
        message = format_triple_quoted_text(f"""
            You are running a pre-release version. A newer stable release is available. Do you want to update?

            Current version: {current_str}
            Latest stable release: {format_project_version(latest_stable)}
        """)
        open_info = latest_stable_info
    else:
        message = format_triple_quoted_text(f"""
            You are running a pre-release version. A newer pre-release is available. Do you want to update?

            Current version: {current_str}
            Latest pre-release: {format_project_version(latest_prerelease)}
        """)
        open_info = latest_prerelease_info

    pending: Callable[[], None] | None = None
    if (
        msgbox.show(
            title=TITLE,
            text=message,
            style=msgbox.Style.MB_YESNO | msgbox.Style.MB_ICONQUESTION | msgbox.Style.MB_SETFOREGROUND,
        )
        == msgbox.ReturnValues.IDYES
    ):
        if _is_frozen():
            version_str = format_project_version(Version(open_info.version))
            pending = lambda: _download_and_apply(open_info, version_str)  # noqa: E731
        else:
            webbrowser.open(open_info.release_url)

    return (UpdateCheckOutcome.PROCEED, pending)
