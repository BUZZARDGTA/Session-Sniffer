"""Updater: GitHub version fetch + retry + UI + version comparison."""

import webbrowser
from enum import Enum, auto

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
from session_sniffer.models import GithubVersionsResponse, VersionInfo
from session_sniffer.networking.http_session import session
from session_sniffer.text_utils import format_triple_quoted_text
from session_sniffer.utils import format_project_version


class UpdateCheckOutcome(Enum):
    """Outcome of the update check process."""
    PROCEED = auto()
    IGNORE = auto()
    FAILED = auto()
    ABORT = auto()


def check_for_updates(*, updater_channel: str | None) -> UpdateCheckOutcome:
    """Fetch versions, handle failures, and prompt for update if needed."""
    outcome, versions = _fetch_versions_with_retries()

    if outcome is UpdateCheckOutcome.PROCEED and versions is not None:
        return _handle_update_decision(updater_channel=updater_channel, versions=versions)
    if outcome is UpdateCheckOutcome.ABORT:
        return outcome
    return UpdateCheckOutcome.IGNORE


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


def _handle_update_decision(
    *,
    updater_channel: str | None,
    versions: GithubVersionsResponse,
) -> UpdateCheckOutcome:
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
        return UpdateCheckOutcome.PROCEED

    label = 'pre-release' if is_rc_updater_channel else 'stable release'

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
        webbrowser.open(candidate_info.release_url)

    return UpdateCheckOutcome.PROCEED


def _handle_prerelease_update_decision(
    *,
    latest_stable_info: VersionInfo,
    latest_prerelease_info: VersionInfo,
) -> UpdateCheckOutcome:
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
        return UpdateCheckOutcome.PROCEED

    current_str = format_project_version(CURRENT_VERSION)

    if stable_newer and prerelease_newer:
        message = format_triple_quoted_text(f"""
            You are running a pre-release version. Newer versions are available. Do you want to update?

            Current version: {current_str}
            Latest stable release: {format_project_version(latest_stable)}
            Latest pre-release: {format_project_version(latest_prerelease)}
        """)
        open_url = (latest_prerelease_info if latest_prerelease > latest_stable else latest_stable_info).release_url
    elif stable_newer:
        message = format_triple_quoted_text(f"""
            You are running a pre-release version. A newer stable release is available. Do you want to update?

            Current version: {current_str}
            Latest stable release: {format_project_version(latest_stable)}
        """)
        open_url = latest_stable_info.release_url
    else:
        message = format_triple_quoted_text(f"""
            You are running a pre-release version. A newer pre-release is available. Do you want to update?

            Current version: {current_str}
            Latest pre-release: {format_project_version(latest_prerelease)}
        """)
        open_url = latest_prerelease_info.release_url

    if (
        msgbox.show(
            title=TITLE,
            text=message,
            style=msgbox.Style.MB_YESNO | msgbox.Style.MB_ICONQUESTION | msgbox.Style.MB_SETFOREGROUND,
        )
        == msgbox.ReturnValues.IDYES
    ):
        webbrowser.open(open_url)

    return UpdateCheckOutcome.PROCEED
