"""Updater: GitHub version fetch + retry + UI + version comparison."""

import webbrowser
from enum import Enum, auto

import requests
from packaging.version import Version

from modules import msgbox
from modules.constants.local import CURRENT_VERSION
from modules.constants.standalone import (
    GITHUB_RELEASES_URL,
    GITHUB_VERSIONS_URL,
    TITLE,
)
from modules.error_messages import format_failed_check_for_updates_message
from modules.models import GithubVersionsResponse
from modules.networking.http_session import session
from modules.text_utils import format_triple_quoted_text
from modules.utils import format_project_version


class UpdateCheckOutcome(Enum):
    """Outcome of the update check process."""
    PROCEED = auto()
    IGNORE = auto()
    FAILED = auto()
    ABORT = auto()


def check_for_updates(*, updater_channel: str | None) -> UpdateCheckOutcome:
    """Fetch versions, handle failures, and prompt for update if needed."""
    outcome, versions = _fetch_versions_with_retries()

    match outcome:
        case UpdateCheckOutcome.PROCEED if versions is not None:
            return _handle_update_decision(
                updater_channel=updater_channel,
                versions=versions,
            )
        case UpdateCheckOutcome.ABORT:
            return outcome
        case UpdateCheckOutcome.IGNORE | UpdateCheckOutcome.FAILED:
            return UpdateCheckOutcome.IGNORE
        case _:
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
            raise requests.exceptions.RequestException("Simulated failure for testing retries")
        except requests.exceptions.RequestException as exc:
            http_code = exc.response.status_code if exc.response is not None else None

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
    latest_stable = Version(versions.latest_stable.version)
    latest_rc = Version(versions.latest_prerelease.version)

    is_rc_updater_channel = updater_channel == 'RC'
    candidate = latest_rc if is_rc_updater_channel else latest_stable

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
            style=msgbox.Style.MB_YESNO | msgbox.Style.MB_ICONQUESTION,
        )
        == msgbox.ReturnValues.IDYES
    ):
        webbrowser.open(GITHUB_RELEASES_URL)

    return UpdateCheckOutcome.PROCEED
