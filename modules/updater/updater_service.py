"""Updater: GitHub version fetch + retry + UI + version comparison."""

import webbrowser
from dataclasses import dataclass
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


@dataclass(slots=True)
class VersionFetchFailure:
    """Failed version fetch."""

    exception: Exception
    http_code: int | None


@dataclass(slots=True)
class VersionFetchSuccess:
    """Successful version fetch."""

    versions: GithubVersionsResponse


VersionFetchResult = VersionFetchFailure | VersionFetchSuccess


class UpdateCheckOutcome(Enum):
    """Outcome of the update check process."""

    PROCEED = auto()
    ABORT = auto()
    IGNORE = auto()


def check_for_updates(*, updater_channel: str | None) -> UpdateCheckOutcome:
    """Orchestrate update checking.

    - fetch versions with retry + UI
    - compare versions
    - optionally open browser
    """
    versions = _fetch_versions_with_retries()
    if versions is None:
        return UpdateCheckOutcome.IGNORE

    return _handle_update_decision(
        updater_channel=updater_channel,
        versions=versions,
    )


def _fetch_versions_with_retries(*, max_attempts: int = 3) -> GithubVersionsResponse | None:
    """Fetch GitHub versions with user-driven retry policy."""
    for attempt in range(1, max_attempts + 1):
        result = _fetch_github_versions()

        if isinstance(result, VersionFetchSuccess):
            return result.versions

        choice = _show_fetch_failure_dialog(result)

        if choice == msgbox.ReturnValues.IDABORT:
            webbrowser.open(GITHUB_RELEASES_URL)
            return None

        if choice == msgbox.ReturnValues.IDIGNORE:
            return None

        if choice != msgbox.ReturnValues.IDRETRY or attempt >= max_attempts:
            return None

    return None


def _fetch_github_versions() -> VersionFetchResult:
    """Fetch and validate version metadata from GitHub."""
    try:
        response = session.get(GITHUB_VERSIONS_URL, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        return VersionFetchFailure(
            exception=exc,
            http_code=getattr(exc.response, 'status_code', None),
        )

    versions = GithubVersionsResponse.model_validate(response.json())
    return VersionFetchSuccess(versions=versions)


def _show_fetch_failure_dialog(result: VersionFetchFailure) -> int:
    """Display failure UI and return user choice."""
    exc = result.exception
    code = result.http_code

    return msgbox.show(
        title=TITLE,
        text=format_triple_quoted_text(
            format_failed_check_for_updates_message(
                exception_name=type(exc).__name__,
                http_code=str(code) if code is not None else 'No response',
            ),
        ),
        style=msgbox.Style.MB_ABORTRETRYIGNORE | msgbox.Style.MB_ICONEXCLAMATION | msgbox.Style.MB_SETFOREGROUND,
    )


def _handle_update_decision(
    *,
    updater_channel: str | None,
    versions: GithubVersionsResponse,
) -> UpdateCheckOutcome:
    """Compare versions and optionally prompt user to update."""
    current = CURRENT_VERSION

    latest_stable = Version(versions.latest_stable.version)
    latest_rc = Version(versions.latest_prerelease.version)

    candidate = latest_rc if updater_channel == 'RC' else latest_stable

    if candidate <= current:
        return UpdateCheckOutcome.PROCEED

    label = 'pre-release' if updater_channel == 'RC' else 'stable release'

    if (
        msgbox.show(
            title=TITLE,
            text=format_triple_quoted_text(f"""
            New {label} version available. Do you want to update?

            Current version: {format_project_version(current)}
            Latest version: {format_project_version(candidate)}
        """),
            style=msgbox.Style.MB_YESNO | msgbox.Style.MB_ICONQUESTION,
        )
        == msgbox.ReturnValues.IDYES
    ):
        webbrowser.open(GITHUB_RELEASES_URL)

    return UpdateCheckOutcome.PROCEED
