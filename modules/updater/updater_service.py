"""Update checker orchestration: UI + retry policy + version comparison."""

import webbrowser
from enum import Enum, auto
from typing import TYPE_CHECKING

from packaging.version import Version

from modules import msgbox
from modules.constants.local import CURRENT_VERSION
from modules.constants.standalone import GITHUB_RELEASES_URL, TITLE
from modules.error_messages import format_failed_check_for_updates_message
from modules.text_utils import format_triple_quoted_text
from modules.updater.result_types import VersionFetchFailure, VersionFetchSuccess
from modules.updater.version_fetcher import fetch_github_versions
from modules.utils import format_project_version

if TYPE_CHECKING:
    from modules.models import GithubVersionsResponse


class UpdateCheckOutcome(Enum):
    """Possible outcomes of an update check operation."""
    PROCEED = auto()
    ABORT = auto()
    IGNORE = auto()


def check_for_updates(*, updater_channel: str | None) -> UpdateCheckOutcome:
    """Check for updates and prompt the user if one is available."""
    max_fetch_attempts = 3
    attempts = 0

    while attempts < max_fetch_attempts:
        attempts += 1
        result = fetch_github_versions()

        match result:
            case VersionFetchSuccess(versions=versions):
                return _handle_update_logic(
                    updater_channel=updater_channel,
                    versions=versions,
                )

            case VersionFetchFailure(exception=exc, http_code=code):
                choice = msgbox.show(
                    title=TITLE,
                    text=format_triple_quoted_text(
                        format_failed_check_for_updates_message(
                            exception_name=type(exc).__name__,
                            http_code=str(code) if code is not None else 'No response',
                        ),
                    ),
                    style=msgbox.Style.MB_ABORTRETRYIGNORE | msgbox.Style.MB_ICONEXCLAMATION | msgbox.Style.MB_SETFOREGROUND,
                )

                if choice == msgbox.ReturnValues.IDABORT:
                    webbrowser.open(GITHUB_RELEASES_URL)
                    return UpdateCheckOutcome.ABORT

                if choice == msgbox.ReturnValues.IDIGNORE:
                    return UpdateCheckOutcome.IGNORE

    return UpdateCheckOutcome.IGNORE


def _handle_update_logic(*, updater_channel: str | None, versions: GithubVersionsResponse) -> UpdateCheckOutcome:
    current_version = CURRENT_VERSION

    latest_stable_version = Version(versions.latest_stable.version)
    latest_rc_version = Version(versions.latest_prerelease.version)

    update_candidate = latest_rc_version if updater_channel == 'RC' else latest_stable_version

    if update_candidate <= current_version:
        return UpdateCheckOutcome.PROCEED

    label = 'pre-release' if updater_channel == 'RC' else 'stable release'

    if msgbox.show(
        title=TITLE,
        text=format_triple_quoted_text(f"""
            New {label} version available. Do you want to update?

            Current version: {format_project_version(current_version)}
            Latest version: {format_project_version(update_candidate)}
        """),
        style=msgbox.Style.MB_YESNO | msgbox.Style.MB_ICONQUESTION,
    ) == msgbox.ReturnValues.IDYES:
        webbrowser.open(GITHUB_RELEASES_URL)

    return UpdateCheckOutcome.PROCEED
