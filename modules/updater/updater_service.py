"""Update checker orchestration: UI + retry policy + version comparison."""

import sys
import webbrowser
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


def check_for_updates(*, updater_channel: str | None) -> None:
    """Check for updates and prompt the user if one is available."""
    while True:
        result = fetch_github_versions()

        match result:
            case VersionFetchSuccess(versions=versions):
                break

            case VersionFetchFailure(exception=exc, http_code=code):
                choice = msgbox.show(
                    title=TITLE,
                    text=format_triple_quoted_text(format_failed_check_for_updates_message(
                        exception_name=type(exc).__name__,
                        http_code=str(code) if code is not None else 'No response',
                    )),
                    style=msgbox.Style.MB_ABORTRETRYIGNORE | msgbox.Style.MB_ICONEXCLAMATION | msgbox.Style.MB_SETFOREGROUND,
                )

                if choice == msgbox.ReturnValues.IDABORT:
                    webbrowser.open(GITHUB_RELEASES_URL)
                    sys.exit(0)

                if choice == msgbox.ReturnValues.IDIGNORE:
                    return

    _handle_update_logic(updater_channel=updater_channel, versions=versions)


def _handle_update_logic(*, updater_channel: str | None, versions: GithubVersionsResponse) -> None:
    current = CURRENT_VERSION

    latest_stable = Version(versions.latest_stable.version)
    latest_rc = Version(versions.latest_prerelease.version)

    target = latest_rc if updater_channel == 'RC' else latest_stable

    if target <= current:
        return

    label = 'pre-release' if updater_channel == 'RC' else 'stable release'

    if msgbox.show(
        title=TITLE,
        text=format_triple_quoted_text(f"""
            New {label} version available. Do you want to update?

            Current version: {format_project_version(current)}
            Latest version: {format_project_version(target)}
        """),
        style=msgbox.Style.MB_YESNO | msgbox.Style.MB_ICONQUESTION,
    ) == msgbox.ReturnValues.IDYES:
        webbrowser.open(GITHUB_RELEASES_URL)
