"""Update checker orchestration: fetch + version comparison + UI."""

import sys
import webbrowser
from typing import TYPE_CHECKING

from packaging.version import Version

from modules import msgbox
from modules.constants.local import CURRENT_VERSION
from modules.constants.standalone import TITLE
from modules.error_messages import format_failed_check_for_updates_message
from modules.text_utils import format_triple_quoted_text
from modules.updater.version_fetcher import fetch_github_versions
from modules.utils import format_project_version

if TYPE_CHECKING:
    import requests

    from modules.models import GithubVersionsResponse

GITHUB_RELEASES_URL = 'https://github.com/BUZZARDGTA/Session-Sniffer/releases'
GITHUB_VERSIONS_URL = 'https://raw.githubusercontent.com/BUZZARDGTA/Session-Sniffer/version/release_versions.json'


def check_for_updates(
    *,
    session: requests.Session,
    updater_channel: str | None,
) -> None:
    """Check for available updates and optionally open the releases page.

    Args:
        session: HTTP session for making requests
        updater_channel: Update channel ('Stable' or 'RC'), defaults to 'Stable' if None
    """
    # Default to 'Stable' if None
    channel = updater_channel or 'Stable'

    def get_updater_json_response() -> GithubVersionsResponse | None:
        while True:
            fetch_result = fetch_github_versions(session=session, versions_url=GITHUB_VERSIONS_URL)

            if fetch_result.exception is not None:
                choice = msgbox.show(
                    title=TITLE,
                    text=format_triple_quoted_text(format_failed_check_for_updates_message(
                        app_title=TITLE,
                        exception_name=type(fetch_result.exception).__name__,
                        http_code=(f'{fetch_result.http_code}' if fetch_result.http_code else 'No response'),
                        versions_url=GITHUB_VERSIONS_URL,
                    )),
                    style=msgbox.Style.MB_ABORTRETRYIGNORE | msgbox.Style.MB_ICONEXCLAMATION | msgbox.Style.MB_SETFOREGROUND,
                )

                if choice == msgbox.ReturnValues.IDABORT:
                    webbrowser.open(GITHUB_RELEASES_URL)
                    sys.exit(0)
                elif choice == msgbox.ReturnValues.IDIGNORE:
                    return None
                # IDRETRY: loop continues
            elif fetch_result.versions_response is not None:
                return fetch_result.versions_response
            else:
                return None

    versions_response = get_updater_json_response()
    if versions_response is None:
        return

    current_version = CURRENT_VERSION

    # Get versions from the response
    latest_stable_version = Version(versions_response.latest_stable.version)
    latest_rc_version = Version(versions_response.latest_prerelease.version)

    # Check for updates based on the current version
    is_new_stable_version_available = latest_stable_version > current_version
    is_new_rc_version_available = latest_rc_version > current_version

    # Determine which version to display based on the user's channel setting
    if is_new_stable_version_available or (channel == 'RC' and is_new_rc_version_available):
        update_channel = 'pre-release' if (channel == 'RC' and is_new_rc_version_available) else 'stable release'
        latest_version = latest_rc_version if (channel == 'RC' and is_new_rc_version_available) else latest_stable_version

        if msgbox.show(
            title=TITLE,
            text=format_triple_quoted_text(f"""
                New {update_channel} version found. Do you want to update?

                Current version: {format_project_version(current_version)}
                Latest version: {format_project_version(latest_version)}
            """),
            style=msgbox.Style.MB_YESNO | msgbox.Style.MB_ICONQUESTION | msgbox.Style.MB_SETFOREGROUND,
        ) == msgbox.ReturnValues.IDYES:
            webbrowser.open(GITHUB_RELEASES_URL)
            sys.exit(0)
