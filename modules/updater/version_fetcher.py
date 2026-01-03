"""Version fetcher for GitHub-hosted version metadata."""

import requests

from modules.constants.standalone import GITHUB_VERSIONS_URL
from modules.models import GithubVersionsResponse
from modules.networking.http_session import session
from modules.updater.result_types import (
    VersionFetchFailure,
    VersionFetchResult,
    VersionFetchSuccess,
)


def fetch_github_versions() -> VersionFetchResult:
    """Fetch and validate version metadata.

    Returns:
        VersionFetchResult: The result of the version fetch attempt.
    """
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
