"""Version fetcher for GitHub releases API."""

from dataclasses import dataclass

import requests

from modules.models import GithubVersionsResponse


@dataclass(kw_only=True, slots=True)
class VersionFetchResult:
    """Outcome of a version fetch attempt."""

    exception: Exception | None = None
    url: str | None = None
    http_code: int | str | None = None
    versions_response: GithubVersionsResponse | None = None


def _version_fetch_result_from_exception(*, exception: requests.exceptions.RequestException, url: str) -> VersionFetchResult:
    return VersionFetchResult(exception=exception, url=url, http_code=getattr(exception.response, 'status_code', None))


def fetch_github_versions(*, session: requests.Session, versions_url: str) -> VersionFetchResult:
    """Fetch version information from GitHub API.

    Returns:
        VersionFetchResult with either exception details or parsed version data.
    """
    try:
        response = session.get(versions_url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return _version_fetch_result_from_exception(exception=e, url=versions_url)

    versions_data = response.json()
    versions_response = GithubVersionsResponse.model_validate(versions_data)

    return VersionFetchResult(versions_response=versions_response)
