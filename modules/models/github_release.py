"""Pydantic models for GitHub Release API responses.

This module provides validation for GitHub release API responses
used for GeoLite2 database updates.
"""

from datetime import (
    datetime,  # noqa: TC003  # TODO (BUZZARDGTA): unsupported in Python 3.14
)

from pydantic import BaseModel, HttpUrl


class GithubReleaseAsset(BaseModel):
    """Model for a single asset in a GitHub release."""

    name: str
    updated_at: datetime
    browser_download_url: HttpUrl


class GithubReleaseResponse(BaseModel):
    """Model for the complete GitHub release API response.

    Used to validate GitHub's "latest release" response for the GeoLite.mmdb database.
    """

    assets: list[GithubReleaseAsset]
