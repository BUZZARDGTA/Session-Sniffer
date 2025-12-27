"""Pydantic models for GitHub Versions API responses.

This module provides validation for the version checking API response
from the Session-Sniffer versions endpoint.
"""

from pydantic import BaseModel


class VersionInfo(BaseModel):
    """Model for individual version information."""

    version: str


class GithubVersionsResponse(BaseModel):
    """Model for the complete GitHub versions API response.

    Used to validate the versions JSON response published for Session Sniffer releases.
    """

    latest_stable: VersionInfo
    latest_prerelease: VersionInfo
