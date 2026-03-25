"""Pydantic models for API response validation.

This module contains pydantic models for validating JSON responses from various APIs:
- GitHub Versions API (version checking)
- GitHub Release API (GeoLite2 database updates)
- IP-API batch lookup (IP geolocation)
"""

from .github_release import GithubReleaseAsset, GithubReleaseResponse
from .github_versions import GithubVersionsResponse, VersionInfo
from .ip_api import IpApiResponse

__all__ = [
    'GithubReleaseAsset',
    'GithubReleaseResponse',
    'GithubVersionsResponse',
    'IpApiResponse',
    'VersionInfo',
]
