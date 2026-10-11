"""Pydantic models for GitHub Versions API responses.

This module provides validation for the version checking API response
from the Session-Sniffer versions endpoint.
"""

import sys

from packaging.version import Version
from pydantic import BaseModel


class VersionInfo(BaseModel):
    """Model for individual version information."""

    version: str
    release_url: str
    download_url: str
    sha256: str
    file_size: int | None = None
    linux_download_url: str | None = None
    linux_sha256: str | None = None
    linux_file_size: int | None = None
    darwin_download_url: str | None = None
    darwin_sha256: str | None = None
    darwin_file_size: int | None = None
    is_prerelease: bool = False

    @property
    def is_release_prerelease(self) -> bool:
        """Return True if this version represents a pre-release."""
        return self.is_prerelease or Version(self.version).is_prerelease

    @property
    def platform_download_url(self) -> str:
        """Return platform-specific download URL."""
        if sys.platform == 'darwin' and self.darwin_download_url:
            return self.darwin_download_url
        if sys.platform.startswith('linux') and self.linux_download_url:
            return self.linux_download_url
        return self.download_url

    @property
    def platform_sha256(self) -> str:
        """Return platform-specific SHA-256."""
        if sys.platform == 'darwin' and self.darwin_sha256:
            return self.darwin_sha256
        if sys.platform.startswith('linux') and self.linux_sha256:
            return self.linux_sha256
        return self.sha256

    @property
    def platform_file_size(self) -> int | None:
        """Return platform-specific file size."""
        if sys.platform == 'darwin' and self.darwin_file_size is not None:
            return self.darwin_file_size
        if sys.platform.startswith('linux') and self.linux_file_size is not None:
            return self.linux_file_size
        return self.file_size


class GithubVersionsResponse(BaseModel):
    """Model for the complete GitHub versions API response.

    Used to validate the versions JSON response published for Session Sniffer releases.
    """

    latest_stable: VersionInfo
    latest_prerelease: VersionInfo
