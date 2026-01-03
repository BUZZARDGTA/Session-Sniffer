"""Result types for version fetch attempts."""

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from modules.models import GithubVersionsResponse


@dataclass(slots=True)
class VersionFetchFailure:
    """Outcome of a version fetch attempt that failed."""
    exception: Exception
    http_code: int | None


@dataclass(slots=True)
class VersionFetchSuccess:
    """Outcome of a version fetch attempt that succeeded."""
    versions: GithubVersionsResponse


VersionFetchResult = VersionFetchFailure | VersionFetchSuccess
