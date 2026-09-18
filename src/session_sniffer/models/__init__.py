"""Pydantic models for API response validation.

This module contains pydantic models for validating JSON responses from various APIs:
- GitHub Versions API (version checking)
- GitHub Release API (GeoLite2 database updates)
- IP-API batch lookup (IP geolocation)
"""

from .combo_rules import ComboRule
from .detections import DetectionActionSettings, DetectionsFile, Gta5RelayDetectionActionSettings, ListDetectionActionSettings
from .discord_rpc import (
    DiscordActivity,
    DiscordActivityArgs,
    DiscordActivityButton,
    DiscordActivityTimestamps,
    DiscordClosePayload,
    DiscordCommandPayload,
    DiscordHandshakePayload,
    DiscordResponsePayload,
)
from .github_release import GithubReleaseAsset, GithubReleaseResponse
from .github_versions import GithubVersionsResponse, VersionInfo
from .gui_state import GUIState
from .ip_api import IpApiResponse
from .sessions_log import SessionLogFile

__all__ = [
    'ComboRule',
    'DetectionActionSettings',
    'DetectionsFile',
    'DiscordActivity',
    'DiscordActivityArgs',
    'DiscordActivityButton',
    'DiscordActivityTimestamps',
    'DiscordClosePayload',
    'DiscordCommandPayload',
    'DiscordHandshakePayload',
    'DiscordResponsePayload',
    'GUIState',
    'GithubReleaseAsset',
    'GithubReleaseResponse',
    'GithubVersionsResponse',
    'Gta5RelayDetectionActionSettings',
    'IpApiResponse',
    'ListDetectionActionSettings',
    'SessionLogFile',
    'VersionInfo',
]
