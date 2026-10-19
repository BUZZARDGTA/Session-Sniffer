"""Pydantic models for detection action settings and detections.json persistence."""

from pydantic import BaseModel, ConfigDict, Field

from session_sniffer.models.combo_rules import ComboRule, DetectionActionBase


class DetectionActionSettings(DetectionActionBase):
    """Base settings for a detection type action."""

    enabled: bool = False


class ListDetectionActionSettings(DetectionActionSettings):
    """Settings for detections that include a target string list (Country, ISP, ASN)."""

    model_config = ConfigDict(extra='ignore', populate_by_name=True)

    target_list: list[str] = Field(default_factory=list, validation_alias='list', serialization_alias='list')


class Gta5RelayDetectionActionSettings(DetectionActionSettings):
    """Settings for GTA5 Relay detection."""

    packet_threshold: int = 40


class DetectionsFile(BaseModel):
    """Validated model for the complete detections.json file."""

    model_config = ConfigDict(extra='ignore', populate_by_name=True)

    mobile: DetectionActionSettings = Field(default_factory=DetectionActionSettings)
    vpn: DetectionActionSettings = Field(default_factory=DetectionActionSettings)
    hosting: DetectionActionSettings = Field(default_factory=DetectionActionSettings)
    country: ListDetectionActionSettings = Field(default_factory=ListDetectionActionSettings)
    isp: ListDetectionActionSettings = Field(default_factory=ListDetectionActionSettings)
    asn: ListDetectionActionSettings = Field(default_factory=ListDetectionActionSettings)
    player_join: DetectionActionSettings = Field(default_factory=DetectionActionSettings)
    player_rejoin: DetectionActionSettings = Field(default_factory=DetectionActionSettings)
    player_leave: DetectionActionSettings = Field(default_factory=DetectionActionSettings)
    gta5_relay: Gta5RelayDetectionActionSettings = Field(default_factory=Gta5RelayDetectionActionSettings)
    combo_rules: list[ComboRule] | None = None
