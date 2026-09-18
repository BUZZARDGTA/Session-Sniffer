"""Pydantic models for detection action settings and detections.json persistence."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

from session_sniffer.models.combo_rules import ComboRule
from session_sniffer.text_utils import format_suspend_duration_setting, parse_suspend_duration_setting, parse_voice_notifications


class DetectionActionSettings(BaseModel):
    """Base settings for a detection type action."""

    model_config = ConfigDict(extra='ignore')

    enabled: bool = False
    duration: int | Literal['Auto'] = 'Auto'
    voice_notifications: Literal['Male', 'Female'] | bool = False
    logging: bool = False
    message_box: bool = False

    @field_validator('duration', mode='before')
    @classmethod
    def _validate_duration(cls, value: object) -> int | Literal['Auto']:
        return parse_suspend_duration_setting(str(value) if value is not None else 'Auto')

    @field_validator('voice_notifications', mode='before')
    @classmethod
    def _validate_voice(cls, value: object) -> Literal['Male', 'Female'] | bool:
        return parse_voice_notifications(str(value) if value is not None else 'False')

    @field_serializer('duration')
    def _serialize_duration(self, duration: int | Literal['Auto']) -> str:
        return format_suspend_duration_setting(duration)

    @field_serializer('voice_notifications')
    def _serialize_voice(self, voice: object) -> str:
        return str(voice) if voice else 'False'


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
