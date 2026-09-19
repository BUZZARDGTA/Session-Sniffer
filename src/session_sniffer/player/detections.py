"""Global detection settings singleton and persistence."""

import json
from typing import TYPE_CHECKING, ClassVar, Literal

from pydantic import ValidationError

from session_sniffer.constants.local import DETECTIONS_JSON_PATH
from session_sniffer.logging_setup import get_logger
from session_sniffer.models.detections import (
    DetectionActionSettings,
    DetectionsFile,
    Gta5RelayDetectionActionSettings,
    ListDetectionActionSettings,
)

if TYPE_CHECKING:
    from pathlib import Path

logger = get_logger(__name__)


class GUIDetectionSettings:
    """Runtime GUI detection settings that persist during application execution and can be saved to detections.json."""

    # Mobile-based detection
    mobile_suspend_enabled: ClassVar[bool] = False
    mobile_suspend_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    mobile_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    mobile_logging: ClassVar[bool] = False
    mobile_message_box: ClassVar[bool] = False

    # VPN-based detection
    vpn_suspend_enabled: ClassVar[bool] = False
    vpn_suspend_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    vpn_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    vpn_logging: ClassVar[bool] = False
    vpn_message_box: ClassVar[bool] = False

    # Hosting-based detection
    hosting_suspend_enabled: ClassVar[bool] = False
    hosting_suspend_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    hosting_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    hosting_logging: ClassVar[bool] = False
    hosting_message_box: ClassVar[bool] = False

    # Country-based detection
    country_suspend_enabled: ClassVar[bool] = False
    country_detection_list: ClassVar[list[str]] = []
    country_suspend_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    country_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    country_logging: ClassVar[bool] = False
    country_message_box: ClassVar[bool] = False

    # ISP-based detection
    isp_suspend_enabled: ClassVar[bool] = False
    isp_detection_list: ClassVar[list[str]] = []
    isp_suspend_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    isp_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    isp_logging: ClassVar[bool] = False
    isp_message_box: ClassVar[bool] = False

    # ASN-based detection
    asn_suspend_enabled: ClassVar[bool] = False
    asn_detection_list: ClassVar[list[str]] = []
    asn_suspend_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    asn_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    asn_logging: ClassVar[bool] = False
    asn_message_box: ClassVar[bool] = False

    # Player join detection
    player_join_enabled: ClassVar[bool] = False
    player_join_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    player_join_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    player_join_logging: ClassVar[bool] = False
    player_join_message_box: ClassVar[bool] = False

    # Player rejoin detection
    player_rejoin_enabled: ClassVar[bool] = False
    player_rejoin_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    player_rejoin_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    player_rejoin_logging: ClassVar[bool] = False
    player_rejoin_message_box: ClassVar[bool] = False

    # Player leave detection
    player_leave_enabled: ClassVar[bool] = False
    player_leave_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    player_leave_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    player_leave_logging: ClassVar[bool] = False
    player_leave_message_box: ClassVar[bool] = False

    # GTA5 relay detection (GTA5 preset only)
    gta5_relay_enabled: ClassVar[bool] = False
    gta5_relay_packet_threshold: ClassVar[int] = 40
    gta5_relay_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    gta5_relay_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    gta5_relay_logging: ClassVar[bool] = False
    gta5_relay_message_box: ClassVar[bool] = False

    @classmethod
    def to_model(cls) -> DetectionsFile:
        """Convert runtime detection settings to a validated DetectionsFile model."""
        return DetectionsFile(
            mobile=DetectionActionSettings(
                enabled=cls.mobile_suspend_enabled,
                duration=cls.mobile_suspend_duration,
                voice_notifications=cls.mobile_voice_notifications,
                logging=cls.mobile_logging,
                message_box=cls.mobile_message_box,
            ),
            vpn=DetectionActionSettings(
                enabled=cls.vpn_suspend_enabled,
                duration=cls.vpn_suspend_duration,
                voice_notifications=cls.vpn_voice_notifications,
                logging=cls.vpn_logging,
                message_box=cls.vpn_message_box,
            ),
            hosting=DetectionActionSettings(
                enabled=cls.hosting_suspend_enabled,
                duration=cls.hosting_suspend_duration,
                voice_notifications=cls.hosting_voice_notifications,
                logging=cls.hosting_logging,
                message_box=cls.hosting_message_box,
            ),
            country=ListDetectionActionSettings(
                enabled=cls.country_suspend_enabled,
                duration=cls.country_suspend_duration,
                voice_notifications=cls.country_voice_notifications,
                logging=cls.country_logging,
                message_box=cls.country_message_box,
                target_list=list(cls.country_detection_list),
            ),
            isp=ListDetectionActionSettings(
                enabled=cls.isp_suspend_enabled,
                duration=cls.isp_suspend_duration,
                voice_notifications=cls.isp_voice_notifications,
                logging=cls.isp_logging,
                message_box=cls.isp_message_box,
                target_list=list(cls.isp_detection_list),
            ),
            asn=ListDetectionActionSettings(
                enabled=cls.asn_suspend_enabled,
                duration=cls.asn_suspend_duration,
                voice_notifications=cls.asn_voice_notifications,
                logging=cls.asn_logging,
                message_box=cls.asn_message_box,
                target_list=list(cls.asn_detection_list),
            ),
            player_join=DetectionActionSettings(
                enabled=cls.player_join_enabled,
                duration=cls.player_join_duration,
                voice_notifications=cls.player_join_voice_notifications,
                logging=cls.player_join_logging,
                message_box=cls.player_join_message_box,
            ),
            player_rejoin=DetectionActionSettings(
                enabled=cls.player_rejoin_enabled,
                duration=cls.player_rejoin_duration,
                voice_notifications=cls.player_rejoin_voice_notifications,
                logging=cls.player_rejoin_logging,
                message_box=cls.player_rejoin_message_box,
            ),
            player_leave=DetectionActionSettings(
                enabled=cls.player_leave_enabled,
                duration=cls.player_leave_duration,
                voice_notifications=cls.player_leave_voice_notifications,
                logging=cls.player_leave_logging,
                message_box=cls.player_leave_message_box,
            ),
            gta5_relay=Gta5RelayDetectionActionSettings(
                enabled=cls.gta5_relay_enabled,
                duration=cls.gta5_relay_duration,
                voice_notifications=cls.gta5_relay_voice_notifications,
                logging=cls.gta5_relay_logging,
                message_box=cls.gta5_relay_message_box,
                packet_threshold=cls.gta5_relay_packet_threshold,
            ),
        )

    @classmethod
    def apply_model(cls, model: DetectionsFile) -> None:
        """Apply a validated DetectionsFile model to runtime detection settings."""
        cls.mobile_suspend_enabled = model.mobile.enabled
        cls.mobile_suspend_duration = model.mobile.duration
        cls.mobile_voice_notifications = model.mobile.voice_notifications
        cls.mobile_logging = model.mobile.logging
        cls.mobile_message_box = model.mobile.message_box

        cls.vpn_suspend_enabled = model.vpn.enabled
        cls.vpn_suspend_duration = model.vpn.duration
        cls.vpn_voice_notifications = model.vpn.voice_notifications
        cls.vpn_logging = model.vpn.logging
        cls.vpn_message_box = model.vpn.message_box

        cls.hosting_suspend_enabled = model.hosting.enabled
        cls.hosting_suspend_duration = model.hosting.duration
        cls.hosting_voice_notifications = model.hosting.voice_notifications
        cls.hosting_logging = model.hosting.logging
        cls.hosting_message_box = model.hosting.message_box

        cls.country_suspend_enabled = model.country.enabled
        cls.country_suspend_duration = model.country.duration
        cls.country_voice_notifications = model.country.voice_notifications
        cls.country_logging = model.country.logging
        cls.country_message_box = model.country.message_box
        cls.country_detection_list = list(model.country.target_list)

        cls.isp_suspend_enabled = model.isp.enabled
        cls.isp_suspend_duration = model.isp.duration
        cls.isp_voice_notifications = model.isp.voice_notifications
        cls.isp_logging = model.isp.logging
        cls.isp_message_box = model.isp.message_box
        cls.isp_detection_list = list(model.isp.target_list)

        cls.asn_suspend_enabled = model.asn.enabled
        cls.asn_suspend_duration = model.asn.duration
        cls.asn_voice_notifications = model.asn.voice_notifications
        cls.asn_logging = model.asn.logging
        cls.asn_message_box = model.asn.message_box
        cls.asn_detection_list = list(model.asn.target_list)

        cls.player_join_enabled = model.player_join.enabled
        cls.player_join_duration = model.player_join.duration
        cls.player_join_voice_notifications = model.player_join.voice_notifications
        cls.player_join_logging = model.player_join.logging
        cls.player_join_message_box = model.player_join.message_box

        cls.player_rejoin_enabled = model.player_rejoin.enabled
        cls.player_rejoin_duration = model.player_rejoin.duration
        cls.player_rejoin_voice_notifications = model.player_rejoin.voice_notifications
        cls.player_rejoin_logging = model.player_rejoin.logging
        cls.player_rejoin_message_box = model.player_rejoin.message_box

        cls.player_leave_enabled = model.player_leave.enabled
        cls.player_leave_duration = model.player_leave.duration
        cls.player_leave_voice_notifications = model.player_leave.voice_notifications
        cls.player_leave_logging = model.player_leave.logging
        cls.player_leave_message_box = model.player_leave.message_box

        cls.gta5_relay_enabled = model.gta5_relay.enabled
        cls.gta5_relay_duration = model.gta5_relay.duration
        cls.gta5_relay_voice_notifications = model.gta5_relay.voice_notifications
        cls.gta5_relay_logging = model.gta5_relay.logging
        cls.gta5_relay_message_box = model.gta5_relay.message_box
        cls.gta5_relay_packet_threshold = model.gta5_relay.packet_threshold

    @classmethod
    def load_from_file_or_defaults(cls, file_path: Path) -> None:
        """Load detection settings from JSON if the file exists, otherwise keep class defaults."""
        if not file_path.is_file():
            return
        try:
            cls.import_from_file(file_path)
        except (ValidationError, json.JSONDecodeError, OSError):
            logger.exception('Failed to load detection settings from %s, keeping defaults', file_path)

    @classmethod
    def export_to_file(cls, file_path: Path) -> None:
        """Export detection settings to a JSON file."""
        file_path.parent.mkdir(parents=True, exist_ok=True)
        model = cls.to_model()
        json_str = model.model_dump_json(indent=4, exclude_none=True, by_alias=True)
        tmp_path = file_path.with_suffix('.tmp')
        tmp_path.write_text(json_str, encoding='utf-8')
        tmp_path.replace(file_path)

    @classmethod
    def import_from_file(cls, file_path: Path) -> None:
        """Import detection settings from a JSON file."""
        content = file_path.read_text(encoding='utf-8')
        model = DetectionsFile.model_validate_json(content)
        cls.apply_model(model)

    @classmethod
    def save_to_settings(cls) -> None:
        """Persist current detection settings to the default detections JSON file."""
        cls.export_to_file(DETECTIONS_JSON_PATH)
