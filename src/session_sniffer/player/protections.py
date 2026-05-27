"""Global protection settings singleton and persistence."""

import json
from typing import TYPE_CHECKING, ClassVar, Literal, cast

from session_sniffer.constants.local import PROTECTIONS_JSON_PATH
from session_sniffer.error_messages import format_type_error
from session_sniffer.text_utils import format_duration_setting, parse_duration_setting, parse_voice_notifications

if TYPE_CHECKING:
    from pathlib import Path


class GUIProtectionSettings:
    """Runtime GUI protection settings that persist during application execution and can be saved to protections.json."""

    # Mobile-based protection
    mobile_suspend_enabled: ClassVar[bool] = False
    mobile_suspend_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    mobile_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    mobile_logging: ClassVar[bool] = False
    mobile_message_box: ClassVar[bool] = False

    # VPN-based protection
    vpn_suspend_enabled: ClassVar[bool] = False
    vpn_suspend_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    vpn_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    vpn_logging: ClassVar[bool] = False
    vpn_message_box: ClassVar[bool] = False

    # Hosting-based protection
    hosting_suspend_enabled: ClassVar[bool] = False
    hosting_suspend_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    hosting_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    hosting_logging: ClassVar[bool] = False
    hosting_message_box: ClassVar[bool] = False

    # Country-based protection
    country_block_enabled: ClassVar[bool] = False
    country_block_list: ClassVar[list[str]] = []
    country_block_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    country_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    country_logging: ClassVar[bool] = False
    country_message_box: ClassVar[bool] = False

    # ISP-based protection
    isp_block_enabled: ClassVar[bool] = False
    isp_block_list: ClassVar[list[str]] = []
    isp_block_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    isp_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    isp_logging: ClassVar[bool] = False
    isp_message_box: ClassVar[bool] = False

    # ASN-based protection
    asn_block_enabled: ClassVar[bool] = False
    asn_block_list: ClassVar[list[str]] = []
    asn_block_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    asn_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    asn_logging: ClassVar[bool] = False
    asn_message_box: ClassVar[bool] = False

    # Player join protection
    player_join_enabled: ClassVar[bool] = False
    player_join_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    player_join_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    player_join_logging: ClassVar[bool] = False
    player_join_message_box: ClassVar[bool] = False

    # Player rejoin protection
    player_rejoin_enabled: ClassVar[bool] = False
    player_rejoin_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    player_rejoin_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    player_rejoin_logging: ClassVar[bool] = False
    player_rejoin_message_box: ClassVar[bool] = False

    # Player leave protection
    player_leave_enabled: ClassVar[bool] = False
    player_leave_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    player_leave_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    player_leave_logging: ClassVar[bool] = False
    player_leave_message_box: ClassVar[bool] = False

    # GTA5 relay protection (GTA5 preset only)
    gta5_relay_enabled: ClassVar[bool] = False
    gta5_relay_packet_threshold: ClassVar[int] = 40
    gta5_relay_duration: ClassVar[int | Literal['Auto']] = 'Auto'
    gta5_relay_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    gta5_relay_logging: ClassVar[bool] = False
    gta5_relay_message_box: ClassVar[bool] = False

    @classmethod
    def load_from_file_or_defaults(cls, file_path: Path) -> None:
        """Load protection settings from JSON if the file exists, otherwise keep class defaults."""
        if file_path.is_file():
            cls.import_from_file(file_path)

    @classmethod
    def _export_common_fields(cls, prefix: str) -> dict[str, object]:
        """Build the common export fields for a protection type."""
        enabled = getattr(cls, f'{prefix}_enabled', getattr(cls, f'{prefix}_suspend_enabled', False))
        duration = cast(
            'int | Literal["Auto"]',
            getattr(cls, f'{prefix}_duration', getattr(cls, f'{prefix}_suspend_duration', 'Auto')),
        )
        voice = getattr(cls, f'{prefix}_voice_notifications', False)
        return {
            'enabled': enabled,
            'duration': format_duration_setting(duration),
            'voice_notifications': str(voice) if voice else 'False',
            'logging': getattr(cls, f'{prefix}_logging', False),
            'message_box': getattr(cls, f'{prefix}_message_box', False),
        }

    @classmethod
    def export_to_file(cls, file_path: Path) -> None:
        """Export protection settings to a JSON file."""
        export_data: dict[str, dict[str, object]] = {}

        # Mobile
        export_data['mobile'] = cls._export_common_fields('mobile')

        # VPN
        vpn = cls._export_common_fields('vpn')
        export_data['vpn'] = vpn

        # Hosting
        export_data['hosting'] = cls._export_common_fields('hosting')

        # Country
        country = cls._export_common_fields('country')
        country['list'] = cls.country_block_list
        export_data['country'] = country

        # ISP
        isp = cls._export_common_fields('isp')
        isp['list'] = cls.isp_block_list
        export_data['isp'] = isp

        # ASN
        asn = cls._export_common_fields('asn')
        asn['list'] = cls.asn_block_list
        export_data['asn'] = asn

        # Player Join
        export_data['player_join'] = cls._export_common_fields('player_join')

        # Player Rejoin
        export_data['player_rejoin'] = cls._export_common_fields('player_rejoin')

        # Player Leave
        export_data['player_leave'] = cls._export_common_fields('player_leave')

        # GTA5 Relay
        gta5_relay = cls._export_common_fields('gta5_relay')
        gta5_relay['packet_threshold'] = cls.gta5_relay_packet_threshold
        export_data['gta5_relay'] = gta5_relay

        file_path.write_text(json.dumps(export_data, indent=4), encoding='utf-8')

    @classmethod
    def _import_common_fields(cls, prefix: str, section: dict[str, object]) -> None:
        """Apply common import fields from a JSON section to a protection type."""
        enabled_attr = f'{prefix}_enabled' if hasattr(cls, f'{prefix}_enabled') else f'{prefix}_suspend_enabled'
        setattr(cls, enabled_attr, section.get('enabled', False))

        duration_attr = f'{prefix}_duration' if hasattr(cls, f'{prefix}_duration') else f'{prefix}_suspend_duration'
        setattr(cls, duration_attr, parse_duration_setting(str(section.get('duration', 'Auto'))))

        voice_str = str(section.get('voice_notifications', 'False'))
        setattr(cls, f'{prefix}_voice_notifications', parse_voice_notifications(voice_str))
        setattr(cls, f'{prefix}_logging', section.get('logging', False))
        setattr(cls, f'{prefix}_message_box', section.get('message_box', False))

    @classmethod
    def import_from_file(cls, file_path: Path) -> None:
        """Import protection settings from a JSON file."""
        data: object = json.loads(file_path.read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            raise TypeError(format_type_error(data, dict))
        data_dict = cast('dict[str, dict[str, object]]', data)

        for key in ('mobile', 'vpn', 'hosting', 'player_join', 'player_rejoin', 'player_leave'):
            if key in data_dict:
                cls._import_common_fields(key, data_dict[key])

        if 'gta5_relay' in data_dict:
            cls._import_common_fields('gta5_relay', data_dict['gta5_relay'])
            raw_threshold = data_dict['gta5_relay'].get('packet_threshold', 40)
            cls.gta5_relay_packet_threshold = int(raw_threshold) if isinstance(raw_threshold, (int, float, str)) else 40

        if 'country' in data_dict:
            cls._import_common_fields('country', data_dict['country'])
            cls.country_block_list = cast('list[str]', data_dict['country'].get('list', []))

        if 'isp' in data_dict:
            cls._import_common_fields('isp', data_dict['isp'])
            cls.isp_block_list = cast('list[str]', data_dict['isp'].get('list', []))

        if 'asn' in data_dict:
            cls._import_common_fields('asn', data_dict['asn'])
            cls.asn_block_list = cast('list[str]', data_dict['asn'].get('list', []))

    @classmethod
    def save_to_settings(cls) -> None:
        """Persist current protection settings to the default protections JSON file."""
        cls.export_to_file(PROTECTIONS_JSON_PATH)
