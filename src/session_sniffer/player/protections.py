"""Global protection settings singleton and persistence."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Literal

from session_sniffer.constants.local import PROTECTIONS_JSON_PATH


def _parse_voice_notifications(value: str) -> Literal['Male', 'Female'] | bool:
    """Parse a voice notification setting string to its typed value."""
    upper = value.upper()
    if upper == 'MALE':
        return 'Male'
    if upper == 'FEMALE':
        return 'Female'
    return False


@dataclass(kw_only=True, slots=True)
class GUIProtectionSettings:
    """Runtime GUI protection settings that persist during application execution and can be saved to settings file."""

    # Mobile-based protection
    mobile_suspend_enabled: ClassVar[bool] = False
    mobile_suspend_process_path: ClassVar[Path | None] = None
    mobile_suspend_duration: ClassVar[int | Literal['Auto', 'Manual', 'Adaptive']] = 'Auto'
    mobile_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    mobile_logging: ClassVar[bool] = False
    mobile_message_box: ClassVar[bool] = False

    # VPN-based protection
    vpn_suspend_enabled: ClassVar[bool] = False
    vpn_suspend_process_path: ClassVar[Path | None] = None
    vpn_suspend_duration: ClassVar[int | Literal['Auto', 'Manual', 'Adaptive']] = 'Auto'
    vpn_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    vpn_logging: ClassVar[bool] = False
    vpn_message_box: ClassVar[bool] = False

    # Hosting-based protection
    hosting_suspend_enabled: ClassVar[bool] = False
    hosting_suspend_process_path: ClassVar[Path | None] = None
    hosting_suspend_duration: ClassVar[int | Literal['Auto', 'Manual', 'Adaptive']] = 'Auto'
    hosting_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    hosting_logging: ClassVar[bool] = False
    hosting_message_box: ClassVar[bool] = False

    # Country-based protection
    country_block_enabled: ClassVar[bool] = False
    country_block_list: ClassVar[list[str]] = []
    country_block_process_path: ClassVar[Path | None] = None
    country_block_duration: ClassVar[int | Literal['Auto', 'Manual', 'Adaptive']] = 'Auto'
    country_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    country_logging: ClassVar[bool] = False
    country_message_box: ClassVar[bool] = False

    # ISP-based protection
    isp_block_enabled: ClassVar[bool] = False
    isp_block_list: ClassVar[list[str]] = []
    isp_block_process_path: ClassVar[Path | None] = None
    isp_block_duration: ClassVar[int | Literal['Auto', 'Manual', 'Adaptive']] = 'Auto'
    isp_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    isp_logging: ClassVar[bool] = False
    isp_message_box: ClassVar[bool] = False

    # ASN-based protection
    asn_block_enabled: ClassVar[bool] = False
    asn_block_list: ClassVar[list[str]] = []
    asn_block_process_path: ClassVar[Path | None] = None
    asn_block_duration: ClassVar[int | Literal['Auto', 'Manual', 'Adaptive']] = 'Auto'
    asn_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    asn_logging: ClassVar[bool] = False
    asn_message_box: ClassVar[bool] = False

    # Player join protection
    player_join_enabled: ClassVar[bool] = False
    player_join_process_path: ClassVar[Path | None] = None
    player_join_duration: ClassVar[int | Literal['Auto', 'Manual', 'Adaptive']] = 'Auto'
    player_join_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    player_join_logging: ClassVar[bool] = False
    player_join_message_box: ClassVar[bool] = False

    # Player rejoin protection
    player_rejoin_enabled: ClassVar[bool] = False
    player_rejoin_process_path: ClassVar[Path | None] = None
    player_rejoin_duration: ClassVar[int | Literal['Auto', 'Manual', 'Adaptive']] = 'Auto'
    player_rejoin_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    player_rejoin_logging: ClassVar[bool] = False
    player_rejoin_message_box: ClassVar[bool] = False

    # Player leave protection
    player_leave_enabled: ClassVar[bool] = False
    player_leave_process_path: ClassVar[Path | None] = None
    player_leave_duration: ClassVar[int | Literal['Auto', 'Manual', 'Adaptive']] = 'Auto'
    player_leave_voice_notifications: ClassVar[Literal['Male', 'Female'] | bool] = False
    player_leave_logging: ClassVar[bool] = False
    player_leave_message_box: ClassVar[bool] = False

    @classmethod
    def load_from_file_or_defaults(cls, file_path: Path) -> None:
        """Load protection settings from JSON if the file exists, otherwise keep class defaults."""
        if file_path.is_file():
            cls.import_from_file(file_path)

    @classmethod
    def _load_duration(cls, raw: str) -> int | Literal['Auto', 'Manual', 'Adaptive']:
        """Parse a duration setting string."""
        try:
            return int(raw)
        except ValueError:
            if raw == 'Manual':
                return 'Manual'
            if raw == 'Adaptive':
                return 'Adaptive'
            return 'Auto'

    @classmethod
    def _export_common_fields(cls, prefix: str) -> dict[str, object]:
        """Build the common export fields for a protection type."""
        enabled = getattr(cls, f'{prefix}_enabled', getattr(cls, f'{prefix}_suspend_enabled', False))
        process_path = getattr(cls, f'{prefix}_process_path', getattr(cls, f'{prefix}_suspend_process_path', None))
        duration = getattr(cls, f'{prefix}_duration', getattr(cls, f'{prefix}_suspend_duration', 'Auto'))
        voice = getattr(cls, f'{prefix}_voice_notifications', False)
        return {
            'enabled': enabled,
            'process_path': str(process_path) if process_path else '',
            'duration': str(duration),
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

        file_path.write_text(json.dumps(export_data, indent=4), encoding='utf-8')

    @classmethod
    def _import_common_fields(cls, prefix: str, section: dict[str, object]) -> None:
        """Apply common import fields from a JSON section to a protection type."""
        enabled_attr = f'{prefix}_enabled' if hasattr(cls, f'{prefix}_enabled') else f'{prefix}_suspend_enabled'
        setattr(cls, enabled_attr, section.get('enabled', False))

        path_attr = f'{prefix}_process_path' if hasattr(cls, f'{prefix}_process_path') else f'{prefix}_suspend_process_path'
        path_str = str(section.get('process_path', ''))
        setattr(cls, path_attr, Path(path_str) if path_str else None)

        duration_attr = f'{prefix}_duration' if hasattr(cls, f'{prefix}_duration') else f'{prefix}_suspend_duration'
        setattr(cls, duration_attr, cls._load_duration(str(section.get('duration', 'Auto'))))

        voice_str = str(section.get('voice_notifications', 'False'))
        setattr(cls, f'{prefix}_voice_notifications', _parse_voice_notifications(voice_str))
        setattr(cls, f'{prefix}_logging', section.get('logging', False))
        setattr(cls, f'{prefix}_message_box', section.get('message_box', False))

    @classmethod
    def import_from_file(cls, file_path: Path) -> None:
        """Import protection settings from a JSON file."""
        data = json.loads(file_path.read_text(encoding='utf-8'))

        for key in ('mobile', 'vpn', 'hosting', 'player_join', 'player_rejoin', 'player_leave'):
            if key in data:
                cls._import_common_fields(key, data[key])

        if 'country' in data:
            cls._import_common_fields('country', data['country'])
            cls.country_block_list = data['country'].get('list', [])

        if 'isp' in data:
            cls._import_common_fields('isp', data['isp'])
            cls.isp_block_list = data['isp'].get('list', [])

        if 'asn' in data:
            cls._import_common_fields('asn', data['asn'])
            cls.asn_block_list = data['asn'].get('list', [])

    @classmethod
    def save_to_settings(cls) -> None:
        """Persist current protection settings to the default protections JSON file."""
        cls.export_to_file(PROTECTIONS_JSON_PATH)
