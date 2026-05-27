"""UserIP INI file parser."""

import re
from typing import TYPE_CHECKING

from pydantic import ValidationError

from session_sniffer.error_messages import format_type_error
from session_sniffer.logging_setup import get_logger
from session_sniffer.models.userip_settings_model import UserIPSettingsModel
from session_sniffer.networking.ip_range import is_valid_ip_range_entry
from session_sniffer.player.userip import ProtectionSettings, UserIPSettings
from session_sniffer.settings.settings import RE_SETTINGS_INI_PARSER_PATTERN
from session_sniffer.utils import validate_file

if TYPE_CHECKING:
    from pathlib import Path

logger = get_logger(__name__)

RE_USERIP_INI_PARSER_PATTERN = re.compile(r'^(?![;#])(?P<username>[^=]+)=(?P<ip>[^;#]+)')

USERIP_INI_SETTINGS = [
    'ENABLED', 'COLOR', 'NOTIFICATIONS', 'VOICE_NOTIFICATIONS', 'LOG', 'PROTECTION',
    'PROTECTION_SUSPEND_PROCESS_MODE',
]

_USERIP_SETTING_DEFAULTS: dict[str, str] = {
    'ENABLED': 'True',
    'COLOR': 'White',
    'NOTIFICATIONS': 'False',
    'VOICE_NOTIFICATIONS': 'False',
    'LOG': 'False',
    'PROTECTION': 'False',
    'PROTECTION_SUSPEND_PROCESS_MODE': 'Auto',
}


def parse_userip_ini_file(ini_path: Path) -> tuple[UserIPSettings | None, dict[str, list[str]] | None]:
    """Parse a UserIP INI file and return its settings and IP-to-usernames mapping."""
    def process_ini_line_output(line: str) -> str:
        return line.strip()

    validate_file(ini_path)

    raw_settings: dict[str, str] = {}
    setting_line_indices: dict[str, int] = {}
    userip: dict[str, list[str]] = {}
    all_seen_pairs: set[tuple[str, str]] = set()
    duplicate_entries: list[tuple[str, str]] = []
    invalid_ip_entries: list[tuple[str, str]] = []
    unknown_settings: list[str] = []
    duplicate_settings: list[str] = []
    current_section = None
    matched_settings: list[str] = []
    ini_data = ini_path.read_text('utf-8')
    corrected_ini_data_lines: list[str] = []

    for line in map(process_ini_line_output, ini_data.splitlines(keepends=True)):
        if line.startswith('[') and line.endswith(']'):
            # Add a blank line before each section header for readability (unless the previous kept line is already blank).
            if corrected_ini_data_lines and corrected_ini_data_lines[-1]:
                corrected_ini_data_lines.append('')

            corrected_ini_data_lines.append(line)
            current_section = line[1:-1]
            continue

        if current_section is None:
            corrected_ini_data_lines.append(line)
            continue

        if current_section == 'Settings':
            if not (match := RE_SETTINGS_INI_PARSER_PATTERN.search(line)):
                # Keep comments; drop other non-setting lines in [Settings] so the file can be normalized on rewrite.
                if line.startswith((';', '#')):
                    corrected_ini_data_lines.append(line)
                continue

            if (setting := match.group('key')) is None:
                continue
            if not isinstance(setting, str):
                raise TypeError(format_type_error(setting, str))
            if (value := match.group('value')) is None:
                continue
            if not isinstance(value, str):
                raise TypeError(format_type_error(value, str))

            if not (setting := setting.strip()):
                continue
            if not (value := value.strip()):
                continue

            # Unknown keys are dropped from the corrected output.
            if setting not in USERIP_INI_SETTINGS:
                unknown_settings.append(setting)
                continue

            # Duplicate keys: keep the first occurrence only.
            if setting in raw_settings:
                duplicate_settings.append(setting)
                continue

            corrected_ini_data_lines.append(line)
            matched_settings.append(setting)
            raw_settings[setting] = value
            setting_line_indices[setting] = len(corrected_ini_data_lines) - 1

        elif current_section == 'UserIP':
            if not (match := RE_USERIP_INI_PARSER_PATTERN.search(line)):
                corrected_ini_data_lines.append(line)
                continue
            if (username := match.group('username')) is None:
                corrected_ini_data_lines.append(line)
                continue
            if not isinstance(username, str):
                raise TypeError(format_type_error(username, str))
            if (ip := match.group('ip')) is None:
                corrected_ini_data_lines.append(line)
                continue
            if not isinstance(ip, str):
                raise TypeError(format_type_error(ip, str))

            if not (username := username.strip()):
                corrected_ini_data_lines.append(line)
                continue
            if not (ip := ip.strip()):
                corrected_ini_data_lines.append(line)
                continue

            if not is_valid_ip_range_entry(ip):
                invalid_ip_entries.append((username, ip))
                continue

            if (username, ip) in all_seen_pairs:
                # Exact duplicate entry (same username and same IP) — drop from corrected output.
                duplicate_entries.append((username, ip))
                continue

            corrected_ini_data_lines.append(line)
            all_seen_pairs.add((username, ip))
            if username in userip:
                userip[username].append(ip)
            else:
                userip[username] = [ip]

    list_of_missing_settings = [setting for setting in USERIP_INI_SETTINGS if setting not in matched_settings]

    if invalid_ip_entries:
        for _username, _ip in invalid_ip_entries:
            logger.info('Auto-removed invalid IP entry "%s=%s" from "%s".', _username, _ip, ini_path.name)
    if duplicate_entries:
        for _username, _ip in duplicate_entries:
            logger.info('Auto-removed duplicate IP entry "%s=%s" from "%s".', _username, _ip, ini_path.name)
    if unknown_settings:
        for _setting in unknown_settings:
            logger.info('Auto-removed unknown setting "%s" from "%s".', _setting, ini_path.name)
    if duplicate_settings:
        for _setting in duplicate_settings:
            logger.info('Auto-removed duplicate setting "%s" from "%s".', _setting, ini_path.name)

    if list_of_missing_settings:
        # Ensure [Settings] header is present.
        if '[Settings]' not in corrected_ini_data_lines:
            userip_section_idx = next(
                (i for i, ln in enumerate(corrected_ini_data_lines) if ln == '[UserIP]'),
                len(corrected_ini_data_lines),
            )
            corrected_ini_data_lines.insert(userip_section_idx, '')
            corrected_ini_data_lines.insert(userip_section_idx, '[Settings]')

        # Insert each missing setting at the correct position according to USERIP_INI_SETTINGS order.
        for missing_setting in list_of_missing_settings:
            default_value = _USERIP_SETTING_DEFAULTS[missing_setting]
            new_line = f'{missing_setting}={default_value}'
            missing_pos = USERIP_INI_SETTINGS.index(missing_setting)

            # Insert after the last preceding setting that already has a known line index.
            insert_idx: int | None = None
            for preceding in reversed(USERIP_INI_SETTINGS[:missing_pos]):
                if preceding in setting_line_indices:
                    insert_idx = setting_line_indices[preceding] + 1
                    break

            if insert_idx is None:
                # No predecessor found — insert right after the [Settings] header.
                settings_header_idx = next(
                    (i for i, ln in enumerate(corrected_ini_data_lines) if ln.strip() == '[Settings]'),
                    0,
                )
                insert_idx = settings_header_idx + 1

            corrected_ini_data_lines.insert(insert_idx, new_line)

            # Shift all tracked line indices at or beyond the insertion point.
            for k in list(setting_line_indices):
                if setting_line_indices[k] >= insert_idx:
                    setting_line_indices[k] += 1

            setting_line_indices[missing_setting] = insert_idx
            raw_settings[missing_setting] = default_value
            matched_settings.append(missing_setting)

        logger.info(
            'Auto-injected %d missing setting(s) in "%s": %s',
            len(list_of_missing_settings), ini_path.name, ', '.join(list_of_missing_settings),
        )

    validated: UserIPSettingsModel | None = None
    ini_rewrites: dict[str, str] = {}
    try:
        validated, ini_rewrites = UserIPSettingsModel.validate_settings(raw_settings)
    except ValidationError as exc:
        first_error = exc.errors()[0]
        corrupted_field = str(first_error['loc'][0]) if first_error['loc'] else 'UNKNOWN'
        old_value = raw_settings.get(corrupted_field, '')
        default_value = _USERIP_SETTING_DEFAULTS.get(corrupted_field, '')
        logger.info(
            'Auto-repaired corrupted setting "%s=%s" in "%s", reset to default "%s".',
            corrupted_field, old_value, ini_path.name, default_value,
        )
        raw_settings[corrupted_field] = default_value
        if corrupted_field in setting_line_indices:
            corrected_ini_data_lines[setting_line_indices[corrupted_field]] = f'{corrupted_field}={default_value}'
        try:
            validated, ini_rewrites = UserIPSettingsModel.validate_settings(raw_settings)
        except ValidationError:
            logger.exception('Failed to validate settings in "%s" after auto-repair, skipping file.', ini_path.name)
            return None, None

    # Apply line rewrites from validated model
    for field_name, rewrite_value in ini_rewrites.items():
        if field_name in setting_line_indices:
            corrected_ini_data_lines[setting_line_indices[field_name]] = f'{field_name}={rewrite_value}'
            logger.info('Auto-normalized setting "%s" to "%s" in "%s".', field_name, rewrite_value, ini_path.name)

    # Basically always have a newline ending
    if (
        len(corrected_ini_data_lines) > 1
        and corrected_ini_data_lines[-1]
    ):
        corrected_ini_data_lines.append('')

    fixed_ini_data = '\n'.join(corrected_ini_data_lines)

    if ini_data != fixed_ini_data:
        ini_path.write_text(fixed_ini_data, encoding='utf-8')
        logger.info('Rewrote "%s" after auto-repairs.', ini_path.name)

    return UserIPSettings(
        enabled=validated.ENABLED,
        color=validated.COLOR,
        log=validated.LOG,
        notifications=validated.NOTIFICATIONS,
        voice_notifications=validated.VOICE_NOTIFICATIONS,
        protection=ProtectionSettings(
            enabled=bool(validated.PROTECTION),
            suspend_process_mode=validated.PROTECTION_SUSPEND_PROCESS_MODE,
        ),
    ), userip
