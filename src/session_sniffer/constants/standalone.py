"""Module for defining constants that don't require imports or functions, using only pure Python."""

MIN_PORT: int = 1
MAX_PORT: int = 65535
TITLE: str = 'Session Sniffer'
DISCORD_INVITE_URL: str = 'https://discord.gg/hMZ7MsPX7G'
GITHUB_RELEASES_URL: str = 'https://github.com/BUZZARDGTA/Session-Sniffer/releases'
GITHUB_VERSIONS_URL: str = 'https://raw.githubusercontent.com/BUZZARDGTA/Session-Sniffer/version/release_versions.json'

# Maximum number of simultaneous peer-to-peer players per game preset.
PRESET_MAX_PLAYERS: dict[str, int] = {
    # Rockstar
    'GTA5': 32,
    # Minecraft
    'Minecraft': 1,
}

# ThirdPartyServers enum member names that belong to each game preset.
# Used to detect whether game-server filtering is active and to adjust thread counts accordingly.
PRESET_GAME_SERVER_NAMES: dict[str, frozenset[str]] = {
    'GTA5': frozenset({
        'GTAV_TAKETWO',
        'GTAV_PC_MICROSOFT',
        'GTAV_PC_UK_MINISTRY_OF_DEFENCE',
        'GTAV_PC_DOD_NETWORK_INFORMATION_CENTER',
        'GTAV_PC_BATTLEYE',
        'GTAV_PS5_TELLAS_GREECE',
        'GTAV_XBOXONE_MICROSOFT',
    }),
    'Minecraft': frozenset({
        'MINECRAFTBEDROCKEDITION_PC_PS4_MICROSOFT',
    }),
}

# Shared bandwidth column → attribute-path mapping (first 6 entries identical in both
# table_model sort map and Settings.GUI_COLUMNS_MAPPING; BPS/BPM paths differ per usage).
BANDWIDTH_BASE_COLUMN_ATTRS: dict[str, str] = {
    'T. Bandwidth': 'bandwidth.total_exchanged',
    'Bandwidth': 'bandwidth.exchanged',
    'T. Download': 'bandwidth.total_download',
    'Download': 'bandwidth.download',
    'T. Upload': 'bandwidth.total_upload',
    'Upload': 'bandwidth.upload',
}
