"""Module for defining constants that don't require imports or functions, using only pure Python."""

MIN_PORT: int = 1
MAX_PORT: int = 65535
WEBSERVER_DEFAULT_HOST: str = '0.0.0.0'  # noqa: S104
WEBSERVER_DEFAULT_PORT: int = 80
TITLE: str = 'Session Sniffer'
DISCORD_INVITE_URL: str = 'https://discord.gg/hMZ7MsPX7G'
LOOKY_BASE_HOST: str = 'https://looky-gta.cc'
GITHUB_REPO_URL: str = 'https://github.com/BUZZARDGTA/Session-Sniffer'
GITHUB_ISSUES_URL: str = 'https://github.com/BUZZARDGTA/Session-Sniffer/issues'
GITHUB_RELEASES_URL: str = 'https://github.com/BUZZARDGTA/Session-Sniffer/releases'
GITHUB_VERSIONS_URL: str = 'https://raw.githubusercontent.com/BUZZARDGTA/Session-Sniffer/version/release_versions.json'
GITHUB_WIKI_URL: str = 'https://github.com/BUZZARDGTA/Session-Sniffer/wiki'
GITHUB_WIKI_TIPS_URL: str = 'https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Tips-and-Tricks'
GITHUB_LICENSE_URL: str = 'https://github.com/BUZZARDGTA/Session-Sniffer/blob/main/COPYING'
GITHUB_WIKI_SCRIPT_CONFIG_URL: str = 'https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#script-settings-configuration'
GITHUB_WIKI_USERIP_CONFIG_URL: str = 'https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#userip-ini-databases-configuration'

# Port numbers used by protocol-specific capture filters.
SSDPP_PORT: int = 1900
RAKNET_PORT: int = 19132
UAUDP_PORT: int = 4569
CLASSICSTUN_PORT: int = 3478
LLMNR_PORT: int = 5355

# Setting names for payload-inspection-based capture filters.
CAPTURE_FILTER_BLOCK_PAYLOAD_SETTINGS: tuple[str, ...] = (
    'CAPTURE_FILTER_BLOCK_RTCP',
    'CAPTURE_FILTER_BLOCK_DTLS',
)

# Setting names for port-based capture filters.
CAPTURE_FILTER_BLOCK_PORT_SETTINGS: tuple[str, ...] = (
    'CAPTURE_FILTER_BLOCK_SSDP',
    'CAPTURE_FILTER_BLOCK_RAKNET',
    'CAPTURE_FILTER_BLOCK_UAUDP',
    'CAPTURE_FILTER_BLOCK_CLASSICSTUN',
    'CAPTURE_FILTER_BLOCK_LLMNR',
)

# Combined tuple of all capture filter block settings (payload + port).
CAPTURE_FILTER_BLOCK_SETTINGS: tuple[str, ...] = (
    *CAPTURE_FILTER_BLOCK_PAYLOAD_SETTINGS,
    *CAPTURE_FILTER_BLOCK_PORT_SETTINGS,
)

# Maximum duration in seconds for suspend rules and actions.
MAX_SUSPEND_DURATION_SECONDS: int = 3600

# Default display color for detected server table rows.
DEFAULT_DETECTED_SERVER_COLOR: str = 'purple'
