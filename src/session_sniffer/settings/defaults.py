"""Default setting values for Session Sniffer."""

from dataclasses import dataclass


@dataclass
class DefaultSettings:  # pylint: disable=too-many-instance-attributes,invalid-name
    """Class containing default setting values."""
    CAPTURE_INTERFACE_NAME: str | None = None
    CAPTURE_IP_ADDRESS: str | None = None
    CAPTURE_MAC_ADDRESS: str | None = None
    CAPTURE_ARP_SPOOFING: bool = False
    CAPTURE_BLOCK_THIRD_PARTY_SERVERS: bool = True
    CAPTURE_PROGRAM_PRESET: str | None = None
    CAPTURE_OVERFLOW_TIMER: float = 3.0
    CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER: str | None = None
    CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER: str | None = None
    GUI_INTERFACE_SELECTION_AUTO_CONNECT: bool = False
    GUI_INTERFACE_SELECTION_HIDE_INACTIVE: bool = True
    GUI_INTERFACE_SELECTION_HIDE_ARP: bool = False
    GUI_SESSIONS_LOGGING: bool = True
    GUI_RESET_PORTS_ON_REJOINS: bool = True
    GUI_COLUMNS_CONNECTED_HIDDEN: tuple[str, ...] = (
        'T. Session Time', 'Session Time',
        'T. Packets', 'T. Packets Received', 'Packets Received', 'T. Packets Sent', 'Packets Sent', 'PPM',
        'T. Bandwith', 'T. Download', 'Download', 'T. Upload', 'Upload', 'BPM',
        'Middle Ports', 'First Port', 'Continent', 'R. Code', 'City', 'District', 'ZIP Code',
        'Lat', 'Lon', 'Time Zone', 'Offset', 'Currency', 'Organization', 'ISP', 'AS', 'ASN',
    )
    GUI_COLUMNS_DISCONNECTED_HIDDEN: tuple[str, ...] = (
        'T. Packets', 'T. Packets Received', 'Packets Received', 'T. Packets Sent', 'Packets Sent',
        'T. Bandwith', 'T. Download', 'Download', 'T. Upload', 'Upload',
        'Middle Ports', 'First Port', 'Continent', 'R. Code', 'City', 'District', 'ZIP Code',
        'Lat', 'Lon', 'Time Zone', 'Offset', 'Currency', 'Organization', 'ISP', 'AS', 'ASN',
    )
    GUI_COLUMNS_DATETIME_SHOW_DATE: bool = False
    GUI_COLUMNS_DATETIME_SHOW_TIME: bool = False
    GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME: bool = True
    GUI_COLUMNS_GEO_COUNTRY_APPEND_ALPHA2: bool = True
    GUI_COLUMNS_GEO_CONTINENT_APPEND_ALPHA2: bool = True
    GUI_DISCONNECTED_PLAYERS_TIMER: float = 10.0
    DISCORD_PRESENCE: bool = True
    SHOW_DISCORD_POPUP: bool = True
    UPDATER_CHANNEL: str | None = 'Stable'
