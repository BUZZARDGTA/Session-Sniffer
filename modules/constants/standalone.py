"""
Module for defining constants that don't require imports or functions, using only pure Python.
"""

TITLE = "Session Sniffer"
VERSION = "v1.3.7 - 29/03/2025 (21:19)"

GITHUB_REPO_URL = "https://github.com/BUZZARDGTA/Session-Sniffer"
GITHUB_RELEASES_URL = "https://github.com/BUZZARDGTA/Session-Sniffer/releases"
GITHUB_VERSIONS_URL = "https://raw.githubusercontent.com/BUZZARDGTA/Session-Sniffer/version/versions.json"
DISCORD_INVITE_URL = "https://discord.gg/hMZ7MsPX7G"
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
GITHUB_RELEASE_API__GEOLITE2__URL = "https://api.github.com/repos/P3TERX/GeoLite.mmdb/releases/latest"
GITHUB_RELEASE_API__GEOLITE2__BACKUP__URL = "https://api.github.com/repos/PrxyHunter/GeoLite2/releases/latest"

TSHARK_RECOMMENDED_FULL_VERSION = "TShark (Wireshark) 4.2.11 (v4.2.11-0-g53ee01efc521)."
TSHARK_RECOMMENDED_VERSION_NUMBER = "4.2.11"
# TODO: NPCAP_RECOMMENDED_VERSION_NUMBER = "1.78"

DISCORD_APPLICATION_ID = 1313304495958261781
USER_SHELL_FOLDERS__REG_KEY = R"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
USERIP_INI_SETTINGS = ["ENABLED", "COLOR", "NOTIFICATIONS", "VOICE_NOTIFICATIONS", "LOG", "PROTECTION", "PROTECTION_PROCESS_PATH", "PROTECTION_RESTART_PROCESS_PATH", "PROTECTION_SUSPEND_PROCESS_MODE"]
EXCLUDED_CAPTURE_NETWORK_INTERFACES = {
    "Adapter for loopback traffic capture",
    "Event Tracing for Windows (ETW) reader"
}
GUI_COLUMN_HEADERS_TOOLTIPS = {
    "Usernames": "Displays the username(s) of players from your UserIP database files.\n\nFor GTA V PC users who have used the Session Sniffer mod menu plugin,\nit automatically resolves usernames while the plugin is running,\nor shows previously resolved players that were seen by the plugin.",
    "First Seen": "The very first time the player was observed across all sessions.",
    "Last Rejoin": "The most recent time the player rejoined your session.",
    "Last Seen": "The most recent time the player was active in your session.",
    "Rejoins": "The number of times the player has left and joined again your session across all sessions.",
    "T. Packets": "The total number of packets exchanged by the player across all sessions.",
    "Packets": "The number of packets exchanged by the player during the current session.",
    "PPS": "The number of Packets exchanged Per Second by the player.",
    "Avg PPS": "The average number of Packets exchanged Per Second by the player, based on the last 3 PPS values.",
    "PPM": "The number of packets exchanged per Minute by the player.",
    "Avg PPM": "The average number of Packets exchanged Per Minute by the player, based on the last 3 PPM values.",
    "IP Address": "The IP address of the player.",
    "Hostname": "The domain name associated with the player's IP address, resolved through a reverse DNS lookup.",
    "Last Port": "The port used by the player's last captured packet.",
    "Intermediate Ports": "The ports used by the player between the first and last captured packets.",
    "First Port": "The port used by the player's first captured packet.",
    "Continent": "The continent of the player's IP location.",
    "Country": "The country of the player's IP location.",
    "Region": "The region of the player's IP location.",
    "R. Code": "The region code of the player's IP location.",
    "City": "The city associated with the player's IP location (typically representing the ISP or an intermediate location, not the player's home address city).",
    "District": "The district of the player's IP location.",
    "ZIP Code": "The ZIP/postal code of the player's IP location.",
    "Lat": "The latitude of the player's IP location.",
    "Lon": "The longitude of the player's IP location.",
    "Time Zone": "The time zone of the player's IP location.",
    "Offset": "The time zone offset of the player's IP location.",
    "Currency": "The currency associated with the player's IP location.",
    "Organization": "The organization associated with the player's IP address.",
    "ISP": "The Internet Service Provider of the player's IP address.",
    "ASN / ISP": "The Autonomous System Number or Internet Service Provider of the player.",
    "AS": "The Autonomous System code of the player's IP.",
    "ASN": "The Autonomous System Number name associated with the player's IP.",
    "Mobile": "Indicates if the player is using a mobile network (e.g., through a cellular hotspot or mobile data).",
    "VPN": "Indicates if the player is using a VPN, Proxy, or Tor relay.",
    "Hosting": "Indicates if the player is using a hosting provider (similar to VPN).",
}
