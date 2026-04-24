"""Player action helpers for session table context menus (info dialogs, ping)."""

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QInputDialog, QMessageBox, QWidget

from session_sniffer.constants.local import BIN_DIR_PATH, SESSIONS_LOGGING_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import MAX_PORT, MIN_PORT, TITLE
from session_sniffer.player.seen_stats import SEEN_STATS_LABELS, analyze_sessions_logging
from session_sniffer.text_utils import format_triple_quoted_text, pluralize
from session_sniffer.utils import run_cmd_command, run_cmd_script

if TYPE_CHECKING:
    from session_sniffer.models.player import Player

PAPING_PATH = BIN_DIR_PATH / 'paping.exe'


def show_detailed_ip_lookup(parent: QWidget, player: Player) -> None:
    """Show a detailed information dialog for the given player."""
    QMessageBox.information(parent, TITLE, format_triple_quoted_text(f"""
        ############ Player Infos #############
        IP Address: {player.ip}
        Hostname: {player.reverse_dns.hostname}
        Username{pluralize(len(player.usernames))}: {', '.join(player.usernames) or ""}
        In UserIP database: {(
            player.userip_detection is not None
            and f"{player.userip and player.userip.database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')}"
        ) or "No"}
        Last Port: {player.ports.last}
        Middle Port{pluralize(len(player.ports.middle))}: {', '.join(map(str, player.ports.middle))}
        First Port: {player.ports.first}

        ########## IP Lookup Details ##########
        Continent: {player.iplookup.ipapi.continent}
        Country: {player.iplookup.geolite2.country}
        Country Code: {player.iplookup.geolite2.country_code}
        Region: {player.iplookup.ipapi.region}
        Region Code: {player.iplookup.ipapi.region_code}
        City: {player.iplookup.geolite2.city}
        District: {player.iplookup.ipapi.district}
        ZIP Code: {player.iplookup.ipapi.zip_code}
        Lat: {player.iplookup.ipapi.lat}
        Lon: {player.iplookup.ipapi.lon}
        Time Zone: {player.iplookup.ipapi.time_zone}
        Offset: {player.iplookup.ipapi.offset}
        Currency: {player.iplookup.ipapi.currency}
        Organization: {player.iplookup.ipapi.org}
        ISP: {player.iplookup.ipapi.isp}
        ASN / ISP: {player.iplookup.geolite2.asn}
        AS: {player.iplookup.ipapi.asn}
        ASN: {player.iplookup.ipapi.as_name}
        Mobile (cellular) connection: {player.iplookup.ipapi.mobile}
        Proxy, VPN or Tor exit address: {player.iplookup.ipapi.proxy}
        Hosting, colocated or data center: {player.iplookup.ipapi.hosting}

        ############ Ping Response ############
        Ping Times: {player.ping.ping_times}
        Packets Transmitted: {player.ping.packets_transmitted}
        Packets Received: {player.ping.packets_received}
        Packet Loss: {player.ping.packet_loss}
        Packet Errors: {player.ping.packet_errors}
        Round-Trip Time Minimum: {player.ping.rtt_min}
        Round-Trip Time Average: {player.ping.rtt_avg}
        Round-Trip Time Maximum: {player.ping.rtt_max}
        Round-Trip Time Mean Deviation: {player.ping.rtt_mdev}
    """),
    )


def show_seen_stats(parent: QWidget, player: Player) -> None:
    """Show historical encounter statistics for the given player IP."""
    stats = analyze_sessions_logging(SESSIONS_LOGGING_DIR_PATH, player.ip)
    lines = '\n'.join(f'{label}: {getattr(stats, key)}' for key, label in SEEN_STATS_LABELS.items())
    QMessageBox.information(parent, TITLE, format_triple_quoted_text(f"""
        ########## Seen Stats ##########
        IP Address: {player.ip}

        {lines}
    """))


def ping_ip(ip: str) -> None:
    """Run a continuous ping to a specified IP address in a new terminal window."""
    run_cmd_command('ping', [ip, '-t'])


def tcp_port_ping(parent: QWidget, ip: str) -> None:
    """Run paping to check TCP connectivity to a host on a user-specified port indefinitely."""
    port_str, ok = QInputDialog.getText(parent, 'Input Port', 'Enter the port number to check TCP connectivity:')

    if not ok:
        return

    port_str = port_str.strip()

    if not port_str.isdigit():
        QMessageBox.warning(parent, 'Error', 'No valid port number provided.')
        return

    port = int(port_str)

    if not MIN_PORT <= port <= MAX_PORT:
        QMessageBox.warning(parent, 'Error', 'Please enter a valid port number between 1 and 65535.')
        return

    run_cmd_script(PAPING_PATH, [ip, '-p', str(port)])
