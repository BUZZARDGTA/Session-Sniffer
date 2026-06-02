"""Discord report, clipboard, ping, and block-IP actions for session table context menus."""

from typing import TYPE_CHECKING

from PyQt6.QtGui import QClipboard
from PyQt6.QtWidgets import (
    QDialog,
    QInputDialog,
    QMessageBox,
    QWidget,
)

from session_sniffer.constants.local import BIN_DIR_PATH
from session_sniffer.constants.standalone import MAX_PORT, MIN_PORT
from session_sniffer.error_messages import ensure_instance
from session_sniffer.guis.app import app
from session_sniffer.guis.tables_player_actions._fmt import (
    fmt_bool,
    fmt_loss_pct,
    fmt_ms,
    fmt_text,
    userip_database_text,
)
from session_sniffer.guis.userip_manager_helpers import IPRangeBuilderDialog
from session_sniffer.settings.settings import Settings
from session_sniffer.text_utils import pluralize
from session_sniffer.utils import run_cmd_command, run_cmd_script

if TYPE_CHECKING:
    from session_sniffer.models.player import Player

PAPING_PATH = BIN_DIR_PATH / 'paping.exe'


def build_discord_player_report(player: Player) -> str:
    """Build a Discord-formatted player info report string."""
    lines: list[str] = []
    lines.append(f'## \U0001f4ca Player Report — `{player.ip}`')
    lines.append('')

    # Player Info
    lines.append('**\U0001f464 Player Info**')
    lines.append(f'> **IP Address:** `{player.ip}`')
    hostname = fmt_text(player.reverse_dns.hostname)
    lines.append(f'> **Hostname:** `{hostname}`')
    usernames = ', '.join(player.usernames) if player.usernames else 'N/A'
    lines.append(f'> **Username{pluralize(len(player.usernames))}:** {usernames}')
    lines.append(f'> **First Port:** {player.ports.first}  |  **Last Port:** {player.ports.last}')
    middle_ports = ', '.join(map(str, player.ports.middle))
    if middle_ports:
        lines.append(f'> **Middle Port(s):** {middle_ports}')
    db_text = userip_database_text(player)
    if db_text != 'No':
        lines.append(f'> **UserIP Database:** {db_text}')
    first_seen = player.datetime.first_seen.strftime('%Y-%m-%d %H:%M:%S')
    last_seen = player.datetime.last_seen.strftime('%Y-%m-%d %H:%M:%S')
    lines.append(f'> **First Seen:** {first_seen}  |  **Last Seen:** {last_seen}')
    lines.append('')

    # Location
    country = fmt_text(player.iplookup.geolite2.country)
    country_code = fmt_text(player.iplookup.geolite2.country_code)
    continent = fmt_text(player.iplookup.ipapi.continent)
    region = fmt_text(player.iplookup.ipapi.region)
    city = fmt_text(player.iplookup.geolite2.city)
    timezone = fmt_text(player.iplookup.ipapi.time_zone)
    lines.append('**\U0001f30d Location**')
    country_display = f'{country} ({country_code})' if country != 'N/A' and country_code != 'N/A' else country
    lines.append(f'> **Country:** {country_display}')
    if continent != 'N/A':
        lines.append(f'> **Continent:** {continent}')
    if region != 'N/A':
        lines.append(f'> **Region:** {region}')
    if city != 'N/A':
        lines.append(f'> **City:** {city}')
    if timezone != 'N/A':
        lines.append(f'> **Timezone:** {timezone}')
    lines.append('')

    # Network
    isp = fmt_text(player.iplookup.ipapi.isp)
    org = fmt_text(player.iplookup.ipapi.org)
    asn = fmt_text(player.iplookup.ipapi.asn)
    as_name = fmt_text(player.iplookup.ipapi.as_name)
    mobile = fmt_bool(player.iplookup.ipapi.mobile)
    proxy = fmt_bool(player.iplookup.ipapi.proxy)
    hosting = fmt_bool(player.iplookup.ipapi.hosting)
    lines.append('**\U0001f310 Network**')
    if isp != 'N/A':
        lines.append(f'> **ISP:** {isp}')
    if org not in {'N/A', isp}:
        lines.append(f'> **Organization:** {org}')
    if asn != 'N/A':
        as_display = f'{asn} ({as_name})' if as_name != 'N/A' else asn
        lines.append(f'> **AS:** {as_display}')
    lines.append(f'> **Mobile:** {mobile}  |  **Proxy/VPN/Tor:** {proxy}  |  **Hosting:** {hosting}')
    lines.append('')

    # Ping
    avg_rtt = fmt_ms(player.ping.rtt_avg)
    packet_loss = fmt_loss_pct(player.ping.packet_loss)
    lines.append('**\U0001f4e1 Ping**')
    lines.append(f'> **Avg RTT:** {avg_rtt}  |  **Packet Loss:** {packet_loss}')

    return '\n'.join(lines)


def copy_player_info_for_discord(player: Player) -> None:
    """Copy a Discord-formatted player info report to the system clipboard."""
    clipboard = ensure_instance(app.clipboard(), QClipboard)
    clipboard.setText(build_discord_player_report(player))


def copy_players_info_for_discord(players: list[Player]) -> None:
    """Copy Discord-formatted reports for multiple players, separated by a divider."""
    clipboard = ensure_instance(app.clipboard(), QClipboard)
    separator = '\n\n---\n\n'
    clipboard.setText(separator.join(build_discord_player_report(p) for p in players))


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


def tcp_port_ping_multi(parent: QWidget, ips: list[str]) -> None:
    """Ask for a port once, then run paping for each IP on that same port."""
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

    for ip in ips:
        run_cmd_script(PAPING_PATH, [ip, '-p', str(port)])


def block_ip_as_range(parent: QWidget, ip_address: str) -> str | None:
    """Open the IP Range Builder dialog pre-filled with *ip_address* and add the result to the blocked IPs setting.

    Returns the raw range string that was added, or `None` if the user cancelled or the entry already exists.
    """
    dialog = IPRangeBuilderDialog(parent, initial_ip=ip_address)
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return None

    entry = dialog.result_entry()
    if not entry:
        return None

    if entry not in Settings.capture_blocked_ips:
        Settings.capture_blocked_ips = (*Settings.capture_blocked_ips, entry)
        Settings.rewrite_settings_file()
        Settings.rebuild_blocked_ip_ranges()

    return entry
