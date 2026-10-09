"""Core rendering loop that compiles GUI payloads from runtime state."""

import logging
import threading
import time
from datetime import datetime
from itertools import chain
from operator import attrgetter
from threading import Thread
from typing import TYPE_CHECKING

from session_sniffer.background.events import gui_closed__event
from session_sniffer.background.tasks import handle_detection_notification, process_userip_task
from session_sniffer.constants.local import SESSIONS_LOGGING_DIR_PATH
from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.core import ScriptControl
from session_sniffer.discord.rpc import DiscordRPC
from session_sniffer.discord.webhook import DiscordWebhookPayload, DiscordWebhookSender
from session_sniffer.gta5.suspend_manager import GTASuspendManager
from session_sniffer.guis.html_templates import generate_gui_header_html
from session_sniffer.models import SessionLogFile
from session_sniffer.models.player import Player, PlayerBandwidth, PlayerModMenus
from session_sniffer.networking.geolite2 import extract_asn_info, extract_city_info, extract_country_info
from session_sniffer.networking.port_scanner import get_active_port_scan_threads
from session_sniffer.player.registry import (
    MAXIMUM_PACKETS_FOR_RELAY_SESSION_HOST,
    MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST,
    SESSION_HOST_CANDIDATE_PLAYERS_COUNT,
    SESSION_HOST_MAX_PACKETS_FOR_DETECTION,
    SESSION_HOST_SEARCH_TIMEOUT_SECONDS,
    SESSION_HOST_STARTUP_WINDOW_SECONDS,
    PlayersRegistry,
    SessionHost,
    SessionTracker,
)
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.player.userip_loader import update_userip_databases
from session_sniffer.rdr2.suspend_manager import RDR2SuspendManager
from session_sniffer.rendering_core.country_flags import get_country_flag
from session_sniffer.rendering_core.events import rendering_wake_event
from session_sniffer.rendering_core.modmenu_logs_parser import ModMenuLogsParser
from session_sniffer.rendering_core.session_table_renderer import (
    SessionTableRenderContext,
    build_session_table_snapshot,
    format_player_ip,
    format_player_middle_ports,
    format_player_ports,
    format_player_usernames,
)
from session_sniffer.rendering_core.status_bar_renderer import build_gui_status_text
from session_sniffer.rendering_core.types import (
    CaptureState,
    GeoIP2Readers,
    GUIColumnConfig,
    GUIRenderingSnapshot,
    GUIRenderingState,
    GUIStatusTexts,
    GUITableData,
    SessionTableSnapshot,
)
from session_sniffer.rendering_core.webhook_text_renderer import build_webhook_mobile_text, build_webhook_table_text
from session_sniffer.settings import Settings
from session_sniffer.text_utils import format_elapsed_time, pluralize
from session_sniffer.utils import cleanup_session_logs, dedup_preserve_order, get_session_log_path

if TYPE_CHECKING:
    from session_sniffer.capture.packet_capture import CaptureHolder

logger = logging.getLogger(__name__)

_THREAD_COUNT_WARN_THRESHOLD = 150


DISCORD_APPLICATION_ID = 1313304495958261781
SESSIONS_LOGGING_PATH = get_session_log_path(SESSIONS_LOGGING_DIR_PATH, LOCAL_TZ)
DISCORD_PRESENCE_UPDATE_INTERVAL_SECONDS = 3.0
DISCORD_WEBHOOK_UPDATE_INTERVAL_SECONDS = 1.0


def rendering_core(
    capture_holder: CaptureHolder,
    geoip2_readers: GeoIP2Readers,
) -> None:
    """Compile GUI payloads from runtime state and emit updates."""

    def get_country_info(ip_address: str) -> tuple[str, str]:
        reader = geoip2_readers.country_reader if geoip2_readers.enabled else None
        return extract_country_info(reader, ip_address)

    def get_city_info(ip_address: str) -> str:
        reader = geoip2_readers.city_reader if geoip2_readers.enabled else None
        return extract_city_info(reader, ip_address)

    def get_asn_info(ip_address: str) -> str:
        reader = geoip2_readers.asn_reader if geoip2_readers.enabled else None
        return extract_asn_info(reader, ip_address)

    _disconnected_json_cache: dict[str, tuple[tuple[object, ...], dict[str, object]]] = {}
    _session_logging_writing: bool = False
    _session_logging_lock = threading.Lock()

    def process_session_logging() -> None:
        nonlocal _session_logging_writing
        # JSON session snapshots are the canonical persisted format.
        SESSIONS_LOGGING_PATH.parent.mkdir(parents=True, exist_ok=True)

        def format_player_logging_datetime(player_datetime: datetime) -> str:
            return player_datetime.strftime('%m/%d/%Y %H:%M:%S.%f')[:-3]

        def _format_lookup_text(value: object) -> str:
            return str(value)

        def _player_columns(player: Player) -> dict[str, object]:
            mobile_value = None if not player.iplookup.ipapi.is_initialized else player.iplookup.ipapi.mobile
            vpn_value = None if not player.iplookup.ipapi.is_initialized else player.iplookup.ipapi.proxy
            hosting_value = None if not player.iplookup.ipapi.is_initialized else player.iplookup.ipapi.hosting

            return {
                'Usernames': format_player_usernames(player),
                'First Seen': format_player_logging_datetime(player.datetime.first_seen),
                'Last Rejoin': format_player_logging_datetime(player.datetime.last_rejoin),
                'Last Seen': format_player_logging_datetime(player.datetime.last_seen),
                'T. Session Time': format_elapsed_time(player.datetime.get_total_session_time()),
                'Session Time': format_elapsed_time(player.datetime.get_session_time()),
                'Biggest Session Time': format_elapsed_time(player.datetime.get_biggest_session_time()),
                'Lowest Session Time': format_elapsed_time(player.datetime.get_lowest_session_time()),
                'Rejoins': player.rejoins,
                'T. Packets': player.packets.total_exchanged,
                'Packets': player.packets.exchanged,
                'T. Packets Received': player.packets.total_received,
                'Packets Received': player.packets.received,
                'T. Packets Sent': player.packets.total_sent,
                'Packets Sent': player.packets.sent,
                'T. Min Packet Length': player.packets.total_min_len,
                'Min Packet Length': player.packets.min_len,
                'T. Avg Packet Length': round(player.packets.total_avg_len, 1),
                'Avg Packet Length': round(player.packets.avg_len, 1),
                'T. Max Packet Length': player.packets.total_max_len,
                'Max Packet Length': player.packets.max_len,
                'PPS': player.packets.pps.calculated_rate,
                'PPM': player.packets.ppm.calculated_rate,
                'T. Bandwidth': PlayerBandwidth.format_bytes(player.bandwidth.total_exchanged),
                'Bandwidth': PlayerBandwidth.format_bytes(player.bandwidth.exchanged),
                'T. Download': PlayerBandwidth.format_bytes(player.bandwidth.total_download),
                'Download': PlayerBandwidth.format_bytes(player.bandwidth.download),
                'T. Upload': PlayerBandwidth.format_bytes(player.bandwidth.total_upload),
                'Upload': PlayerBandwidth.format_bytes(player.bandwidth.upload),
                'BPS': PlayerBandwidth.format_bytes(player.bandwidth.bps.calculated_rate),
                'BPM': PlayerBandwidth.format_bytes(player.bandwidth.bpm.calculated_rate),
                'IP Address': format_player_ip(player.ip),
                'Hostname': player.reverse_dns.hostname,
                'Ports': format_player_ports(player),
                'Last Port': player.ports.last,
                'Middle Ports': format_player_middle_ports(player),
                'First Port': player.ports.first,
                'Continent': _format_lookup_text(player.iplookup.ipapi.continent),
                'Country': _format_lookup_text(player.iplookup.geolite2.country),
                'Region': _format_lookup_text(player.iplookup.ipapi.region),
                'R. Code': _format_lookup_text(player.iplookup.ipapi.region_code),
                'City': _format_lookup_text(player.iplookup.geolite2.city),
                'District': _format_lookup_text(player.iplookup.ipapi.district),
                'ZIP Code': _format_lookup_text(player.iplookup.ipapi.zip_code),
                'Lat': _format_lookup_text(player.iplookup.ipapi.lat),
                'Lon': _format_lookup_text(player.iplookup.ipapi.lon),
                'Time Zone': _format_lookup_text(player.iplookup.ipapi.time_zone),
                'Offset': _format_lookup_text(player.iplookup.ipapi.offset),
                'Currency': _format_lookup_text(player.iplookup.ipapi.currency),
                'Organization': _format_lookup_text(player.iplookup.ipapi.org),
                'ISP': _format_lookup_text(player.iplookup.ipapi.isp),
                'ASN / ISP': _format_lookup_text(player.iplookup.geolite2.asn),
                'AS': _format_lookup_text(player.iplookup.ipapi.asn),
                'ASN': _format_lookup_text(player.iplookup.ipapi.as_name),
                'Mobile': mobile_value,
                'VPN': vpn_value,
                'Hosting': hosting_value,
                'Pinging': player.ping.is_pinging if player.ping.is_initialized else None,
            }

        def _player_to_json_dict(player: Player) -> dict[str, object]:
            columns = _player_columns(player)
            return {
                'Usernames': player.usernames,
                'First Seen': player.datetime.first_seen.isoformat(),
                'Last Rejoin': player.datetime.last_rejoin.isoformat(),
                'Last Seen': player.datetime.last_seen.isoformat(),
                'T. Session Time': player.datetime.get_total_session_time().total_seconds(),
                'Session Time': player.datetime.get_session_time().total_seconds(),
                'Biggest Session Time': player.datetime.get_biggest_session_time().total_seconds(),
                'Lowest Session Time': player.datetime.get_lowest_session_time().total_seconds(),
                'Rejoins': player.rejoins,
                'T. Packets': player.packets.total_exchanged,
                'Packets': player.packets.exchanged,
                'T. Packets Received': player.packets.total_received,
                'Packets Received': player.packets.received,
                'T. Packets Sent': player.packets.total_sent,
                'Packets Sent': player.packets.sent,
                'T. Min Packet Length': player.packets.total_min_len,
                'Min Packet Length': player.packets.min_len,
                'T. Avg Packet Length': player.packets.total_avg_len,
                'Avg Packet Length': player.packets.avg_len,
                'T. Max Packet Length': player.packets.total_max_len,
                'Max Packet Length': player.packets.max_len,
                'PPS': player.packets.pps.calculated_rate,
                'PPM': player.packets.ppm.calculated_rate,
                'T. Bandwidth': player.bandwidth.total_exchanged,
                'Bandwidth': player.bandwidth.exchanged,
                'T. Download': player.bandwidth.total_download,
                'Download': player.bandwidth.download,
                'T. Upload': player.bandwidth.total_upload,
                'Upload': player.bandwidth.upload,
                'BPS': player.bandwidth.bps.calculated_rate,
                'BPM': player.bandwidth.bpm.calculated_rate,
                'IP Address': format_player_ip(player.ip),
                'Hostname': player.reverse_dns.hostname,
                'Ports': format_player_ports(player),
                'Last Port': player.ports.last,
                'Middle Ports': format_player_middle_ports(player),
                'First Port': player.ports.first,
                'Continent': player.iplookup.ipapi.continent,
                'Country': player.iplookup.geolite2.country,
                'Country Code': player.iplookup.geolite2.country_code,
                'Region': player.iplookup.ipapi.region,
                'R. Code': player.iplookup.ipapi.region_code,
                'City': player.iplookup.geolite2.city,
                'District': player.iplookup.ipapi.district,
                'ZIP Code': player.iplookup.ipapi.zip_code,
                'Lat': player.iplookup.ipapi.lat,
                'Lon': player.iplookup.ipapi.lon,
                'Time Zone': player.iplookup.ipapi.time_zone,
                'Offset': player.iplookup.ipapi.offset,
                'Currency': player.iplookup.ipapi.currency,
                'Organization': player.iplookup.ipapi.org,
                'ISP': player.iplookup.ipapi.isp,
                'ASN / ISP': player.iplookup.geolite2.asn,
                'AS': player.iplookup.ipapi.asn,
                'ASN': player.iplookup.ipapi.as_name,
                'Mobile': player.iplookup.ipapi.mobile,
                'VPN': player.iplookup.ipapi.proxy,
                'Hosting': player.iplookup.ipapi.hosting,
                'Pinging': player.ping.is_pinging,
                'columns': columns,
            }

        def _get_player_json_dict(player: Player) -> dict[str, object]:
            if player.left_event.is_set():
                lookup_key = (
                    player.rejoins,
                    player.iplookup.geolite2.is_initialized,
                    player.iplookup.ipapi.is_initialized,
                    player.reverse_dns.is_initialized,
                    player.looky_system.is_initialized,
                )
                cached = _disconnected_json_cache.get(player.ip)
                if cached is not None and cached[0] == lookup_key:
                    return cached[1]
                data = _player_to_json_dict(player)
                _disconnected_json_cache[player.ip] = (lookup_key, data)
                return data
            return _player_to_json_dict(player)

        with _session_logging_lock:
            if _session_logging_writing:
                return
            _session_logging_writing = True

        snapshot_model = SessionLogFile(
            connected={player.ip: _get_player_json_dict(player) for player in session_connected},
            disconnected={player.ip: _get_player_json_dict(player) for player in session_disconnected},
        )

        def _write_session_logging_task(model_snapshot: SessionLogFile) -> None:
            nonlocal _session_logging_writing
            try:
                json_path = SESSIONS_LOGGING_PATH.with_suffix('.json')
                json_path.write_text(model_snapshot.model_dump_json(by_alias=True), encoding='utf-8')
            finally:
                with _session_logging_lock:
                    _session_logging_writing = False

        Thread(target=_write_session_logging_task, args=(snapshot_model,), name='SessionLoggingWriter', daemon=True).start()

    def process_gui_session_tables_rendering() -> SessionTableSnapshot:
        return build_session_table_snapshot(
            SessionTableRenderContext(
                session_connected=session_connected,
                session_disconnected=session_disconnected,
                connected_shown_columns=connected_shown_columns,
                disconnected_shown_columns=disconnected_shown_columns,
                connected_num_columns=connected_num_columns,
                disconnected_num_columns=disconnected_num_columns,
                connected_column_mapping=connected_column_mapping,
            ),
        )

    def generate_gui_status_text() -> tuple[str, str, str, str]:
        return build_gui_status_text(
            capture=capture,
            discord_rpc_manager=discord_rpc_manager,
        )

    last_userip_parse_time = None
    last_session_logging_processing_time = None
    last_modmenu_refresh_time: float | None = None
    _has_players_for_poll: bool = False
    _relay_host_logged_ip: str | None = None
    _last_recorded_host_ip: str | None = None
    _sniffer_just_started: bool = True
    _sniffer_start_time: float = time.monotonic()
    _session_host_was_active: bool = False
    _session_ended: bool = False
    _session_transitioned_for_pending_disconnections: bool = False
    last_webhook_submit_time: float | None = None
    discord_rpc_manager: DiscordRPC | None = None
    discord_webhook_sender: DiscordWebhookSender | None = None
    _last_column_key: tuple[tuple[str, ...], tuple[str, ...]] | None = None
    connected_shown_columns: set[str] = set()
    disconnected_shown_columns: set[str] = set()
    connected_column_names: list[str] = []
    disconnected_column_names: list[str] = []
    connected_num_columns = 0
    disconnected_num_columns = 0
    connected_column_mapping: dict[str, int] = {}
    _userip_not_found: set[str] = set()

    def _process_player_disconnections(connected: list[Player], disconnected: list[Player]) -> list[int]:
        if not Settings.gui_disconnected_players_enabled:
            for player in disconnected:
                player.left_event.clear()
                PlayersRegistry.move_player_to_connected(player)
                connected.append(player)
            disconnected.clear()
            return []

        to_disconnect: list[int] = []
        now = datetime.now(tz=LOCAL_TZ)
        for i, player in enumerate(connected):
            if player.left_event.is_set() or (now - player.datetime.last_seen).total_seconds() < Settings.gui_disconnected_players_timer:
                continue
            player.mark_as_left()
            player.detection_checked = False
            player.relay_monitor_started = False
            to_disconnect.append(i)
            disconnected.append(player)

            if player.userip_detection and player.userip_detection.as_processed_task:
                player.userip_detection.as_processed_task = False
                disconnected_userip = player.userip or UserIPDatabases.resolve_userip(player.ip)
                if disconnected_userip is None:
                    logger.warning('No UserIP found for disconnecting player ip=%s — skipping disconnected UserIP task', player.ip)
                else:
                    Thread(
                        target=process_userip_task,
                        name=f'ProcessUserIPTask-{player.ip}-disconnected',
                        args=(player, disconnected_userip, 'disconnected'),
                        daemon=True,
                    ).start()

            handle_detection_notification(player, 'player_left_session')
        return to_disconnect

    # Perform session log cleanup once at startup in a background thread so startup is not delayed
    Thread(
        target=cleanup_session_logs,
        kwargs={
            'sessions_dir': SESSIONS_LOGGING_DIR_PATH,
            'delete_empty_files': Settings.gui_sessions_logging_delete_empty_files,
            'delete_empty_folders': Settings.gui_sessions_logging_delete_empty_folders,
            'gui_sessions_logging': Settings.gui_sessions_logging,
            'active_session_path': SESSIONS_LOGGING_PATH.with_suffix('.json'),
        },
        name='CleanupSessionLogs',
        daemon=True,
    ).start()

    while not gui_closed__event.is_set():
        capture = capture_holder.get()  # Resolve the active capture each iteration

        if ScriptControl.has_crashed():
            break

        _userip_db_rebuilt = False
        _poll_interval = 1.0 if _has_players_for_poll else 5.0
        if last_userip_parse_time is None or time.monotonic() - last_userip_parse_time >= _poll_interval:
            last_userip_parse_time, _userip_db_rebuilt = update_userip_databases()
            if _userip_db_rebuilt:
                _userip_not_found.clear()

        if Settings.is_gta5_feature_set():
            if last_modmenu_refresh_time is None or time.monotonic() - last_modmenu_refresh_time >= _poll_interval:
                ModMenuLogsParser.refresh()
                last_modmenu_refresh_time = time.monotonic()
            all_modmenu_usernames = ModMenuLogsParser.get_all_ip_to_usernames_map()
        else:
            all_modmenu_usernames = {}

        session_connected, session_disconnected = PlayersRegistry.get_connected_and_disconnected_players()
        players_to_disconnect = _process_player_disconnections(session_connected, session_disconnected)

        # Nudge the GTA5 / RDR2 suspend monitor so reasons waiting on a player 'left' event
        # resume the process immediately instead of waiting for the next poll cycle.
        if players_to_disconnect:
            if Settings.is_gta5_feature_set():
                GTASuspendManager.wake()
            elif Settings.is_rdr2_feature_set():
                RDR2SuspendManager.wake()
            if 0 < Settings.gui_disconnected_players_limit < len(session_disconnected):
                session_disconnected = PlayersRegistry.get_disconnected_players()

        _active_threads = threading.active_count()
        _effective_threshold = _THREAD_COUNT_WARN_THRESHOLD + get_active_port_scan_threads()
        if _active_threads > _effective_threshold:
            logger.warning('High thread count detected: %d active threads (threshold: %d)', _active_threads, _effective_threshold)

        # Remove disconnected players from session_connected in reverse index order
        for i in reversed(players_to_disconnect):
            del session_connected[i]

        for player in chain(session_connected, session_disconnected):
            has_geo = player.country_flag is not None or player.iplookup.ipapi.is_initialized
            with player.looky_system.lock:
                looky_usernames = list(player.looky_system.usernames)
                looky_initialized = player.looky_system.is_initialized
                looky_needs_refresh = player.looky_system.needs_refresh

            if Settings.looky_enabled and Settings.is_gta5_feature_set():
                looky_complete = looky_initialized and not looky_needs_refresh and all(name in player.usernames for name in looky_usernames)
            else:
                looky_complete = True
            if player.left_event.is_set() and not _userip_db_rebuilt and player.iplookup.geolite2.is_initialized and has_geo and looky_complete:
                continue

            if _userip_db_rebuilt:
                if not UserIPDatabases.is_known_ip(player.ip):
                    player.userip = None
                    player.userip_detection = None
                    _userip_not_found.discard(player.ip)
                else:
                    resolved = UserIPDatabases.resolve_userip(player.ip)
                    if resolved is not None:
                        player.userip = resolved
                        _userip_not_found.discard(player.ip)
                    else:
                        player.userip = None
                        _userip_not_found.add(player.ip)
            elif player.userip is None and player.ip not in _userip_not_found:
                resolved = UserIPDatabases.resolve_userip(player.ip)
                if resolved is None:
                    _userip_not_found.add(player.ip)
                else:
                    player.userip = resolved

            modmenu_usernames_for_player = all_modmenu_usernames.get(player.ip)
            if modmenu_usernames_for_player is not None and modmenu_usernames_for_player:
                if player.mod_menus is None:
                    player.mod_menus = PlayerModMenus(
                        usernames=modmenu_usernames_for_player,
                    )
                else:
                    player.mod_menus.usernames[:] = modmenu_usernames_for_player
            else:
                player.mod_menus = None

            ps3_username = player.ps3_username
            has_usernames = bool(
                ps3_username
                or (player.userip is not None and player.userip.usernames)
                or (player.mod_menus is not None and player.mod_menus.usernames)
                or (looky_initialized and looky_usernames)
            )
            if not has_usernames:
                if player.usernames:
                    player.usernames = []
            else:
                player.usernames = dedup_preserve_order(
                    (ps3_username,) if ps3_username is not None and ps3_username else (),
                    player.userip.usernames if player.userip is not None else (),
                    player.mod_menus.usernames if player.mod_menus is not None else (),
                    looky_usernames if looky_initialized else (),
                )

            if not player.iplookup.geolite2.is_initialized:
                player.iplookup.geolite2.country, player.iplookup.geolite2.country_code = get_country_info(player.ip)
                player.iplookup.geolite2.city = get_city_info(player.ip)
                player.iplookup.geolite2.asn = get_asn_info(player.ip)
                player.iplookup.geolite2.is_initialized = True

            if player.country_flag is None:
                country_code_value = (
                    player.iplookup.geolite2.country_code
                    if player.iplookup.geolite2.country_code not in {'...', 'N/A'}
                    else player.iplookup.ipapi.country_code
                    if player.iplookup.ipapi.country_code not in {'...', 'N/A'}
                    else None
                )
                if country_code_value is not None:
                    player.country_flag = get_country_flag(country_code_value)

        p2p_session_connected = [player for player in session_connected if not player.is_third_party_server]

        if Settings.is_session_host_feature_set():
            game_is_running = (
                CaptureState.is_scanning_gta5_process()
                if Settings.is_gta5_feature_set()
                else (CaptureState.rdr2_is_running or not CaptureState.is_local_capture())
            )

            if not game_is_running or not Settings.gui_session_host_detection:
                if SessionHost.has_player() or SessionHost.players_pending_for_disconnection or SessionHost.search_player or SessionHost.last_timing_gap_candidate is not None:
                    SessionHost.clear_session_host_data()
                    _session_transitioned_for_pending_disconnections = False
            else:
                game_just_started = False
                if Settings.is_gta5_feature_set() and CaptureState.gta5_just_started:
                    CaptureState.gta5_just_started = False
                    game_just_started = True
                elif Settings.is_rdr2_feature_set() and CaptureState.rdr2_just_started:
                    CaptureState.rdr2_just_started = False
                    game_just_started = True

                if game_just_started:
                    _sniffer_just_started = True
                    _sniffer_start_time = time.monotonic()
                    _session_host_was_active = False
                    _session_ended = False
                    _session_transitioned_for_pending_disconnections = False
                    _relay_host_logged_ip = None
                current_session_host = SessionHost.get_player()
                is_relay_host = current_session_host is not None and SessionHost.is_relay_host_candidate(current_session_host)
                if current_session_host is not None and current_session_host.left_event.is_set():
                    if is_relay_host and _relay_host_logged_ip != current_session_host.ip:
                        logger.debug(
                            '[SessionHost] Current host %s disconnected but is relayed (%d sent packets <= %d), keeping as host until session clears',
                            current_session_host.ip,
                            current_session_host.packets.sent,
                            MAXIMUM_PACKETS_FOR_RELAY_SESSION_HOST,
                        )
                        _relay_host_logged_ip = current_session_host.ip
                    elif not is_relay_host:
                        logger.debug('[SessionHost] Current host %s left_event is set, clearing host', current_session_host.ip)
                        _relay_host_logged_ip = None
                        SessionHost.set_player(None)
                        SessionHost.search_player = any(player.packets.pps.calculated_rate for player in p2p_session_connected if player.ip != current_session_host.ip)
                        SessionHost.search_start_time = None
                # Trigger search once every pending player has completed disconnection
                if SessionHost.players_pending_for_disconnection and all(player.left_event.is_set() for player in SessionHost.players_pending_for_disconnection):
                    if not SessionHost.has_player():
                        logger.debug(
                            '[SessionHost] All %d pending disconnection player%s have left, triggering search',
                            len(SessionHost.players_pending_for_disconnection),
                            pluralize(len(SessionHost.players_pending_for_disconnection)),
                        )
                        _relay_host_logged_ip = None
                        SessionHost.set_player(None)
                        SessionHost.search_player = True
                        SessionHost.search_start_time = None
                    if not _session_transitioned_for_pending_disconnections and p2p_session_connected:
                        SessionTracker.advance_session(players=p2p_session_connected)
                    SessionHost.players_pending_for_disconnection.clear()
                    _session_transitioned_for_pending_disconnections = False
                elif SessionHost.players_pending_for_disconnection:
                    recovered_players = [
                        player for player in SessionHost.players_pending_for_disconnection if not player.left_event.is_set() and player.packets.pps.calculated_rate
                    ]
                    if recovered_players:
                        logger.debug(
                            '[SessionHost] %d pending disconnection player%s recovered non-zero PPS, clearing from pending list (likely a transient network issue)',
                            len(recovered_players),
                            pluralize(len(recovered_players)),
                        )
                        SessionHost.players_pending_for_disconnection = [player for player in SessionHost.players_pending_for_disconnection if player not in recovered_players]

                    new_active_players = (
                        [player for player in p2p_session_connected if player not in SessionHost.players_pending_for_disconnection and player.packets.pps.calculated_rate]
                        if SessionHost.players_pending_for_disconnection
                        else []
                    )
                    if new_active_players and not _session_transitioned_for_pending_disconnections:
                        logger.debug(
                            '[SessionHost] %d new active player%s detected while %d player%s pending disconnection, resetting host and triggering search',
                            len(new_active_players),
                            pluralize(len(new_active_players)),
                            len(SessionHost.players_pending_for_disconnection),
                            pluralize(len(SessionHost.players_pending_for_disconnection)),
                        )
                        new_session_connected = [
                            player for player in p2p_session_connected if player not in SessionHost.players_pending_for_disconnection
                        ]
                        _session_transitioned_for_pending_disconnections = True
                        _relay_host_logged_ip = None
                        SessionHost.set_player(None)
                        SessionHost.search_player = True
                        SessionHost.search_start_time = None
                        SessionTracker.advance_session(players=new_session_connected)
                        _session_ended = False

                # Sniffer startup: wait the full window before deciding.
                # Players seen before the window expires suppress the search; once the window
                # elapses we snapshot whoever is still connected and either skip or allow search.
                if _sniffer_just_started:
                    elapsed_seconds = time.monotonic() - _sniffer_start_time
                    past_window = elapsed_seconds >= SESSION_HOST_STARTUP_WINDOW_SECONDS
                    if past_window:
                        _sniffer_just_started = False
                    if p2p_session_connected and past_window:
                        logger.debug(
                            '[SessionHost] Sniffer startup: %d pre-existing player%s detected within %.0fs window, skipping host search',
                            len(p2p_session_connected),
                            pluralize(len(p2p_session_connected)),
                            SESSION_HOST_STARTUP_WINDOW_SECONDS,
                        )
                        SessionHost.search_player = False
                    elif p2p_session_connected:
                        SessionHost.search_player = False

                if p2p_session_connected and _session_ended:
                    SessionTracker.advance_session(players=p2p_session_connected)
                    _session_ended = False
                if p2p_session_connected:
                    _session_host_was_active = True

                if not p2p_session_connected:
                    if _session_host_was_active and (SessionHost.has_player() or not SessionHost.search_player):
                        logger.debug('[SessionHost] No connected P2P players, resetting host and triggering search')
                    if _session_host_was_active:
                        _session_ended = True
                    _session_host_was_active = False
                    _relay_host_logged_ip = None
                    SessionHost.clear_session_host_data()
                    _session_transitioned_for_pending_disconnections = False
                    SessionHost.search_player = True
                elif all(not player.packets.pps.is_first_calculation and not player.packets.pps.calculated_rate for player in p2p_session_connected):
                    if not SessionHost.players_pending_for_disconnection:
                        logger.debug(
                            '[SessionHost] All %d connected player%s have 0 PPS (past first calc), marking as pending for disconnection',
                            len(p2p_session_connected),
                            pluralize(len(p2p_session_connected)),
                        )
                        SessionHost.players_pending_for_disconnection = list(p2p_session_connected)
                        _session_transitioned_for_pending_disconnections = False
                elif (
                    current_session_host is not None
                    and not is_relay_host
                    and not current_session_host.packets.pps.is_first_calculation
                    and not current_session_host.packets.pps.calculated_rate
                    and any(player.packets.pps.calculated_rate for player in p2p_session_connected if player.ip != current_session_host.ip)
                ):
                    idle_players = [player for player in p2p_session_connected if not player.packets.pps.calculated_rate]
                    if not SessionHost.players_pending_for_disconnection:
                        logger.debug(
                            '[SessionHost] Current host %s has 0 PPS while active players joined, marking %d idle player%s as pending disconnection',
                            current_session_host.ip,
                            len(idle_players),
                            pluralize(len(idle_players)),
                        )
                        SessionHost.players_pending_for_disconnection = idle_players
                        _session_transitioned_for_pending_disconnections = False
                elif SessionHost.search_player:
                    if SessionHost.search_start_time is None:
                        SessionHost.search_start_time = time.monotonic()
                    if (time.monotonic() - SessionHost.search_start_time) >= SESSION_HOST_SEARCH_TIMEOUT_SECONDS:
                        logger.debug(
                            '[SessionHost] Host search timed out after %ds with no result, giving up (pending: %d players). Clearing search state.',
                            SESSION_HOST_SEARCH_TIMEOUT_SECONDS,
                            len(SessionHost.players_pending_for_disconnection),
                        )
                        SessionHost.clear_session_host_data()
                        _session_transitioned_for_pending_disconnections = False
                    elif len(p2p_session_connected) != 1 or p2p_session_connected[0].packets.sent >= MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST:
                        SessionHost.get_host_player(p2p_session_connected)
                elif not SessionHost.has_player() and SessionHost.last_timing_gap_candidate is not None and len(p2p_session_connected) >= SESSION_HOST_CANDIDATE_PLAYERS_COUNT:
                    top2 = sorted(p2p_session_connected, key=attrgetter('datetime.last_rejoin'))[:SESSION_HOST_CANDIDATE_PLAYERS_COUNT]
                    current_pair = (top2[0].ip, top2[1].ip)
                    if current_pair != SessionHost.last_timing_gap_candidate:
                        logger.debug(
                            '[SessionHost] Top candidates changed from %s to %s, re-triggering search',
                            SessionHost.last_timing_gap_candidate,
                            current_pair,
                        )
                        SessionHost.last_timing_gap_candidate = None
                        SessionHost.search_player = True
                    elif top2[0].packets.exchanged > SESSION_HOST_MAX_PACKETS_FOR_DETECTION:
                        logger.debug(
                            '[SessionHost] Timing gap candidate[0] %s now has > %d packets, clearing timing gap candidate',
                            top2[0].ip,
                            SESSION_HOST_MAX_PACKETS_FOR_DETECTION,
                        )
                        SessionHost.last_timing_gap_candidate = None
                    elif top2[0].packets.sent >= MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST:
                        logger.debug(
                            '[SessionHost] Timing gap candidate[0] %s now has >= %d sent packets, re-triggering search',
                            top2[0].ip,
                            MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST,
                        )
                        SessionHost.last_timing_gap_candidate = None
                        SessionHost.search_player = True

        current_session_host = SessionHost.get_player()
        if current_session_host is not None and current_session_host.ip != _last_recorded_host_ip:
            active_session_id = SessionTracker.get_current_session_id()
            SessionTracker.record_session_host(current_session_host.ip)
            SessionHost.record_host(
                current_session_host,
                diagnostics=SessionHost.last_diagnostics,
                session_id=active_session_id,
            )
            _last_recorded_host_ip = current_session_host.ip
        elif current_session_host is None and _last_recorded_host_ip is not None:
            _last_recorded_host_ip = None

        if Settings.gui_sessions_logging and (last_session_logging_processing_time is None or (time.monotonic() - last_session_logging_processing_time) >= 1.0):
            last_session_logging_processing_time = time.monotonic()
            process_session_logging()

        # Runtime Discord RPC toggle: create or close based on current setting
        if Settings.discord_presence and discord_rpc_manager is None:
            discord_rpc_manager = DiscordRPC(client_id=DISCORD_APPLICATION_ID)
        elif not Settings.discord_presence and discord_rpc_manager is not None:
            discord_rpc_manager.close()
            discord_rpc_manager = None

        CaptureState.discord_rpc_connected = discord_rpc_manager is not None and discord_rpc_manager.connection_status.is_set()

        if discord_rpc_manager is not None and (
            discord_rpc_manager.last_update_time is None or (time.monotonic() - discord_rpc_manager.last_update_time) >= DISCORD_PRESENCE_UPDATE_INTERVAL_SECONDS
        ):
            discord_rpc_manager.update(
                state_message=f'{len(session_connected)} player{pluralize(len(session_connected))} connected',
                details=Settings.discord_presence_title or None,
            )

        # Runtime Discord Webhook toggle: create or close based on current setting
        if Settings.discord_webhook_enabled and discord_webhook_sender is None:
            discord_webhook_sender = DiscordWebhookSender.instance()
        elif not Settings.discord_webhook_enabled and discord_webhook_sender is not None:
            discord_webhook_sender.close()
            discord_webhook_sender = None

        if discord_webhook_sender is not None and (
            last_webhook_submit_time is None or (time.monotonic() - last_webhook_submit_time) >= DISCORD_WEBHOOK_UPDATE_INTERVAL_SECONDS
        ):
            last_webhook_submit_time = time.monotonic()
            use_mobile_text = Settings.discord_webhook_format in ('Mobile', 'Embed')
            webhook_connected = session_connected[: Settings.discord_webhook_max_connected_players] if Settings.discord_webhook_max_connected_players > 0 else session_connected
            webhook_disconnected = (
                session_disconnected[: Settings.discord_webhook_max_disconnected_players] if Settings.discord_webhook_max_disconnected_players > 0 else session_disconnected
            )
            if Settings.discord_webhook_include_connected:
                connected_text = (
                    build_webhook_mobile_text(webhook_connected, Settings.discord_webhook_columns_connected)
                    if use_mobile_text
                    else build_webhook_table_text(
                        webhook_connected,
                        columns=Settings.discord_webhook_columns_connected,
                        title=f'Connected ({len(session_connected)})',
                    )
                )
            else:
                connected_text = None
            if Settings.discord_webhook_include_disconnected:
                disconnected_text = (
                    build_webhook_mobile_text(webhook_disconnected, Settings.discord_webhook_columns_disconnected)
                    if use_mobile_text
                    else build_webhook_table_text(
                        webhook_disconnected,
                        columns=Settings.discord_webhook_columns_disconnected,
                        title=f'Disconnected ({len(session_disconnected)})',
                    )
                )
            else:
                disconnected_text = None
            discord_webhook_sender.submit(
                DiscordWebhookPayload(
                    connected_text=connected_text,
                    disconnected_text=disconnected_text,
                    connected_count=len(session_connected),
                    disconnected_count=len(session_disconnected),
                    generated_at=datetime.now(tz=LOCAL_TZ),
                    capture_running=capture.is_running(),
                ),
            )

        _column_key = (Settings.gui_columns_connected_shown, Settings.gui_columns_disconnected_shown)
        if _column_key != _last_column_key:
            _last_column_key = _column_key
            connected_shown_columns = set(Settings.gui_columns_connected_shown)
            disconnected_shown_columns = set(Settings.gui_columns_disconnected_shown)
            connected_column_names = [
                column_name for column_name in Settings.GUI_ALL_CONNECTED_COLUMNS if column_name in connected_shown_columns or column_name in Settings.GUI_FORCED_COLUMNS
            ]
            disconnected_column_names = [
                column_name for column_name in Settings.GUI_ALL_DISCONNECTED_COLUMNS if column_name in disconnected_shown_columns or column_name in Settings.GUI_FORCED_COLUMNS
            ]
            connected_num_columns = len(connected_column_names)
            disconnected_num_columns = len(disconnected_column_names)
            connected_column_mapping = {header: i for i, header in enumerate(connected_column_names)}
        header_text = generate_gui_header_html(capture=capture)
        (
            status_capture_text,
            status_config_text,
            status_issues_text,
            status_performance_text,
        ) = generate_gui_status_text()
        session_table_snapshot = process_gui_session_tables_rendering()

        GUIRenderingState.publish_rendering_snapshot(
            GUIRenderingSnapshot(
                column_config=GUIColumnConfig(
                    connected_shown_columns=connected_shown_columns,
                    disconnected_shown_columns=disconnected_shown_columns,
                    connected_column_names=connected_column_names,
                    disconnected_column_names=disconnected_column_names,
                ),
                status=GUIStatusTexts(
                    header_text=header_text,
                    status_capture_text=status_capture_text,
                    status_config_text=status_config_text,
                    status_issues_text=status_issues_text,
                    status_performance_text=status_performance_text,
                ),
                connected=GUITableData(
                    column_count=connected_num_columns,
                    row_count=session_table_snapshot.connected_count,
                    rows_with_colors=session_table_snapshot.connected_rows_with_colors,
                ),
                disconnected=GUITableData(
                    column_count=disconnected_num_columns,
                    row_count=session_table_snapshot.disconnected_count,
                    rows_with_colors=session_table_snapshot.disconnected_rows_with_colors,
                ),
                past_sessions={
                    session_id: GUITableData(
                        column_count=disconnected_num_columns,
                        row_count=len(rows),
                        rows_with_colors=rows,
                    )
                    for session_id, rows in session_table_snapshot.past_sessions_with_colors.items()
                },
            ),
        )

        _has_players_for_poll = bool(session_connected or session_disconnected)
        if not gui_closed__event.is_set():
            rendering_wake_event.wait(1.0)
            rendering_wake_event.clear()

    if discord_rpc_manager is not None:
        discord_rpc_manager.close()
    if discord_webhook_sender is not None:
        discord_webhook_sender.close()
