"""Web server module for remote access to session data via web browsers."""

import sys
from pathlib import Path

from session_sniffer.ctypes_windows import is_admin
from session_sniffer.settings import Settings

from .addresses import (
    WEBSERVER_LAN_HOST,
    WEBSERVER_LOCAL_HOST,
    LocalNetworkAddress,
    detect_local_ipv4_addresses,
    format_webserver_url,
    is_loopback_ipv4,
    resolve_local_access_url,
)
from .firewall import (
    WEBSERVER_FIREWALL_RULE_NAME,
    FirewallStatus,
    allow_webserver_firewall_port,
    check_windows_firewall_status,
    format_webserver_firewall_failure,
    format_webserver_firewall_warning,
    has_managed_webserver_firewall_rule,
    remove_webserver_firewall_rule,
)
from .server import WebServer, WebServerConfig, WebServerStatus, format_webserver_error


def _sync_admin_webserver_firewall_rule() -> None:
    """Keep the managed Windows Firewall rule aligned with Web Server settings when running elevated."""
    if sys.platform != 'win32' or not is_admin() or not WebServer.is_running():
        return
    if is_loopback_ipv4(Settings.webserver_host):
        if has_managed_webserver_firewall_rule():
            remove_webserver_firewall_rule()
        return
    target_ip = Settings.webserver_host if Settings.webserver_host != WEBSERVER_LAN_HOST else None
    if check_windows_firewall_status(Settings.webserver_port, local_ip=target_ip) == 'blocked':
        allow_webserver_firewall_port(Settings.webserver_port, local_ip=target_ip)


def start_webserver_from_settings() -> None:
    """Start or restart the embedded web server using current Settings values."""
    WebServer.start_server(
        config=WebServerConfig(
            host=Settings.webserver_host,
            port=Settings.webserver_port,
            static_dir=Path(__file__).parent / 'static',
            auth_username=Settings.webserver_username,
            auth_password=Settings.webserver_password,
        ),
    )
    _sync_admin_webserver_firewall_rule()


__all__ = [
    'WEBSERVER_FIREWALL_RULE_NAME',
    'WEBSERVER_LAN_HOST',
    'WEBSERVER_LOCAL_HOST',
    'FirewallStatus',
    'LocalNetworkAddress',
    'WebServer',
    'WebServerStatus',
    'allow_webserver_firewall_port',
    'check_windows_firewall_status',
    'detect_local_ipv4_addresses',
    'format_webserver_error',
    'format_webserver_firewall_failure',
    'format_webserver_firewall_warning',
    'format_webserver_url',
    'has_managed_webserver_firewall_rule',
    'is_loopback_ipv4',
    'remove_webserver_firewall_rule',
    'resolve_local_access_url',
    'start_webserver_from_settings',
]
