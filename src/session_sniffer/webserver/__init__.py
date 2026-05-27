"""Web server module for remote access to session data via web browsers."""

from pathlib import Path

from session_sniffer.settings import Settings

from .server import WebServer, WebServerConfig


def get_static_dir() -> Path:
    """Return the static assets directory used by the embedded web server."""
    return Path(__file__).parent / 'static'


def start_webserver(host: str, port: int, auth_username: str | None, auth_password: str | None) -> None:
    """Start or restart the embedded web server with the provided settings."""
    WebServer.start_server(
        config=WebServerConfig(
            host=host,
            port=port,
            static_dir=get_static_dir(),
            auth_username=auth_username,
            auth_password=auth_password,
        ),
    )


def start_webserver_from_settings() -> None:
    """Start or restart the embedded web server using current Settings values."""
    start_webserver(
        host=Settings.webserver_host,
        port=Settings.webserver_port,
        auth_username=Settings.webserver_username,
        auth_password=Settings.webserver_password,
    )


__all__ = ['WebServer', 'WebServerConfig', 'get_static_dir', 'start_webserver', 'start_webserver_from_settings']
