"""Web server module for remote access to session data via web browsers."""

from pathlib import Path

from session_sniffer.settings import Settings

from .server import WebServer, WebServerConfig


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


__all__ = ['WebServer', 'start_webserver_from_settings']
