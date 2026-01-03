"""GeoLite2 orchestration: update + initialize."""

from typing import TYPE_CHECKING

from modules import msgbox
from modules.constants.standalone import TITLE
from modules.error_messages import format_geolite2_update_initialize_error_message
from modules.networking.geolite2.readers import initialize_geolite2_readers
from modules.networking.geolite2.updater import update_geolite2_databases

if TYPE_CHECKING:
    import geoip2.database


def update_and_initialize_geolite2_readers() -> (
    tuple[bool,
          geoip2.database.Reader | None,
          geoip2.database.Reader | None,
          geoip2.database.Reader | None]
):
    """Update GeoLite2 databases (best-effort) and initialize readers.

    Returns:
        (geoip2_enabled, asn_reader, city_reader, country_reader)
    """
    update_result = update_geolite2_databases()

    init_exception, asn_reader, city_reader, country_reader = initialize_geolite2_readers()

    geoip2_enabled, msgbox_message = format_geolite2_update_initialize_error_message(
        update_exception=update_result.exception if isinstance(update_result.exception, Exception) else None,
        failed_url=update_result.url if isinstance(update_result.url, str) else None,
        http_code=(update_result.http_code if isinstance(update_result.http_code, (int, str)) else None),
        initialize_exception=init_exception,
    )

    if msgbox_message is not None:
        msgbox_style = msgbox.Style.MB_OK | msgbox.Style.MB_ICONEXCLAMATION | msgbox.Style.MB_SETFOREGROUND
        msgbox.show(TITLE, msgbox_message, msgbox_style)

    return geoip2_enabled, asn_reader, city_reader, country_reader
