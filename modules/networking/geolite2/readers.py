"""GeoLite2 database reader initialization and sanity checks."""

import geoip2.database
import geoip2.errors

from modules.constants.local import GEOLITE2_DATABASES_DIR_PATH


def initialize_geolite2_readers() -> (
    tuple[geoip2.errors.GeoIP2Error | None,
          geoip2.database.Reader | None,
          geoip2.database.Reader | None,
          geoip2.database.Reader | None]
):
    """Open the GeoLite2 databases and sanity-check them with a known IP."""
    try:
        geolite2_asn_reader = geoip2.database.Reader(GEOLITE2_DATABASES_DIR_PATH / 'GeoLite2-ASN.mmdb')
        geolite2_city_reader = geoip2.database.Reader(GEOLITE2_DATABASES_DIR_PATH / 'GeoLite2-City.mmdb')
        geolite2_country_reader = geoip2.database.Reader(GEOLITE2_DATABASES_DIR_PATH / 'GeoLite2-Country.mmdb')

        geolite2_asn_reader.asn('1.1.1.1')
        geolite2_city_reader.city('1.1.1.1')
        geolite2_country_reader.country('1.1.1.1')

        exception = None
    except geoip2.errors.GeoIP2Error as e:
        geolite2_asn_reader = None
        geolite2_city_reader = None
        geolite2_country_reader = None
        exception = e

    return exception, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader
