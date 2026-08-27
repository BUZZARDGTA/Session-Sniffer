"""GeoLite2 database reader initialization and query helpers."""

import functools

import geoip2.database
import geoip2.errors

from session_sniffer.constants.local import GEOLITE2_DATABASES_DIR_PATH


def initialize_geolite2_readers() -> tuple[geoip2.errors.GeoIP2Error | None, geoip2.database.Reader | None, geoip2.database.Reader | None, geoip2.database.Reader | None]:
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


@functools.cache
def get_cached_geolite2_readers() -> tuple[geoip2.database.Reader | None, geoip2.database.Reader | None, geoip2.database.Reader | None]:
    """Return cached GeoLite2 readers, initializing them on first call."""
    _, asn_reader, city_reader, country_reader = initialize_geolite2_readers()
    return asn_reader, city_reader, country_reader


def query_geolite2_country(ip_address: str) -> tuple[str, str]:
    """Query GeoLite2 for country name and country ISO code for *ip_address*."""
    _, _, country_reader = get_cached_geolite2_readers()
    if country_reader is not None:
        try:
            response = country_reader.country(ip_address)
        except geoip2.errors.AddressNotFoundError:
            pass
        else:
            country_name = response.country.name if response.country.name is not None else 'N/A'
            country_code = response.country.iso_code if response.country.iso_code is not None else 'N/A'
            return country_name, country_code
    return 'N/A', 'N/A'


def query_geolite2_city(ip_address: str) -> str:
    """Query GeoLite2 for city name for *ip_address*."""
    _, city_reader, _ = get_cached_geolite2_readers()
    if city_reader is not None:
        try:
            response = city_reader.city(ip_address)
        except geoip2.errors.AddressNotFoundError:
            pass
        else:
            return response.city.name if response.city.name is not None else 'N/A'
    return 'N/A'


def query_geolite2_asn(ip_address: str) -> str:
    """Query GeoLite2 for ASN organization name for *ip_address*."""
    asn_reader, _, _ = get_cached_geolite2_readers()
    if asn_reader is not None:
        try:
            response = asn_reader.asn(ip_address)
        except geoip2.errors.AddressNotFoundError:
            pass
        else:
            return response.autonomous_system_organization if response.autonomous_system_organization is not None else 'N/A'
    return 'N/A'
