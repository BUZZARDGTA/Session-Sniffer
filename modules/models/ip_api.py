"""Pydantic models for IP-API batch response validation.

This module provides validation for IP geolocation API batch responses
from ip-api.com.
"""

from pydantic import BaseModel, Field


class IpApiResponse(BaseModel):
    """Model for a single IP lookup result from ip-api.com batch endpoint.

    Used to validate individual items in the batch response from:
    http://ip-api.com/batch
    """

    # Location information
    continent: str
    continent_code: str = Field(alias='continentCode')
    country: str
    country_code: str = Field(alias='countryCode')
    region: str = Field(alias='regionName')
    region_code: str = Field(alias='region')
    city: str
    district: str
    zip_code: str = Field(alias='zip')

    # Coordinates
    lat: float
    lon: float

    # Timezone and currency
    time_zone: str = Field(alias='timezone')
    offset: int
    currency: str

    # ISP and organization
    isp: str
    org: str
    asn: str = Field(alias='as')
    as_name: str = Field(alias='asname')

    # Detection flags
    mobile: bool
    proxy: bool
    hosting: bool

    # Query IP (the IP that was looked up)
    query: str
