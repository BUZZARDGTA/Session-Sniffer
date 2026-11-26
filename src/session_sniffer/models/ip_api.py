"""Pydantic models for IP-API response validation.

This module provides validation for IP geolocation API single and batch responses
from ip-api.com.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

IPAPI_FIELDS = (
    'status,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query'
)


class IpApiResponse(BaseModel):
    """Model for a single successful IP lookup result from ip-api.com."""

    model_config = ConfigDict(allow_inf_nan=False)

    # Response status
    status: Literal['success']

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


class IpApiFailResponse(BaseModel):
    """Model for a single failed IP lookup result from ip-api.com."""

    status: Literal['fail']
    query: str = ''
    message: str = ''


type IpApiLookupItem = IpApiResponse | IpApiFailResponse

IPAPI_ITEM_ADAPTER: TypeAdapter[IpApiLookupItem] = TypeAdapter(
    Annotated[IpApiLookupItem, Field(discriminator='status')],
)
IPAPI_RAW_LIST_ADAPTER: TypeAdapter[list[object]] = TypeAdapter(list[object])
