"""GeoLite2 database updater + reader initialization."""

import hashlib
import json
import tempfile
from dataclasses import dataclass
from datetime import datetime  # noqa: TC003  # Pydantic needs this import at runtime for datetime parsing
from pathlib import Path
from threading import Thread
from typing import Literal

import geoip2.database
import geoip2.errors
import requests
from pydantic import BaseModel, Field, ValidationError

from modules import msgbox
from modules.constants.local import GEOLITE2_DATABASES_DIR_PATH
from modules.constants.standalone import TITLE
from modules.error_messages import format_geolite2_download_flags_failed_message, format_geolite2_update_initialize_error_message, format_type_error
from modules.logging_setup import get_logger
from modules.models import GithubReleaseResponse
from modules.networking.http_session import s as default_http_session
from modules.text_utils import format_triple_quoted_text

GITHUB_RELEASE_API__GEOLITE2__URL = 'https://api.github.com/repos/P3TERX/GeoLite.mmdb/releases/latest'

logger = get_logger(__name__)


class GeoLite2VersionEntry(BaseModel):
    """Represents a single GeoLite2 database version entry."""
    version: datetime


class GeoLite2VersionFile(BaseModel):
    """Represents the full GeoLite2 version file."""
    GeoLite2_ASN: GeoLite2VersionEntry = Field(alias='GeoLite2-ASN.mmdb')
    GeoLite2_City: GeoLite2VersionEntry = Field(alias='GeoLite2-City.mmdb')
    GeoLite2_Country: GeoLite2VersionEntry = Field(alias='GeoLite2-Country.mmdb')


@dataclass(kw_only=True, slots=True)
class GeoLite2UpdateResult:
    """Outcome of a GeoLite2 update attempt (success or failure)."""

    exception: Exception | None = None
    url: str | None = None
    http_code: int | str | None = None


@dataclass(kw_only=True, slots=True)
class GeoLite2DatabaseInfo:
    """Mutable state for a single GeoLite2 database file."""
    current_version: str | None = None
    last_version: str | None = None
    download_url: str | None = None

    def set_current_version_from_datetime(self, dt: datetime) -> None:
        """Set current_version from a datetime object, storing ISO string."""
        self.current_version = dt.isoformat()

    def apply_release_asset(self, *, updated_at: datetime, download_url: str) -> None:
        """Update last version and download URL together."""
        self.last_version = updated_at.isoformat()
        self.download_url = download_url


GeoLite2DatabaseKey = Literal['GeoLite2-ASN.mmdb', 'GeoLite2-City.mmdb', 'GeoLite2-Country.mmdb']
GeoLite2Databases = dict[GeoLite2DatabaseKey, GeoLite2DatabaseInfo]


def _build_geolite2_databases_state() -> GeoLite2Databases:
    return {name: GeoLite2DatabaseInfo() for name in ('GeoLite2-ASN.mmdb', 'GeoLite2-City.mmdb', 'GeoLite2-Country.mmdb')}


def _load_geolite2_current_versions(*, geolite2_version_file_path: Path, geolite2_databases: GeoLite2Databases) -> None:
    """Load current GeoLite2 database versions from disk into in-memory state."""
    try:
        raw_data = json.loads(geolite2_version_file_path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return

    try:
        version_file = GeoLite2VersionFile.model_validate(raw_data)
    except ValidationError:
        logger.warning('Failed to parse GeoLite2 JSON version file at %s', geolite2_version_file_path)
        return

    geolite2_databases['GeoLite2-ASN.mmdb'].set_current_version_from_datetime(version_file.GeoLite2_ASN.version)
    geolite2_databases['GeoLite2-City.mmdb'].set_current_version_from_datetime(version_file.GeoLite2_City.version)
    geolite2_databases['GeoLite2-Country.mmdb'].set_current_version_from_datetime(version_file.GeoLite2_Country.version)


def _geolite2_update_result_from_exception(*, exception: requests.exceptions.RequestException, url: str) -> GeoLite2UpdateResult:
    return GeoLite2UpdateResult(exception=exception, url=url, http_code=getattr(exception.response, 'status_code', None))


def _fetch_geolite2_release_assets(*, session: requests.Session) -> tuple[GeoLite2UpdateResult, None] | tuple[None, GithubReleaseResponse]:
    try:
        response = session.get(GITHUB_RELEASE_API__GEOLITE2__URL)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return _geolite2_update_result_from_exception(exception=e, url=GITHUB_RELEASE_API__GEOLITE2__URL), None

    release_response_data = response.json()
    release_data = GithubReleaseResponse.model_validate(release_response_data)

    return None, release_data


def _download_geolite2_asset_bytes(*, session: requests.Session, download_url: str) -> tuple[GeoLite2UpdateResult | None, bytes | None]:
    try:
        response = session.get(download_url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return _geolite2_update_result_from_exception(exception=e, url=download_url), None

    if not isinstance(response.content, bytes):
        raise TypeError(format_type_error(response.content, bytes))

    return None, response.content


def _write_geolite2_version_file(geolite2_version_file_path: Path, geolite2_databases: GeoLite2Databases, /) -> None:
    geolite2_version_file_path.parent.mkdir(parents=True, exist_ok=True)

    data = {name: {'version': info.current_version} for name, info in geolite2_databases.items()}
    geolite2_version_file_path.write_text(json.dumps(data, indent=4), encoding='utf-8')


def _notify_geolite2_download_flags_failed(failed_flags: list[str], /) -> None:
    if not failed_flags:
        return

    Thread(
        target=msgbox.show,
        name='GeoLite2DownloadError',
        kwargs={
            'title': TITLE,
            'text': format_triple_quoted_text(
                format_geolite2_download_flags_failed_message(failed_flags=failed_flags, geolite2_release_api_url=GITHUB_RELEASE_API__GEOLITE2__URL),
            ),
            'style': msgbox.Style.MB_OK | msgbox.Style.MB_ICONEXCLAMATION | msgbox.Style.MB_SYSTEMMODAL,
        },
        daemon=True,
    ).start()


def _persist_geolite2_database_bytes(
    *,
    database_name: str,
    file_bytes: bytes,
    desired_version: str,
    current_version: str | None,
) -> str | None:
    GEOLITE2_DATABASES_DIR_PATH.mkdir(parents=True, exist_ok=True)
    destination_file_path = GEOLITE2_DATABASES_DIR_PATH / database_name

    if destination_file_path.is_file():
        existing_size = destination_file_path.stat().st_size
        new_size = len(file_bytes)

        if (
            existing_size == new_size
            and hashlib.sha256(destination_file_path.read_bytes()).digest() == hashlib.sha256(file_bytes).digest()  # Only compare hashes if file sizes match
        ):
            return desired_version

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(file_bytes)
            temp_path = Path(tmp.name)

        try:
            temp_path.replace(destination_file_path)
        except PermissionError:
            temp_path.unlink(missing_ok=True)
            return current_version

        return desired_version

    destination_file_path.write_bytes(file_bytes)
    return desired_version


def update_geolite2_databases(*, session: requests.Session = default_http_session) -> GeoLite2UpdateResult:
    """Download/update GeoLite2 ASN/City/Country mmdb databases and persist versions."""
    geolite2_version_file_path = GEOLITE2_DATABASES_DIR_PATH / 'version.json'
    geolite2_databases = _build_geolite2_databases_state()

    _load_geolite2_current_versions(geolite2_version_file_path=geolite2_version_file_path, geolite2_databases=geolite2_databases)

    update_error, release_data = _fetch_geolite2_release_assets(session=session)
    if update_error is not None or release_data is None:
        return update_error if update_error is not None else GeoLite2UpdateResult()

    for asset in release_data.assets:
        if asset.name not in geolite2_databases:
            continue

        geolite2_databases[asset.name].apply_release_asset(
            updated_at=asset.updated_at,
            download_url=str(asset.browser_download_url),
        )

    failed_fetching_flag_list: list[str] = []

    for database_name, database_info in geolite2_databases.items():
        last_version = database_info.last_version
        if not last_version:
            failed_fetching_flag_list.append(database_name)
            continue

        if database_info.current_version == last_version:
            continue

        download_url = database_info.download_url
        if download_url is None:
            failed_fetching_flag_list.append(database_name)
            continue

        download_error, file_bytes = _download_geolite2_asset_bytes(session=session, download_url=download_url)
        if download_error is not None or file_bytes is None:
            return download_error if download_error is not None else GeoLite2UpdateResult()

        database_info.current_version = _persist_geolite2_database_bytes(
            database_name=database_name,
            file_bytes=file_bytes,
            desired_version=last_version,
            current_version=database_info.current_version,
        )

    _notify_geolite2_download_flags_failed(failed_fetching_flag_list)
    _write_geolite2_version_file(geolite2_version_file_path, geolite2_databases)

    return GeoLite2UpdateResult()


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


def update_and_initialize_geolite2_readers(*, session: requests.Session = default_http_session) -> (
    tuple[bool,
          geoip2.database.Reader | None,
          geoip2.database.Reader | None,
          geoip2.database.Reader | None]
):
    """Update GeoLite2 databases (best-effort) and initialize readers.

    Returns:
        (geoip2_enabled, asn_reader, city_reader, country_reader)
    """
    update_result = update_geolite2_databases(session=session)

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
