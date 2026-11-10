"""Module for defining constants that include only imports from standard Python libraries."""

from datetime import datetime, tzinfo

_local_tz: tzinfo | None = datetime.now().astimezone().tzinfo
if _local_tz is None:
    _ERROR_MESSAGE: str = 'Failed to determine local timezone'
    raise RuntimeError(_ERROR_MESSAGE)
LOCAL_TZ: tzinfo = _local_tz
