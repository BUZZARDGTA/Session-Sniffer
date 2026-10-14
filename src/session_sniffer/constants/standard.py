"""Module for defining constants that include only imports from standard Python libraries."""

import os
from datetime import datetime, tzinfo
from pathlib import Path

_local_tz: tzinfo | None = datetime.now().astimezone().tzinfo
if _local_tz is None:
    _ERROR_MESSAGE: str = 'Failed to determine local timezone'
    raise RuntimeError(_ERROR_MESSAGE)
LOCAL_TZ: tzinfo = _local_tz

CMD_EXE: Path = Path(os.getenv('SYSTEMROOT', 'C:/Windows')) / 'System32' / 'cmd.exe'
