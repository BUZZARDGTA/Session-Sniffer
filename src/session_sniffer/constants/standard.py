"""Module for defining constants that include only imports from standard Python libraries."""

import os
from datetime import datetime, tzinfo
from pathlib import Path

_local_tz: tzinfo | None = datetime.now().astimezone().tzinfo
if _local_tz is None:
    _ERROR_MESSAGE: str = 'Failed to determine local timezone'
    raise RuntimeError(_ERROR_MESSAGE)
LOCAL_TZ: tzinfo = _local_tz

SYSTEMROOT_PATH: Path = Path(os.getenv('SYSTEMROOT', 'C:/Windows'))
SYSTEM32_PATH: Path = SYSTEMROOT_PATH / 'System32'
CMD_EXE: Path = SYSTEM32_PATH / 'cmd.exe'
SC_EXE: Path = SYSTEM32_PATH / 'sc.exe'
