"""Module for defining constants that include only imports from standard Python libraries."""

import os
from pathlib import Path

SYSTEMROOT_PATH: Path = Path(os.getenv('SYSTEMROOT', 'C:/Windows'))
SYSTEM32_PATH: Path = SYSTEMROOT_PATH / 'System32'
CMD_EXE: Path = SYSTEM32_PATH / 'cmd.exe'
SC_EXE: Path = SYSTEM32_PATH / 'sc.exe'
