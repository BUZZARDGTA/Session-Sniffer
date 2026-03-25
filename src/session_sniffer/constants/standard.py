"""Module for defining constants that include only imports from standard Python libraries."""
import os
from pathlib import Path

SYSTEMROOT_PATH = Path(os.getenv('SYSTEMROOT', 'C:/Windows'))
SYSTEM32_PATH = SYSTEMROOT_PATH / 'System32'
CMD_EXE = SYSTEM32_PATH / 'cmd.exe'
SC_EXE = SYSTEM32_PATH / 'sc.exe'
