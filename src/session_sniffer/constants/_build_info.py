"""Build-time metadata.

In development the values are resolved live from git/environment.
The CI workflow overwrites this file with literal strings before bundling,
so the frozen exe always carries the correct release info.
"""
import os
import platform
import shutil
import subprocess
from pathlib import Path

from PyQt6.QtCore import PYQT_VERSION_STR


def _git(cmd: list[str]) -> str:
    git_exe = shutil.which('git')
    if git_exe is None:
        return 'Unknown'
    project_root = Path(__file__).resolve().parents[3]
    try:
        return subprocess.run(
            [git_exe, *cmd],
            cwd=project_root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip() or 'Unknown'
    except (OSError, subprocess.SubprocessError):
        return 'Unknown'


def _compute_os_build_info() -> str:
    machine = platform.machine()
    arch = 'x64' if machine in ('AMD64', 'x86_64') else machine
    return f'{os.environ.get("OS", platform.system())} {arch} {platform.version()}'


COMMIT: str = _git(['rev-parse', 'HEAD'])
BUILD_DATE: str = _git(['log', '-1', '--format=%cI'])
RELEASE_TAG: str = 'dev'
PYQT_VERSION: str = PYQT_VERSION_STR
OS_BUILD_INFO: str = _compute_os_build_info()
