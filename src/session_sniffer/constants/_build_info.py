"""Build-time metadata.

In development the values are resolved live from git/environment.
The CI workflow overwrites this file with literal strings before bundling,
so the frozen exe always carries the correct release info.
"""

import os
import platform
import sys
import tomllib
from pathlib import Path

from packaging.requirements import Requirement

from session_sniffer.utils import resource_path


def _read_pyside6_version() -> str:
    pyproject_path = resource_path(Path('pyproject.toml'))
    pyproject_data = tomllib.loads(pyproject_path.read_text(encoding='utf-8'))
    for entry in pyproject_data['project']['dependencies']:
        parsed_requirement = Requirement(entry)
        if parsed_requirement.name.casefold() == 'pyside6':
            exact_versions = [specifier.version for specifier in parsed_requirement.specifier if specifier.operator == '==']
            if exact_versions:
                return exact_versions[0]

    message = f'PySide6 dependency is missing from {pyproject_path}.'
    raise RuntimeError(message)


def _compute_os_info() -> str:
    if sys.platform == 'win32':
        winver = sys.getwindowsversion()
        raw_arch = os.environ.get('PROCESSOR_ARCHITEW6432') or os.environ.get('PROCESSOR_ARCHITECTURE', '')
        arch = 'x64' if raw_arch in ('AMD64', 'x86_64') else (raw_arch or 'x64')
        return f'{os.environ.get("OS", "Windows")} {arch} {winver.major}.{winver.minor}.{winver.build}'

    machine = platform.machine()
    arch = 'x64' if machine in ('AMD64', 'x86_64') else machine
    if sys.platform == 'darwin':
        macos_version = platform.mac_ver()[0]
        version_string = macos_version or platform.version()
        return f'macOS {arch} {version_string}'
    return f'{platform.system()} {arch} {platform.version()}'


RELEASE_TAG = '-'
RELEASE_DATE = '-'
COMMIT_SHA = '-'
COMMIT_DATE = '-'

PYSIDE6_VERSION = _read_pyside6_version()
OS_INFO = _compute_os_info()
