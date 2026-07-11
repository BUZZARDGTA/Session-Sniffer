"""Build-time metadata.

In development the values are resolved live from git/environment.
The CI workflow overwrites this file with literal strings before bundling,
so the frozen exe always carries the correct release info.
"""

import os
import platform

from packaging.requirements import Requirement

from session_sniffer.constants.local import PYPROJECT_DATA, PYPROJECT_PATH


def _read_pyside6_version() -> str:
    for dependency in PYPROJECT_DATA['project']['dependencies']:
        requirement = Requirement(dependency)

        if requirement.name.lower() == 'pyside6':
            for specifier in requirement.specifier:
                if specifier.operator == '==':
                    return specifier.version

    message = f'PySide6 dependency is missing from {PYPROJECT_PATH}.'
    raise RuntimeError(message)


def _compute_os_info() -> str:
    machine = platform.machine()
    arch = 'x64' if machine in ('AMD64', 'x86_64') else machine
    return f'{os.environ.get("OS", platform.system())} {arch} {platform.version()}'


RELEASE_TAG = '-'
RELEASE_DATE = '-'
COMMIT_SHA = '-'
COMMIT_DATE = '-'

PYSIDE6_VERSION = _read_pyside6_version()
OS_INFO = _compute_os_info()
