"""Bake build metadata into src/session_sniffer/constants/_build_info.py for CI releases."""  # noqa: INP001

import os
import platform
import py_compile
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

from packaging.requirements import Requirement

REQUIRED_CONSTANTS: tuple[str, ...] = (
    'RELEASE_TAG',
    'RELEASE_DATE',
    'COMMIT_SHA',
    'COMMIT_DATE',
    'PYSIDE6_VERSION',
    'OS_INFO',
)
PROHIBITED_SUBSTRINGS: tuple[str, ...] = (
    'import ',
    'subprocess',
    '_git',
    'Unknown',
)


def get_repo_root() -> Path:
    """Return the repository root directory for this workspace."""
    return Path(__file__).resolve().parents[3]


def resolve_commit_date(repo_root: Path, commit_sha: str) -> str:
    """Resolve the ISO-8601 commit date from git or environment."""
    commit_date = os.environ.get('COMMIT_DATE', '').strip()
    if commit_date:
        return commit_date

    git_executable = shutil.which('git') or 'git'
    git_result = subprocess.run(
        [git_executable, 'show', '-s', '--format=%cI', commit_sha],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    commit_date = git_result.stdout.strip()
    if not commit_date:
        message = f'Failed to resolve commit date for commit SHA: {commit_sha}'
        raise ValueError(message)
    return commit_date


def extract_pyside6_version(dependencies: list[str]) -> str:
    """Extract the exact pinned PySide6 version from dependencies."""
    for dependency in dependencies:
        requirement = Requirement(dependency)
        if requirement.name.lower() == 'pyside6':
            for specifier in requirement.specifier:
                if specifier.operator == '==':
                    return specifier.version
            break

    message = 'PySide6 exact version specification (==) is missing from dependencies.'
    raise ValueError(message)


def compute_os_info() -> str:
    """Compute normalized operating system and architecture description."""
    machine = platform.machine()
    architecture = 'x64' if machine in ('AMD64', 'x86_64') else machine
    return f'{os.environ.get("OS", platform.system())} {architecture} {platform.version()}'


def bake_metadata(repo_root: Path) -> None:
    """Update pyproject.toml and freeze build info constants."""
    release_tag = os.environ.get('RELEASE_TAG', '').strip()
    if not release_tag:
        message = 'Environment variable RELEASE_TAG must not be empty.'
        raise ValueError(message)

    release_date = os.environ.get('RELEASE_DATE', '').strip()
    if not release_date:
        message = 'Environment variable RELEASE_DATE must not be empty.'
        raise ValueError(message)

    commit_sha = os.environ.get('COMMIT_SHA', '').strip()
    if not commit_sha:
        message = 'Environment variable COMMIT_SHA must not be empty.'
        raise ValueError(message)

    commit_date = resolve_commit_date(repo_root, commit_sha)

    pyproject_path = repo_root / 'pyproject.toml'
    pyproject_text = pyproject_path.read_text(encoding='utf-8')
    pyproject_data = tomllib.loads(pyproject_text)
    committed_version = pyproject_data['project']['version']
    if committed_version != release_tag:
        message = (
            f'Committed pyproject.toml version {committed_version!r} does not match '
            f'release tag {release_tag!r}. You must commit the updated version string '
            'in pyproject.toml before publishing the release.'
        )
        raise ValueError(message)

    dependencies = pyproject_data['project']['dependencies']
    pyside6_version = extract_pyside6_version(dependencies)
    os_info = compute_os_info()

    build_info_path = repo_root / 'src' / 'session_sniffer' / 'constants' / '_build_info.py'
    build_info_content = (
        '"""Build-time metadata frozen by the CI workflow."""\r\n'
        f'RELEASE_TAG: str = {release_tag!r}\r\n'
        f'RELEASE_DATE: str = {release_date!r}\r\n'
        f'COMMIT_SHA: str = {commit_sha!r}\r\n'
        f'COMMIT_DATE: str = {commit_date!r}\r\n'
        f'PYSIDE6_VERSION: str = {pyside6_version!r}\r\n'
        f'OS_INFO: str = {os_info!r}\r\n'
    )
    build_info_path.write_text(build_info_content, encoding='utf-8')

    # Verify baked metadata
    for prohibited in PROHIBITED_SUBSTRINGS:
        if prohibited in build_info_content:
            message = f'Build metadata contains development/runtime value: {prohibited}'
            raise ValueError(message)

    for required in REQUIRED_CONSTANTS:
        if f'{required}: str =' not in build_info_content:
            message = f'Build metadata is missing required constant: {required}'
            raise ValueError(message)

    py_compile.compile(str(build_info_path), doraise=True)
    sys.stdout.write(build_info_content)


def main() -> None:
    """Main execution entry point."""
    repo_root = get_repo_root()
    bake_metadata(repo_root)


if __name__ == '__main__':
    main()
