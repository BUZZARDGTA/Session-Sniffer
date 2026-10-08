#!/usr/bin/env python3
"""Check pip and installed packages for updates, and inspect GitHub Actions workflow pins.

This script performs read-only checks and does not perform any upgrades.
"""

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import cast

from packaging.version import InvalidVersion, Version

CYAN = '\033[0;36m'
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
DARK_YELLOW = '\033[0;33m'
GRAY = '\033[0;37m'
RED = '\033[0;31m'
RESET = '\033[0m'

SEMVER_TWO_PARTS = 2


def ensure_virtualenv(repo_root: Path) -> None:
    """Ensure the script runs in the project virtual environment if available."""
    in_virtualenv = sys.prefix != sys.base_prefix
    virtualenv_directory = repo_root / '.venv'

    if sys.platform == 'win32':
        virtualenv_python = virtualenv_directory / 'Scripts' / 'python.exe'
    else:
        virtualenv_python = virtualenv_directory / 'bin' / 'python'

    if not in_virtualenv:
        if virtualenv_python.is_file():
            os.execv(str(virtualenv_python), [str(virtualenv_python), str(repo_root / 'check_project_dependencies.py'), *sys.argv[1:]])
        else:
            print(f'{RED}Error: Virtual environment not found at {virtualenv_directory}{RESET}', file=sys.stderr)
            sys.exit(1)


def fetch_json(url: str, timeout: int = 10) -> object:
    """Fetch JSON data from an HTTP URL."""
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme not in ('http', 'https'):
        return None

    request = urllib.request.Request(  # noqa: S310
        url,
        headers={
            'User-Agent': 'Session-Sniffer-Dependency-Checker',
            'Accept': 'application/vnd.github+json, application/json',
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return json.loads(response.read().decode('utf-8'))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None


def get_normalized_semver(tag: str) -> Version | None:
    """Parse a semver tag into a Version object, normalizing shorthand versions."""
    raw = tag.lstrip('v')
    parts = raw.split('.')
    if len(parts) == 1 and parts[0].isdigit():
        raw = f'{parts[0]}.0.0'
    elif len(parts) == SEMVER_TWO_PARTS and parts[0].isdigit() and parts[1].isdigit():
        raw = f'{parts[0]}.{parts[1]}.0'
    try:
        return Version(raw)
    except InvalidVersion:
        return None


def get_latest_github_tag(owner: str, repository: str) -> str | None:
    """Query GitHub API for the latest release tag or highest semver tag."""
    release_data: object = fetch_json(f'https://api.github.com/repos/{owner}/{repository}/releases/latest')
    if isinstance(release_data, dict):
        release_dict = cast('dict[str, object]', release_data)
        tag_name = release_dict.get('tag_name')
        if isinstance(tag_name, str):
            return tag_name

    tags_data: object = fetch_json(f'https://api.github.com/repos/{owner}/{repository}/tags?per_page=100')
    if not isinstance(tags_data, list) or not tags_data:
        return None

    tags_list = cast('list[object]', tags_data)
    semver_tags: list[tuple[Version, str]] = []
    for tag_entry in tags_list:
        if not isinstance(tag_entry, dict):
            continue
        tag_dict = cast('dict[str, object]', tag_entry)
        tag_name_value = tag_dict.get('name')
        if not isinstance(tag_name_value, str):
            continue
        version = get_normalized_semver(tag_name_value)
        if version is not None:
            semver_tags.append((version, tag_name_value))

    if semver_tags:
        semver_tags.sort(key=lambda item: item[0])
        return semver_tags[-1][1]

    first_tag = tags_list[0]
    if isinstance(first_tag, dict):
        first_dict = cast('dict[str, object]', first_tag)
        name_value = first_dict.get('name')
        if isinstance(name_value, str):
            return name_value
    return None


def check_pip_version() -> None:
    """Check current pip version against latest release on PyPI."""
    print(f'{YELLOW}[2/4] Checking pip version...{RESET}')
    current_pip_version: str | None = None
    try:
        pip_process = subprocess.run([sys.executable, '-m', 'pip', '--version'], capture_output=True, text=True, check=True)
        current_pip_version = pip_process.stdout.split()[1]
    except (subprocess.CalledProcessError, IndexError, FileNotFoundError):
        print(f'{YELLOW}Warning: Failed to probe pip version.{RESET}')

    if current_pip_version is not None:
        pypi_data: object = fetch_json('https://pypi.org/pypi/pip/json')
        latest_pip_version: str | None = None
        if isinstance(pypi_data, dict):
            pypi_dict = cast('dict[str, object]', pypi_data)
            info_data = pypi_dict.get('info')
            if isinstance(info_data, dict):
                info_dict = cast('dict[str, object]', info_data)
                version_value = info_dict.get('version')
                if isinstance(version_value, str):
                    latest_pip_version = version_value

        if latest_pip_version is not None:
            if current_pip_version != latest_pip_version:
                print(f'{CYAN}pip: {current_pip_version} -> {latest_pip_version}{RESET}')
                print(f'{DARK_YELLOW}To upgrade pip, run: `python -m pip install --upgrade pip` (not performed by this script){RESET}')
            else:
                print(f'{GREEN}pip is up to date ({current_pip_version}){RESET}')
        else:
            print(f'{GRAY}pip: current version {current_pip_version} (could not determine latest on PyPI){RESET}')

    print()


def check_installed_packages() -> None:
    """Check installed virtual environment packages for outdated versions."""
    print(f'{YELLOW}[3/4] Checking installed packages for available updates...{RESET}')
    packages: list[dict[str, str]] = []
    try:
        outdated_process = subprocess.run(
            [sys.executable, '-m', 'pip', 'list', '--outdated', '--format=json'],
            capture_output=True,
            text=True,
            check=True,
        )
        raw_packages: object = json.loads(outdated_process.stdout) if outdated_process.stdout.strip() else []
        if isinstance(raw_packages, list):
            for item in cast('list[object]', raw_packages):
                if isinstance(item, dict):
                    item_dict = cast('dict[str, object]', item)
                    name = item_dict.get('name')
                    version = item_dict.get('version')
                    latest = item_dict.get('latest_version')
                    packages.append({
                        'name': str(name or ''),
                        'version': str(version or ''),
                        'latest_version': str(latest or ''),
                    })
    except (subprocess.CalledProcessError, json.JSONDecodeError) as exception:
        print(f'{RED}Error: Failed to list packages: {exception}{RESET}', file=sys.stderr)
        sys.exit(1)

    if not packages:
        print(f'{GREEN}All packages are already up to date!{RESET}')
    else:
        print(f'{CYAN}Found {len(packages)} package(s) with updates available:{RESET}')
        for package in packages:
            name = package.get('name', '')
            version = package.get('version', '')
            latest = package.get('latest_version', '')
            print(f'{GRAY}  - {name}: {version} -> {latest}{RESET}')
        print()
        print(f'{YELLOW}This script only checks for updates and does NOT perform upgrades.{RESET}')
        print(f'{DARK_YELLOW}To upgrade packages run: `pip install --upgrade <package>` or update dependencies in pyproject.toml manually.{RESET}')

    print()


def check_workflow_action_pins(repo_root: Path) -> None:
    """Scan GitHub Actions workflow files for outdated action pins."""
    print(f'{YELLOW}[4/4] Checking GitHub Actions pins in workflow files...{RESET}')
    workflows_directory = repo_root / '.github' / 'workflows'
    if not workflows_directory.is_dir():
        print(f'{GRAY}Workflow directory not found at {workflows_directory}{RESET}')
        return

    workflow_files = [f for f in workflows_directory.iterdir() if f.suffix in ('.yml', '.yaml')]
    if not workflow_files:
        print(f'{GRAY}No workflow files found to scan.{RESET}')
        return

    uses_matches: list[tuple[str, int, str]] = []
    pattern = re.compile(r'^\s*uses:\s*([^\s]+)\s*$')
    for workflow_file in workflow_files:
        try:
            lines = workflow_file.read_text(encoding='utf-8').splitlines()
            for line_index, line in enumerate(lines, start=1):
                match = pattern.match(line)
                if match:
                    uses_matches.append((workflow_file.name, line_index, match.group(1)))
        except OSError:
            continue

    action_pattern = re.compile(r'^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)@(.+)$')
    cache: dict[str, str | None] = {}
    outdated_actions: list[tuple[str, str, str, str, int]] = []

    for workflow_name, line_number, uses_string in uses_matches:
        match = action_pattern.match(uses_string)
        if not match:
            continue
        owner, repository_name, current_ref = match.groups()
        repository_key = f'{owner}/{repository_name}'
        if repository_key not in cache:
            cache[repository_key] = get_latest_github_tag(owner, repository_name)

        latest_tag = cache[repository_key]
        if latest_tag is None or not latest_tag:
            print(f'{DARK_YELLOW}  - {repository_key}@{current_ref} -> unable to resolve latest tag (API/rate/network).{RESET}')
            continue

        current_version = get_normalized_semver(current_ref)
        latest_version = get_normalized_semver(latest_tag)
        if current_version is None or latest_version is None:
            print(f'{GRAY}  - {repository_key}@{current_ref} (latest: {latest_tag}) [non-semver compare skipped]{RESET}')
            continue

        if current_version < latest_version:
            outdated_actions.append((repository_key, current_ref, latest_tag, workflow_name, line_number))

    if not outdated_actions:
        print(f'{GREEN}All scanned GitHub Actions are up to date.{RESET}')
    else:
        print(f'{CYAN}Found {len(outdated_actions)} outdated GitHub Action pin(s):{RESET}')
        for repository_key, current_ref, latest_tag, workflow_name, line_number in outdated_actions:
            print(f'{GRAY}  - {repository_key}: {current_ref} -> {latest_tag} ({workflow_name}:{line_number}){RESET}')


def main() -> int:
    """Main execution entry point."""
    repo_root = Path(__file__).resolve().parent
    ensure_virtualenv(repo_root)

    print(f'{CYAN}========================================{RESET}')
    print(f'{CYAN}  Project Dependency Check Script{RESET}')
    print(f'{CYAN}========================================{RESET}')
    print()

    print(f'{YELLOW}[1/4] Activating virtual environment...{RESET}')
    print(f'{GREEN}Virtual environment activated successfully!{RESET}')
    print()

    check_pip_version()
    check_installed_packages()
    check_workflow_action_pins(repo_root)

    print()
    print(f'{CYAN}========================================{RESET}')
    print(f'{GREEN}  Check Complete!{RESET}')
    print(f'{CYAN}========================================{RESET}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
