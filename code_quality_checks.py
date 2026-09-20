#!/usr/bin/env python3
"""Run all configured code quality and security tools across platforms."""

import argparse
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

CYAN = '\033[0;36m'
DARK_GRAY = '\033[1;30m'
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
DARK_YELLOW = '\033[0;33m'
GRAY = '\033[0;37m'
RESET = '\033[0m'


@dataclass(frozen=True)
class QualityTool:
    """Specification for an automated code quality or security tool."""

    name: str
    command: str
    install_command: str
    description: str
    category: str


TOOLS: list[QualityTool] = [
    QualityTool(
        name='ruff',
        command='ruff check .',
        install_command='pip install ruff',
        description='Fast Python linter and code formatter',
        category='LINTING',
    ),
    QualityTool(
        name='flake8',
        command='flake8 . --config .flake8',
        install_command='pip install flake8',
        description='Style guide enforcement',
        category='LINTING',
    ),
    QualityTool(
        name='pylint',
        command='pylint . --rcfile pyproject.toml',
        install_command='pip install pylint',
        description='Comprehensive Python code analysis',
        category='LINTING',
    ),
    QualityTool(
        name='mypy',
        command='mypy . --config-file pyproject.toml',
        install_command='pip install mypy',
        description='Static type checking',
        category='TYPE CHECKING',
    ),
    QualityTool(
        name='pyright',
        command='pyright',
        install_command='pip install pyright',
        description='Microsoft Python type checker',
        category='TYPE CHECKING',
    ),
    QualityTool(
        name='pyrefly',
        command='pyrefly check .',
        install_command='pip install pyrefly',
        description="Meta's fast Python type checker",
        category='TYPE CHECKING',
    ),
    QualityTool(
        name='ty',
        command='ty check .',
        install_command='pip install ty',
        description="Astral's fast Python type checker",
        category='TYPE CHECKING',
    ),
    QualityTool(
        name='vulture',
        command='vulture .',
        install_command='pip install vulture',
        description='Dead code detection and analysis',
        category='LINTING',
    ),
    QualityTool(
        name='pip-audit',
        command='pip-audit --local --skip-editable --ignore-vuln PYSEC-2026-3740',
        install_command='pip install pip-audit',
        description="PyPA's official security vulnerability scanner",
        category='SECURITY',
    ),
    QualityTool(
        name='snyk',
        command='snyk test',
        install_command='npm install -g snyk',
        description='Security vulnerability scanning',
        category='SECURITY',
    ),
]


def ensure_virtualenv(repo_root: Path) -> None:
    """Ensure the script runs in the project virtual environment if available."""
    in_virtualenv = sys.prefix != sys.base_prefix
    virtualenv_directory = repo_root / '.venv'

    if sys.platform == 'win32':
        virtualenv_python = virtualenv_directory / 'Scripts' / 'python.exe'
        virtualenv_binaries = virtualenv_directory / 'Scripts'
    else:
        virtualenv_python = virtualenv_directory / 'bin' / 'python'
        virtualenv_binaries = virtualenv_directory / 'bin'

    # Prepend virtualenv bin/Scripts to PATH so tools installed in .venv can be invoked directly
    if virtualenv_binaries.is_dir():
        current_path = os.environ.get('PATH', '')
        if str(virtualenv_binaries) not in current_path.split(os.pathsep):
            os.environ['PATH'] = f'{virtualenv_binaries}{os.pathsep}{current_path}'

    if not in_virtualenv and virtualenv_python.is_file():
        os.execv(str(virtualenv_python), [str(virtualenv_python), str(repo_root / 'code_quality_checks.py'), *sys.argv[1:]])


def show_header() -> None:
    """Display code quality analysis header banner."""
    print(f'{CYAN}==================================={RESET}')
    print(f'{CYAN}Running Code Quality Analysis{RESET}')
    print(f'{CYAN}==================================={RESET}')


def show_footer() -> None:
    """Display code quality analysis footer banner."""
    print()
    print(f'{GREEN}==================================={RESET}')
    print(f'{GREEN}Code Quality Analysis Complete{RESET}')
    print(f'{GREEN}==================================={RESET}')


def invoke_quality_tool(tool: QualityTool, step_number: int, total_steps: int) -> bool:
    """Execute a single quality tool, print output, and return True if successful."""
    print()
    print(f'{CYAN}[{step_number}/{total_steps}] {tool.category} - {tool.name} ({tool.description}){RESET}')
    print(f'{DARK_GRAY}-----------------------------------{RESET}')

    if shutil.which(tool.name) is None:
        print(f'{DARK_YELLOW}[WARN] {tool.name} is not installed. Skipping {tool.name} check.{RESET}')
        print(f'{GRAY}   To install: {tool.install_command}{RESET}')
        return True

    start_time = time.perf_counter()
    process = subprocess.run(tool.command, shell=True, check=False)
    elapsed_seconds = round(time.perf_counter() - start_time, 1)

    if not process.returncode:
        print(f'{GREEN}[OK] {tool.name} completed in {elapsed_seconds} seconds{RESET}')
        return True

    print(
        f'{DARK_YELLOW}[FAIL] {tool.name} completed with errors '
        f'(exit code {process.returncode}) in {elapsed_seconds} seconds{RESET}'
    )
    return False


def main() -> int:
    """Main execution entry point."""
    repo_root = Path(__file__).resolve().parent
    ensure_virtualenv(repo_root)

    parser = argparse.ArgumentParser(description='Run Session Sniffer code quality checks.')
    parser.add_argument(
        '--all',
        '--include-all',
        '-IncludeAll',
        dest='include_all',
        action='store_true',
        help='Run all tools including slow/network security scans.',
    )
    parser.add_argument(
        '--skip-slow-security',
        '-SkipSlowSecurity',
        dest='skip_slow_security',
        action='store_true',
        help='Skip slow or interactive security tools (snyk).',
    )
    arguments = parser.parse_args()

    show_header()

    is_ai_agent = bool(os.environ.get('ANTIGRAVITY_AGENT') or os.environ.get('AI_AGENT') or os.environ.get('AGENT'))
    omit_slow = (is_ai_agent or arguments.skip_slow_security) and not arguments.include_all

    active_tools = [
        tool for tool in TOOLS
        if not (omit_slow and tool.name in ('snyk',))
    ]

    if omit_slow:
        print(f'{YELLOW}[INFO] AI agent detected: omitting snyk security checks.{RESET}')

    all_passed = True
    total_steps = len(active_tools)

    for i, tool in enumerate(active_tools, start=1):
        if not invoke_quality_tool(tool, i, total_steps):
            all_passed = False

    show_footer()
    return 0 if all_passed else 1


if __name__ == '__main__':
    sys.exit(main())
