"""Lifecycle hook handlers for Session Sniffer Antigravity agent sessions."""

import argparse
import json
import re
import sys
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

TEXT_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        '.cfg',
        '.cmd',
        '.css',
        '.gitattributes',
        '.gitignore',
        '.html',
        '.ini',
        '.js',
        '.json',
        '.jsonc',
        '.lock',
        '.md',
        '.ps1',
        '.py',
        '.pyi',
        '.python-version',
        '.sh',
        '.spec',
        '.svg',
        '.toml',
        '.txt',
        '.xml',
        '.yaml',
        '.yml',
    },
)

PYTEST_COMMAND_PATTERN = re.compile(r'(?:^|[;&|]\s*|\b(?:uv\s+run|python(?:\.exe)?\s+-m)\s+)pytest\b', re.IGNORECASE)
DESTRUCTIVE_GIT_PATTERN = re.compile(
    r'\bgit\s+(?:reset\s+--hard|push\s+(?:--force|-f)\b|clean\s+-[a-z]*f|rebase\b|commit\s+--amend\b)',
    re.IGNORECASE,
)
UV_LOCK_PATTERN = re.compile(r'\buv\s+(?:lock|sync|add|remove)\b', re.IGNORECASE)


def get_repo_root() -> Path:
    """Return the repository root directory."""
    return Path(__file__).resolve().parents[2]


def read_hook_payload() -> dict[str, Any]:
    """Read and parse the JSON hook payload from standard input."""
    raw_input = sys.stdin.read().strip()
    if not raw_input:
        return {}
    with suppress(json.JSONDecodeError):
        parsed = json.loads(raw_input)
        if isinstance(parsed, dict):
            return cast('dict[str, Any]', parsed)
    return {}


def write_hook_response(payload: dict[str, Any]) -> None:
    """Write a JSON hook response to standard output."""
    sys.stdout.write(json.dumps(payload) + '\n')
    sys.stdout.flush()


def ensure_crlf_file(file_path: Path, repo_root: Path) -> bool:
    """Convert LF line endings to CRLF for a repository text file if needed.

    Returns:
        True if the file was modified to enforce CRLF, False otherwise.
    """
    with suppress(OSError):
        resolved_path = file_path.resolve()
        suffix = resolved_path.suffix.lower() or resolved_path.name.lower()
        if not resolved_path.is_file() or not resolved_path.is_relative_to(repo_root) or suffix not in TEXT_FILE_EXTENSIONS:
            return False

        raw_bytes = resolved_path.read_bytes()
        if b'\x00' in raw_bytes or b'\n' not in raw_bytes:
            return False

        normalized_bytes = raw_bytes.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
        if normalized_bytes != raw_bytes:
            resolved_path.write_bytes(normalized_bytes)
            return True
    return False


def handle_pre_tool_use(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate tool execution requests before they run."""
    tool_call = payload.get('toolCall')
    if not isinstance(tool_call, dict):
        return {'decision': 'allow'}

    tool_call_dict = cast('dict[str, Any]', tool_call)
    tool_name = tool_call_dict.get('name')
    tool_args = tool_call_dict.get('args')
    if tool_name != 'run_command' or not isinstance(tool_args, dict):
        return {'decision': 'allow'}

    tool_args_dict = cast('dict[str, Any]', tool_args)
    command_line = tool_args_dict.get('CommandLine')
    if not isinstance(command_line, str) or not command_line.strip():
        return {'decision': 'allow'}

    if PYTEST_COMMAND_PATTERN.search(command_line):
        return {
            'decision': 'deny',
            'reason': (
                'Session Sniffer does not have a pytest suite (.agents/rules/core.md). '
                'Validate changes using the configured tools in .venv (ruff, flake8, pylint, '
                'mypy, pyright, pyrefly, ty, vulture, or python code_quality_checks.py).'
            ),
        }

    if DESTRUCTIVE_GIT_PATTERN.search(command_line):
        return {
            'decision': 'ask',
            'reason': 'Rewriting Git history or discarding worktree changes requires explicit user confirmation (.agents/rules/core.md).',
        }

    return {'decision': 'allow'}


def handle_post_tool_use(payload: dict[str, Any]) -> dict[str, Any]:
    """Enforce CRLF line endings after file edits or lockfile updates."""
    repo_root = get_repo_root()
    tool_call = payload.get('toolCall')
    if not isinstance(tool_call, dict):
        return {}

    tool_call_dict = cast('dict[str, Any]', tool_call)
    tool_name = tool_call_dict.get('name')
    tool_args = tool_call_dict.get('args')
    if not isinstance(tool_args, dict):
        return {}

    tool_args_dict = cast('dict[str, Any]', tool_args)

    if tool_name in ('write_file', 'edit_file'):
        target_path = tool_args_dict.get('Path')
        if isinstance(target_path, str) and target_path.strip():
            ensure_crlf_file(Path(target_path), repo_root)
    elif tool_name == 'run_command':
        command_line = tool_args_dict.get('CommandLine')
        if isinstance(command_line, str) and UV_LOCK_PATTERN.search(command_line):
            ensure_crlf_file(repo_root / 'uv.lock', repo_root)
            ensure_crlf_file(repo_root / 'pyproject.toml', repo_root)

    return {}


def main() -> None:
    """Dispatch the requested hook event handler."""
    parser = argparse.ArgumentParser(description='Session Sniffer Antigravity lifecycle hook dispatcher.')
    parser.add_argument(
        'event',
        choices=('pre-tool-use', 'post-tool-use'),
        help='The lifecycle hook event to process.',
    )
    args = parser.parse_args()

    payload = read_hook_payload()
    if args.event == 'pre-tool-use':
        write_hook_response(handle_pre_tool_use(payload))
    else:
        write_hook_response(handle_post_tool_use(payload))


if __name__ == '__main__':
    main()
