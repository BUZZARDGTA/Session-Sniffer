"""Send a Discord webhook notification for a published GitHub release."""

import argparse
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests
from packaging.version import InvalidVersion, Version

DISCORD_WEBHOOK_HOSTS = frozenset({
    'discord.com',
    'discordapp.com',
    'ptb.discord.com',
    'canary.discord.com',
})
DISCORD_WEBHOOK_PATH_PREFIX = '/api/webhooks/'
STABLE_RELEASE_ROLE_ID = '1562696020456898650'
PRERELEASE_ROLE_ID = '1562696518211866674'
MAX_DESCRIPTION_LENGTH = 3800
STABLE_EMBED_COLOR = 0x00B4D8
PRERELEASE_EMBED_COLOR = 0x5865F2
REQUEST_TIMEOUT_SECONDS = 30
BYTES_PER_MEGABYTE = 1024 * 1024


def validate_webhook_url(webhook_url: str) -> str:
    """Validate that the Discord webhook URL uses HTTPS and an official Discord host."""
    if not webhook_url:
        message = 'Environment variable DISCORD_WEBHOOK_URL is not set or empty.'
        raise ValueError(message)

    parsed = urlsplit(webhook_url)
    if (
        parsed.scheme != 'https'
        or parsed.netloc.lower() not in DISCORD_WEBHOOK_HOSTS
        or not parsed.path.startswith(DISCORD_WEBHOOK_PATH_PREFIX)
    ):
        message = 'Environment variable DISCORD_WEBHOOK_URL is not a valid HTTPS Discord webhook URL.'
        raise ValueError(message)

    return webhook_url


def read_release_body_from_event() -> str:
    """Read the release changelog body from the GitHub Actions event payload file."""
    event_path = os.environ.get('GITHUB_EVENT_PATH', '').strip()
    if not event_path:
        message = 'Environment variable GITHUB_EVENT_PATH is not set or empty.'
        raise ValueError(message)

    event_payload = json.loads(Path(event_path).read_text(encoding='utf-8'))
    release_body = event_payload.get('release', {}).get('body')
    return release_body if isinstance(release_body, str) else ''


def validate_release_tag(
    parser: argparse.ArgumentParser,
    tag: str,
    *,
    prerelease: bool,
) -> None:
    """Validate that the release tag is a valid PEP 440 version matching the prerelease flag."""
    try:
        version = Version(tag)
    except InvalidVersion:
        parser.error(f'Invalid release tag version: {tag!r}.')

    if version.is_prerelease != prerelease:
        expected_state = 'marked as prerelease' if version.is_prerelease else 'not marked as prerelease'
        parser.error(f'Release tag "{tag}" prerelease state mismatch: expected GitHub release to be {expected_state}.')


def validate_positive_int(value: str) -> int:
    """Return the parsed integer if it is strictly positive."""
    try:
        parsed = int(value)
    except ValueError as err:
        message = f'Expected a positive integer, got {value!r}.'
        raise argparse.ArgumentTypeError(message) from err

    if parsed <= 0:
        message = f'Value must be greater than zero, got {parsed}.'
        raise argparse.ArgumentTypeError(message)

    return parsed


def format_file_size(size_in_bytes: int) -> str:
    """Format a byte count as a human-readable megabyte string."""
    megabytes = size_in_bytes / BYTES_PER_MEGABYTE
    return f'{megabytes:.1f} MB'


def format_changelog_description(release_body: str, release_url: str) -> str:
    """Normalize and safely truncate the release changelog for a Discord embed description."""
    normalized = release_body.replace('\r\n', '\n').strip()
    if not normalized:
        return f'View release details and assets on [GitHub]({release_url}).'

    if len(normalized) <= MAX_DESCRIPTION_LENGTH:
        return normalized

    truncation_suffix = f'\n\n*... [Read the full changelog on GitHub]({release_url})*'
    max_content_length = MAX_DESCRIPTION_LENGTH - len(truncation_suffix)

    kept_lines: list[str] = []
    current_length = 0
    for line in normalized.split('\n'):
        line_length = len(line) + (1 if kept_lines else 0)
        if current_length + line_length > max_content_length:
            break
        kept_lines.append(line)
        current_length += line_length

    if not kept_lines:
        return normalized[:max_content_length].rstrip() + truncation_suffix

    return '\n'.join(kept_lines).rstrip() + truncation_suffix


def build_discord_payload(args: argparse.Namespace, release_body: str) -> dict[str, Any]:
    """Build the Discord webhook JSON payload with a rich release embed."""
    release_label = args.release_name.strip() or args.tag
    title = release_label if release_label.lower().startswith('session sniffer') else f'Session Sniffer {release_label}'

    embed: dict[str, Any] = {
        'title': title,
        'url': args.release_url,
        'description': format_changelog_description(release_body, args.release_url),
        'color': PRERELEASE_EMBED_COLOR if args.prerelease else STABLE_EMBED_COLOR,
        'fields': [
            {
                'name': 'Windows x64',
                'value': f'[Session_Sniffer.exe]({args.download_url})\n`{format_file_size(args.file_size)}`',
                'inline': True,
            },
            {
                'name': 'Linux x64',
                'value': f'[Session_Sniffer]({args.linux_download_url})\n`{format_file_size(args.linux_file_size)}`',
                'inline': True,
            },
            {
                'name': 'macOS ARM64',
                'value': f'[Session_Sniffer_macOS]({args.darwin_download_url})\n`{format_file_size(args.darwin_file_size)}`',
                'inline': True,
            },
        ],
        'footer': {
            'text': 'Pre-release (Release Candidate)' if args.prerelease else 'Stable Release',
        },
    }

    published_at = args.published_at.strip()
    if published_at:
        embed['timestamp'] = published_at

    target_role_id = PRERELEASE_ROLE_ID if args.prerelease else STABLE_RELEASE_ROLE_ID

    return {
        'content': f'<@&{target_role_id}>',
        'embeds': [embed],
        'allowed_mentions': {
            'parse': [],
            'roles': [target_role_id],
        },
    }


def main() -> None:
    """Parse release arguments and post the release notification to Discord."""
    parser = argparse.ArgumentParser(description='Send a Discord webhook notification for a published release.')
    parser.add_argument('tag', action='store', help='The release tag (e.g., v1.5.0+20261022.1200)')
    parser.add_argument('--prerelease', action='store_true', help='Mark the release as a prerelease')
    parser.add_argument('--release-name', default='', help='The display name/title of the GitHub release')
    parser.add_argument('--release-url', required=True, help='The URL of the GitHub release page')
    parser.add_argument('--published-at', default='', help='The ISO-8601 publication timestamp of the GitHub release')
    parser.add_argument('--download-url', required=True, help='The direct download URL for the Windows release executable')
    parser.add_argument('--file-size', required=True, type=validate_positive_int, help='The size of the Windows release executable in bytes')
    parser.add_argument('--linux-download-url', required=True, help='The direct download URL for the Linux release binary')
    parser.add_argument('--linux-file-size', required=True, type=validate_positive_int, help='The size of the Linux release binary in bytes')
    parser.add_argument('--darwin-download-url', required=True, help='The direct download URL for the macOS release binary')
    parser.add_argument('--darwin-file-size', required=True, type=validate_positive_int, help='The size of the macOS release binary in bytes')

    args = parser.parse_args()
    validate_release_tag(parser, args.tag, prerelease=args.prerelease)

    webhook_url = validate_webhook_url(os.environ.get('DISCORD_WEBHOOK_URL', '').strip())
    payload = build_discord_payload(args, read_release_body_from_event())

    try:
        response = requests.post(
            webhook_url,
            json=payload,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException as err:
        message = f'Discord webhook request failed ({type(err).__name__}).'
        raise RuntimeError(message) from None
    if not response.ok:
        message = f'Discord webhook request failed with HTTP status {response.status_code}.'
        raise RuntimeError(message)


if __name__ == '__main__':
    main()
