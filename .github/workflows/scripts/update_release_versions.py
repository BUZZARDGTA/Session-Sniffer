"""Update release_versions.json with version info from a release tag."""  # noqa: INP001
import argparse
import json
from pathlib import Path

from packaging.version import InvalidVersion, Version

SHA256_HEX_LENGTH = 64
LOWERCASE_HEX_DIGITS = frozenset('0123456789abcdef')


def get_repo_root() -> Path:
    """Return the repository root directory for this workspace."""
    return Path(__file__).resolve().parents[3]


def validate_sha256(value: str) -> str:
    """Return the SHA-256 value if it is valid lowercase hexadecimal."""
    if len(value) != SHA256_HEX_LENGTH or not all(char in LOWERCASE_HEX_DIGITS for char in value):
        error_msg = 'SHA-256 must be exactly 64 lowercase hexadecimal characters.'
        raise argparse.ArgumentTypeError(error_msg)
    return value


def validate_release_type(
    parser: argparse.ArgumentParser,
    tag: str,
    version: Version,
    *,
    prerelease: bool,
) -> None:
    """Validate that the GitHub release type matches the parsed version."""
    if version.is_prerelease and not prerelease:
        error_msg = f'Release tag "{tag}" is a prerelease, but the GitHub release is not marked as prerelease.'
        parser.error(error_msg)

    if prerelease and not version.is_prerelease:
        error_msg = f'Release tag "{tag}" is not a prerelease, but the GitHub release is marked as prerelease.'
        parser.error(error_msg)


def main() -> None:
    """Update `release_versions.json` using the provided tag."""
    parser = argparse.ArgumentParser(description='Update "release_versions.json" with updated version info.')
    parser.add_argument('tag', action='store', help='The release tag (e.g., 1.3.7+20250405.1644)')
    parser.add_argument('--prerelease', action='store_true', help='Mark the release as a prerelease')
    parser.add_argument('--release-url', required=True, help='The URL of the GitHub release page (e.g., https://github.com/owner/repo/releases/tag/1.0.0)')
    parser.add_argument('--download-url', required=True, help='The direct download URL for the release executable')
    parser.add_argument('--sha256', required=True, type=validate_sha256, help='The SHA-256 hash of the release executable (lowercase hex)')

    args = parser.parse_args()

    try:
        version = Version(args.tag)
    except InvalidVersion:
        parser.error(f'Release tag must be a valid version: {args.tag!r}.')

    validate_release_type(parser, args.tag, version, prerelease=args.prerelease)

    json_path = get_repo_root() / 'release_versions.json'

    if not json_path.exists():
        error_msg = f'File: "{json_path.absolute()}" not found.'
        raise FileNotFoundError(error_msg)

    data = json.loads(json_path.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        error_msg = f'File: "{json_path.absolute()}" must contain a JSON object.'
        raise TypeError(error_msg)

    target_key = 'latest_prerelease' if args.prerelease else 'latest_stable'

    data[target_key] = {
        'base_version': version.base_version,
        'epoch': version.epoch,
        'release_url': args.release_url,
        'download_url': args.download_url,
        'sha256': args.sha256,
        'is_devrelease': version.is_devrelease,
        'is_postrelease': version.is_postrelease,
        'is_prerelease': version.is_prerelease,
        'local': version.local,
        'major': version.major,
        'micro': version.micro,
        'minor': version.minor,
        'post': version.post,
        'pre': version.pre,
        'public': version.public,
        'release': version.release,
        'version': str(version),
    }

    json_path.write_text(json.dumps(data, indent=4) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
