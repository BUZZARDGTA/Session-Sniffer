# Standard Python Libraries
import json
import argparse
from pathlib import Path

# External/Third-party Python Libraries
from packaging.version import Version


def main():
    parser = argparse.ArgumentParser(description='Update "release_versions.json" with updated version info.')
    parser.add_argument("tag", action="store", help="The release tag (e.g., 1.3.7+20250405.1644)")
    parser.add_argument("--prerelease", action="store_true", help="Mark the release as a prerelease")

    args = parser.parse_args()

    version = Version(args.tag)
    json_path = Path("release_versions.json")

    if not json_path.exists():
        error_msg = f'File: "{json_path.absolute()}" not found.'
        raise FileNotFoundError(error_msg)

    data = json.loads(json_path.read_text())

    target_key = "latest_prerelease" if args.prerelease else "latest_stable"

    data[target_key] = {
        "base_version": version.base_version,
        "epoch": version.epoch,
        "is_devrelease": version.is_devrelease,
        "is_postrelease": version.is_postrelease,
        "is_prerelease": version.is_prerelease,
        "local": version.local,
        "major": version.major,
        "micro": version.micro,
        "minor": version.minor,
        "post": version.post,
        "pre": version.pre,
        "public": version.public,
        "release": version.release,
        "version": str(version),
    }

    json_path.write_text(json.dumps(data, indent=4) + "\n")


if __name__ == "__main__":
    main()
