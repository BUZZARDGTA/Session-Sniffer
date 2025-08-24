"""Module for defining and managing constants that require a local function to be executed first."""
from pathlib import Path

import toml
from packaging.version import Version

from modules.utils import format_project_version, resource_path

BIN_FOLDER_PATH = resource_path(Path("bin/"))
IMAGES_FOLDER_PATH = resource_path(Path("images/"))
PYPROJECT_PATH = resource_path(Path("pyproject.toml"))
REQUIREMENTS_PATH = resource_path(Path("requirements.txt"))
RESOURCES_FOLDER_PATH = resource_path(Path("resources/"))
SCRIPTS_FOLDER_PATH = resource_path(Path("scripts/"))
TTS_FOLDER_PATH = resource_path(Path("TTS/"))

PAPING_PATH = BIN_FOLDER_PATH / "paping.exe"
TSHARK_PATH = BIN_FOLDER_PATH / "WiresharkPortable64/App/Wireshark/tshark.exe"
COUNTRY_FLAGS_FOLDER_PATH = IMAGES_FOLDER_PATH / "country_flags"
MANUF_FILE_PATH = RESOURCES_FOLDER_PATH / "manuf"

PYPROJECT_DATA = toml.load(PYPROJECT_PATH)
CURRENT_VERSION = Version(PYPROJECT_DATA["project"]["version"])
VERSION = format_project_version(CURRENT_VERSION)
