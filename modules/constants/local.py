"""Module for defining and managing constants that require a local function to be executed first."""

# Standard Python Libraries
from pathlib import Path

# External/Third-party Python Libraries
import toml
from packaging.version import Version

# Local Python Libraries (Included with Project)
from modules.utils import format_project_version, get_documents_folder, resource_path


PYPROJECT_PATH = resource_path(Path("pyproject.toml"))
REQUIEREMENTS_PATH = resource_path(Path("requirements.txt"))
BIN_PATH = resource_path(Path("bin/"))
IMAGES_PATH = resource_path(Path("images/"))
SCRIPTS_PATH = resource_path(Path("scripts/"))
SETUP_PATH = resource_path(Path("setup/"))
TTS_PATH = resource_path(Path("TTS/"))

PYPROJECT_DATA = toml.load(PYPROJECT_PATH)
VERSION = format_project_version(Version(PYPROJECT_DATA["project"]["version"]))

CHERAX__PLUGIN__LOG_PATH = get_documents_folder() / "Cherax/Lua/GTA_V_Session_Sniffer-plugin/log.txt"
