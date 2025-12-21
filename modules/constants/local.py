"""Module for defining and managing constants that require a local function to be executed first."""
from pathlib import Path

import toml
from packaging.version import Version

from modules.utils import format_project_version, resource_path

BIN_DIR_PATH = resource_path(Path('bin'))
IMAGES_DIR_PATH = resource_path(Path('images'))
PYPROJECT_PATH = resource_path(Path('pyproject.toml'))
REQUIREMENTS_PATH = resource_path(Path('requirements.txt'))
RESOURCES_DIR_PATH = resource_path(Path('resources'))
SCRIPTS_DIR_PATH = resource_path(Path('scripts'))
TTS_DIR_PATH = resource_path(Path('TTS'))

PYPROJECT_DATA = toml.load(PYPROJECT_PATH)
CURRENT_VERSION = Version(PYPROJECT_DATA['project']['version'])
VERSION = format_project_version(CURRENT_VERSION)
