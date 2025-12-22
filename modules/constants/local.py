"""Module for defining and managing constants that require a local function to be executed first."""
from pathlib import Path

import toml
from packaging.version import Version

from modules.utils import format_project_version, get_app_dir, resource_path

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


APP_DIR_LOCAL = get_app_dir(scope='local')
APP_DIR_ROAMING = get_app_dir(scope='roaming')

# Local (machine-specific): logs and large databases
ERROR_LOG_PATH = APP_DIR_LOCAL / 'error.log'
GEOLITE2_DATABASES_DIR_PATH = APP_DIR_LOCAL / 'GeoLite2 Databases'
SESSIONS_LOGGING_DIR_PATH = APP_DIR_LOCAL / 'Sessions Logging'
USERIP_LOGGING_PATH = APP_DIR_LOCAL / 'UserIP_Logging.log'

# Roaming (syncable): settings, user databases, user scripts
SETTINGS_PATH = APP_DIR_ROAMING / 'Settings.ini'
USERIP_DATABASES_DIR_PATH = APP_DIR_ROAMING / 'UserIP Databases'
USER_SCRIPTS_DIR_PATH = APP_DIR_ROAMING / 'scripts'
