"""Module for defining and managing constants that require a local function to be executed first."""
from pathlib import Path
from typing import Any

import toml
from packaging.version import Version

from session_sniffer.utils import format_project_version, get_app_dir, get_working_directory_to_script_location, resource_path

SCRIPT_DIR: Path = get_working_directory_to_script_location()

BIN_DIR_PATH: Path = resource_path(Path('bin'))
IMAGES_DIR_PATH: Path = resource_path(Path('images'))
PYPROJECT_PATH: Path = resource_path(Path('pyproject.toml'))
RESOURCES_DIR_PATH: Path = resource_path(Path('resources'))
BUILTIN_SCRIPTS_DIR_PATH: Path = resource_path(Path('scripts'))
TTS_DIR_PATH: Path = resource_path(Path('TTS'))


PYPROJECT_DATA: dict[str, Any] = toml.load(PYPROJECT_PATH)
CURRENT_VERSION: Version = Version(PYPROJECT_DATA['project']['version'])
VERSION: str = format_project_version(CURRENT_VERSION)


APP_DIR_LOCAL: Path = get_app_dir(scope='local')
APP_DIR_ROAMING: Path = get_app_dir(scope='roaming')

# Local (machine-specific): logs and large databases
DEBUG_DIR_PATH: Path = APP_DIR_LOCAL / 'Debug'
DEBUG_LOG_PATH: Path = DEBUG_DIR_PATH / 'debug.log'
ERRORS_LOG_PATH: Path = DEBUG_DIR_PATH / 'errors.log'
WARNINGS_LOG_PATH: Path = DEBUG_DIR_PATH / 'warnings.log'

LOGGING_DIR_PATH: Path = APP_DIR_LOCAL / 'Logging'
DETECTION_LOGGING_PATH: Path = LOGGING_DIR_PATH / 'Detection_Logging.csv'
PROTECTION_LOGGING_PATH: Path = LOGGING_DIR_PATH / 'Protection_Logging.csv'
USERIP_LOGGING_PATH: Path = LOGGING_DIR_PATH / 'UserIP_Logging.csv'

GEOLITE2_DATABASES_DIR_PATH: Path = APP_DIR_LOCAL / 'GeoLite2 Databases'
SESSIONS_LOGGING_DIR_PATH: Path = LOGGING_DIR_PATH / 'Sessions'

# Roaming (syncable): settings, user databases, user scripts
COMBO_RULES_PATH: Path = APP_DIR_ROAMING / 'combo_rules.json'
PROTECTIONS_JSON_PATH: Path = APP_DIR_ROAMING / 'protections.json'
SETTINGS_PATH: Path = APP_DIR_ROAMING / 'Settings.ini'
USERIP_DATABASES_DIR_PATH: Path = APP_DIR_ROAMING / 'UserIP Databases'
USER_SCRIPTS_DIR_PATH: Path = APP_DIR_ROAMING / 'scripts'
