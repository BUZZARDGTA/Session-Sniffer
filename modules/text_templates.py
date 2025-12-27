"""Centralized multi-line *assets*.

Keep only large, mostly-static multi-line blobs here (e.g., INI headers/defaults, HTML snippets).

Short, logic-dependent, or one-off UI messages should live close to their call sites.
"""


SETTINGS_INI_HEADER_TEMPLATE = """
;;-----------------------------------------------------------------------------
;; {title} Configuration Settings
;;-----------------------------------------------------------------------------
;; Lines starting with ";" or "#" symbols are commented lines.
;;
;; For detailed explanations of each setting, please refer to the following documentation:
;; {configuration_guide_url}
;;-----------------------------------------------------------------------------
"""


USERIP_DEFAULT_DB_HEADER_TEMPLATE = """
;;-----------------------------------------------------------------------------
;; {title} User IP default database file
;;-----------------------------------------------------------------------------
;; Lines starting with ";" or "#" symbols are commented lines.
;;
;; For detailed explanations of each setting, please refer to the following documentation:
;; {configuration_guide_url}
;;-----------------------------------------------------------------------------
[Settings]
"""


DEFAULT_USERIP_FILES_SETTINGS_INI: dict[str, str] = {
    'Blacklist.ini': """
ENABLED=True
COLOR=RED
LOG=True
NOTIFICATIONS=True
VOICE_NOTIFICATIONS=Male
PROTECTION=False
PROTECTION_PROCESS_PATH=None
PROTECTION_RESTART_PROCESS_PATH=None
PROTECTION_SUSPEND_PROCESS_MODE=Auto
""",
    'Enemylist.ini': """
ENABLED=True
COLOR=DARKGOLDENROD
LOG=True
NOTIFICATIONS=True
VOICE_NOTIFICATIONS=Male
PROTECTION=False
PROTECTION_PROCESS_PATH=None
PROTECTION_RESTART_PROCESS_PATH=None
PROTECTION_SUSPEND_PROCESS_MODE=Auto
""",
    'Friendlist.ini': """
ENABLED=True
COLOR=GREEN
LOG=True
NOTIFICATIONS=False
VOICE_NOTIFICATIONS=Female
PROTECTION=False
PROTECTION_PROCESS_PATH=None
PROTECTION_RESTART_PROCESS_PATH=None
PROTECTION_SUSPEND_PROCESS_MODE=Auto
""",
    'Randomlist.ini': """
ENABLED=True
COLOR=BLACK
LOG=True
NOTIFICATIONS=False
VOICE_NOTIFICATIONS=Female
PROTECTION=False
PROTECTION_PROCESS_PATH=None
PROTECTION_RESTART_PROCESS_PATH=None
PROTECTION_SUSPEND_PROCESS_MODE=Auto
""",
    'Searchlist.ini': """
ENABLED=True
COLOR=BLUE
LOG=True
NOTIFICATIONS=False
VOICE_NOTIFICATIONS=Female
PROTECTION=False
PROTECTION_PROCESS_PATH=None
PROTECTION_RESTART_PROCESS_PATH=None
PROTECTION_SUSPEND_PROCESS_MODE=Auto
""",
}


USERIP_DEFAULT_DB_FOOTER_TEMPLATE = """
[UserIP]
# Add users below in this format: username=IP
# Examples:
# username1=192.168.1.1
# username2=127.0.0.1
# username3=255.255.255.255
"""
