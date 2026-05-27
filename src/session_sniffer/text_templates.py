"""Centralized multi-line *assets*.

Keep only large, mostly-static multi-line blobs here (e.g., INI headers/defaults, HTML snippets).

Short, logic-dependent, or one-off UI messages should live close to their call sites.
"""

from session_sniffer.constants.standalone import GITHUB_WIKI_SCRIPT_CONFIG_URL, TITLE
from session_sniffer.text_utils import format_triple_quoted_text

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


def build_settings_ini_header_text() -> str:
    """Return the formatted Settings.ini header text (with trailing newline)."""
    return format_triple_quoted_text(
        SETTINGS_INI_HEADER_TEMPLATE.format(
            title=TITLE,
            configuration_guide_url=GITHUB_WIKI_SCRIPT_CONFIG_URL,
        ),
        add_trailing_newline=True,
    )


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
PROTECTION_SUSPEND_PROCESS_MODE=Auto
""",
    'Enemylist.ini': """
ENABLED=True
COLOR=DARKGOLDENROD
LOG=True
NOTIFICATIONS=True
VOICE_NOTIFICATIONS=Male
PROTECTION=False
PROTECTION_SUSPEND_PROCESS_MODE=Auto
""",
    'Friendlist.ini': """
ENABLED=True
COLOR=GREEN
LOG=True
NOTIFICATIONS=False
VOICE_NOTIFICATIONS=Female
PROTECTION=False
PROTECTION_SUSPEND_PROCESS_MODE=Auto
""",
    'Randomlist.ini': """
ENABLED=True
COLOR=BLACK
LOG=True
NOTIFICATIONS=False
VOICE_NOTIFICATIONS=Female
PROTECTION=False
PROTECTION_SUSPEND_PROCESS_MODE=Auto
""",
    'Searchlist.ini': """
ENABLED=True
COLOR=BLUE
LOG=True
NOTIFICATIONS=False
VOICE_NOTIFICATIONS=Female
PROTECTION=False
PROTECTION_SUSPEND_PROCESS_MODE=Auto
""",
}


USERIP_DEFAULT_DB_FOOTER_TEMPLATE = """
[UserIP]
# Add users below in this format: username=IP_OR_RANGE
# Supported formats:
#   Single IP:  username1=192.168.1.1
#   CIDR range: username2=10.0.0.0/24
#   Start-end:  username3=192.168.1.100-192.168.1.200
#   Wildcard:   username4=172.16.*.*
"""
