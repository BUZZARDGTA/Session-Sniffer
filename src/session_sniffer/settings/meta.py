"""Setting type enumeration and metadata dataclass for application settings."""

from dataclasses import dataclass
from enum import Enum, auto


class SettingType(Enum):
    """Enumeration of supported setting widget types."""

    BOOLEAN = auto()
    STRING = auto()
    INTEGER = auto()
    INTEGER_OR_ALL = auto()
    FLOAT = auto()
    ENUM = auto()
    IPV4 = auto()
    MAC_ADDRESS = auto()
    COLUMN_TUPLE = auto()
    IP_RANGE_TUPLE = auto()
    STRING_TUPLE = auto()
    THIRD_PARTY_SERVERS_TUPLE = auto()
    COLOR = auto()


@dataclass(frozen=True, slots=True)
class SettingMeta:
    """Metadata describing a single application setting for the Settings dialog."""

    category: str
    display_label: str
    setting_type: SettingType
    tooltip: str = ''
    requires_capture_restart: bool = False
    allowed_values: tuple[str, ...] = ()
    min_value: float | None = None
    max_value: float | None = None
    step: float | None = None
    allowed_columns_attr: str | None = None
    display_labels: dict[str, str] | None = None
    group: str | None = None
    subgroup: str | None = None
    hidden: bool = False
    special_value_text: str = 'All'
    max_length: int | None = None
    min_width: int | None = None
    max_width: int | None = None
    validator_pattern: str | None = None
    secret: bool = False
    suffix: str | None = None
