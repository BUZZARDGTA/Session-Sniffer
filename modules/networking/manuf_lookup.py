"""Provide functionality for MAC address lookup using the Wireshark manuf database.

Includes functions to fetch, parse, and search the database with CIDR-aware prefix matching.
"""
import re
from typing import TYPE_CHECKING

from pydantic.dataclasses import dataclass

from modules.constants.local import MANUF_FILE_PATH
from modules.networking.exceptions import (
    InvalidCidrError,
    InvalidMacPrefixError,
    InvalidManufacturerError,
    InvalidOrganizationNameError,
    ManufLineParseError,
)
from modules.networking.utils import is_mac_address

if TYPE_CHECKING:
    ManufDatabaseType = dict[str, list['ManufEntry']]

RE_MANUF_ENTRY_PATTERN = re.compile(
    r"""
        ^
        ([0-9A-Fa-f:]{6,17})  # MAC address prefix
        (?:/(\d+))?           # Optional /CIDR
        [\t ]+                # Separator
        (\S+)                 # Manufacturer
        (?:[\t ]+(.*))?       # Optional organization name
        $
    """,
    re.VERBOSE,
)


@dataclass(frozen=True, kw_only=True, slots=True)
class ManufEntry:
    mac_prefix: str
    prefix_int: int
    cidr: int
    manufacturer: str
    organization_name: str


def _mac_str_to_int(mac: str) -> int:
    """Convert a MAC address string (with colons or dashes) to an integer."""
    return int(mac.translate(str.maketrans('', '', ':-')), 16)


def _mac_prefix_str_to_int(prefix: str, cidr: int) -> int:
    """Convert the MAC prefix string to an integer, shifted to the top bits per CIDR."""
    raw_int = _mac_str_to_int(prefix)
    shift_amount = 48 - cidr
    return raw_int << shift_amount


def _matches_prefix(mac_int: int, prefix_int: int, cidr: int) -> bool:
    """Return True if mac_int matches the prefix_int on the first cidr bits."""
    shift = 48 - cidr  # MAC addresses are 48 bits long
    return (mac_int >> shift) == (prefix_int >> shift)


def _parse_and_load_manuf_database() -> 'ManufDatabaseType':
    """Parse the manuf file and return a database dict of prefix -> ManufEntry list."""
    manuf_database: ManufDatabaseType = {}

    for raw_line in MANUF_FILE_PATH.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue

        match = RE_MANUF_ENTRY_PATTERN.match(line)
        if not match:
            raise ManufLineParseError(line)

        mac_prefix, cidr, manufacturer, organization_name = match.groups()

        if not isinstance(mac_prefix, str):
            raise InvalidMacPrefixError(mac_prefix)
        if not isinstance(cidr, (str, type(None))):
            raise InvalidCidrError(cidr)
        if not isinstance(manufacturer, str):
            raise InvalidManufacturerError(manufacturer)
        if not isinstance(organization_name, str):
            raise InvalidOrganizationNameError(organization_name)

        cidr_int = int(cidr) if cidr else 24
        prefix_int = _mac_prefix_str_to_int(mac_prefix, cidr_int)

        entry = ManufEntry(
            mac_prefix=mac_prefix,
            prefix_int=prefix_int,
            cidr=cidr_int,
            manufacturer=manufacturer,
            organization_name=organization_name,
        )
        manuf_database.setdefault(mac_prefix.upper(), [])
        if entry not in manuf_database[mac_prefix.upper()]:
            manuf_database[mac_prefix.upper()].append(entry)

    return manuf_database


class MacLookup:
    def __init__(self, *, load_on_init: bool = False) -> None:
        """Initialize the MacLookup instance.

        :param load_on_init: If True, fetches and loads the manuf database immediately.
        """
        self.manuf_database: ManufDatabaseType | None = None
        if load_on_init:
            self._refresh_manuf_database()

    def _refresh_manuf_database(self) -> None:
        """Parse and load the manuf database."""
        self.manuf_database = _parse_and_load_manuf_database()

    def _find_best_match(self, mac_address: str) -> 'ManufEntry | None':
        """Find the best matching ManufEntry for the given MAC address using CIDR longest prefix match."""
        if self.manuf_database is None:
            self._refresh_manuf_database()
        if self.manuf_database is None:
            return None

        mac_int = _mac_str_to_int(mac_address)

        best_entry: ManufEntry | None = None
        best_cidr = -1

        for manuf_entries in self.manuf_database.values():
            for manuf in manuf_entries:
                if (
                    _matches_prefix(mac_int, manuf.prefix_int, manuf.cidr)
                    and manuf.cidr > best_cidr
                ):
                    best_cidr = manuf.cidr
                    best_entry = manuf

        return best_entry

    def lookup(self, mac_address: str) -> 'ManufEntry | None':
        """Lookup the MAC address in the manuf database.

        :param mac_address: MAC address to lookup (string)
        :return: Best matching ManufEntry or None if no match.
        """
        is_mac_address(mac_address, raise_exception=True)

        return self._find_best_match(mac_address)

    def get_mac_address_organization_name(self, mac_address: str) -> str | None:
        """Return the organization name for a given MAC address, if available."""
        entry = self.lookup(mac_address)
        if entry is None:
            return None
        return entry.organization_name or None
