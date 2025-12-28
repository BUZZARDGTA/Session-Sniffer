"""Provide functionality for MAC address lookup using the Wireshark manuf database.

Includes functions to fetch, parse, and search the database with CIDR-aware prefix matching.
"""
import re
from typing import TYPE_CHECKING, NamedTuple

from modules.constants.local import RESOURCES_DIR_PATH
from modules.networking.exceptions import (
    InvalidCidrError,
    InvalidMacPrefixError,
    InvalidManufacturerError,
    InvalidVendorNameError,
    ManufLineParseError,
)
from modules.networking.utils import is_mac_address

if TYPE_CHECKING:
    ManufDatabaseType = dict[str, list['ManufEntry']]

MANUF_FILE_PATH = RESOURCES_DIR_PATH / 'manuf'
RE_MANUF_ENTRY_PATTERN = re.compile(
    r"""
        ^
        (?P<mac_prefix>[0-9A-Fa-f:]{6,17})  # MAC address prefix
        (?:/(?P<cidr>\d+))?                 # Optional /CIDR
        [\t ]+                              # Separator
        (?P<manufacturer>\S+)               # Manufacturer
        (?:[\t ]+(?P<vendor_name>.*))?      # Optional organization name
        $
    """,
    re.VERBOSE,
)


class ManufEntry(NamedTuple):
    """Represent a parsed entry from the Wireshark manuf database."""

    mac_prefix: str
    prefix_int: int
    cidr: int
    manufacturer: str
    vendor_name: str


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


def _parse_and_load_manuf_database() -> ManufDatabaseType:
    """Parse the manuf file and return a database dict of prefix -> ManufEntry list."""
    manuf_database: ManufDatabaseType = {}

    for raw_line in MANUF_FILE_PATH.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue

        match = RE_MANUF_ENTRY_PATTERN.match(line)
        if not match:
            raise ManufLineParseError(line)

        mac_prefix, cidr, manufacturer, vendor_name = match.group('mac_prefix', 'cidr', 'manufacturer', 'vendor_name')
        if not isinstance(mac_prefix, str):
            raise InvalidMacPrefixError(mac_prefix)
        if not isinstance(cidr, (str, type(None))):
            raise InvalidCidrError(cidr)
        if not isinstance(manufacturer, str):
            raise InvalidManufacturerError(manufacturer)
        if not isinstance(vendor_name, str):
            raise InvalidVendorNameError(vendor_name)

        cidr_int = int(cidr) if cidr else 24
        prefix_int = _mac_prefix_str_to_int(mac_prefix, cidr_int)

        entry = ManufEntry(
            mac_prefix=mac_prefix,
            prefix_int=prefix_int,
            cidr=cidr_int,
            manufacturer=manufacturer,
            vendor_name=vendor_name,
        )
        manuf_database.setdefault(mac_prefix.upper(), [])
        if entry not in manuf_database[mac_prefix.upper()]:
            manuf_database[mac_prefix.upper()].append(entry)

    return manuf_database


class MacLookup:
    """Look up MAC address vendor information using the local manuf database."""

    def __init__(self, *, load_on_init: bool = False) -> None:
        """Initialize the MacLookup instance.

        Args:
            load_on_init: If True, fetch and load the manuf database immediately.
        """
        self.manuf_database: ManufDatabaseType | None = None
        if load_on_init:
            self._refresh_manuf_database()

    def _refresh_manuf_database(self) -> None:
        """Parse and load the manuf database."""
        self.manuf_database = _parse_and_load_manuf_database()

    def _find_best_match(self, mac_address: str) -> ManufEntry | None:
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

    def lookup(self, mac_address: str) -> ManufEntry | None:
        """Lookup the MAC address in the manuf database.

        Args:
            mac_address: The MAC address to look up.

        Returns:
            The best matching entry, or `None` if no match is found.
        """
        is_mac_address(mac_address, raise_exception=True)

        return self._find_best_match(mac_address)

    def get_mac_address_vendor_name(self, mac_address: str) -> str | None:
        """Return the vendor name for a given MAC address, if available."""
        entry = self.lookup(mac_address)
        if entry is None:
            return None
        return entry.vendor_name or None
