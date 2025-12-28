"""Provide functionality for MAC address lookup using the Wireshark manuf database.

Includes functions to fetch, parse, and search the database, with support for longest-prefix matching.
"""
import re
from typing import TYPE_CHECKING, NamedTuple

from modules.constants.local import RESOURCES_DIR_PATH
from modules.networking.exceptions import (
    InvalidFullVendorNameError,
    InvalidMacAddressBlockError,
    InvalidPrefixLengthBitsError,
    InvalidWiresharkResolutionAliasError,
    ManufLineParseError,
)
from modules.networking.utils import is_mac_address

if TYPE_CHECKING:
    ManufDatabaseType = dict[str, list['ManufEntry']]

MANUF_FILE_PATH = RESOURCES_DIR_PATH / 'manuf'
RE_MANUF_ENTRY_PATTERN = re.compile(
    r"""
        ^
        (?P<mac_address_block>  # MAC address block
            (?:[0-9A-Fa-f]{2}:){2}[0-9A-Fa-f]{2}  # 3-byte base
            (?::[0-9A-Fa-f]{2}){0,2}  # optional 4th and 5th byte for /28 and /36 bits wide
        )
        (?:/(?P<prefix_length_bits>24|28|36))?  # optional IEEE prefix length in bits; default 24 if missing
        [ \t]+
        (?P<wireshark_resolution_alias>\S+)  # shortened name used by Wireshark for address name resolution
        [ \t]+
        (?P<full_vendor_name>[^\t]+)  # the full vendor name from the registry
        $
    """,
    re.VERBOSE,
)


class ManufEntry(NamedTuple):
    """Represent a parsed entry from the Wireshark manuf database."""

    mac_address_block: str
    prefix_int: int
    prefix_length_bits: int
    wireshark_resolution_alias: str
    full_vendor_name: str


def _mac_str_to_int(mac: str) -> int:
    """Convert a MAC address string (with colons or dashes) to an integer."""
    return int(mac.translate(str.maketrans('', '', ':-')), 16)


def _mac_address_block_str_to_int(mac_address_block: str, prefix_length_bits: int) -> int:
    """Convert the MAC address block string to an integer, shifted to the top bits per prefix length."""
    raw_int = _mac_str_to_int(mac_address_block)
    shift_amount = 48 - prefix_length_bits
    return raw_int << shift_amount


def _matches_prefix(mac_int: int, prefix_int: int, prefix_length_bits: int) -> bool:
    """Return whether `mac_int` matches `prefix_int` on the first `prefix_length_bits` bits."""
    shift = 48 - prefix_length_bits  # MAC addresses are 48 bits long
    return (mac_int >> shift) == (prefix_int >> shift)


def _parse_and_load_manuf_database() -> ManufDatabaseType:
    """Parse the manuf file and return a database dict of prefix -> `ManufEntry` list."""
    manuf_database: ManufDatabaseType = {}

    for raw_line in MANUF_FILE_PATH.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue

        match = RE_MANUF_ENTRY_PATTERN.match(line)
        if not match:
            raise ManufLineParseError(line)

        mac_address_block, prefix_length_bits, wireshark_resolution_alias, full_vendor_name = match.group(
            'mac_address_block',
            'prefix_length_bits',
            'wireshark_resolution_alias',
            'full_vendor_name',
        )
        if not isinstance(mac_address_block, str):
            raise InvalidMacAddressBlockError(mac_address_block)
        if not isinstance(prefix_length_bits, (str, type(None))):
            raise InvalidPrefixLengthBitsError(prefix_length_bits)
        if not isinstance(wireshark_resolution_alias, str):
            raise InvalidWiresharkResolutionAliasError(wireshark_resolution_alias)
        if not isinstance(full_vendor_name, str):
            raise InvalidFullVendorNameError(full_vendor_name)

        prefix_length_bits_int = int(prefix_length_bits) if prefix_length_bits is not None else 24
        prefix_int = _mac_address_block_str_to_int(mac_address_block, prefix_length_bits_int)

        entry = ManufEntry(
            mac_address_block=mac_address_block,
            prefix_int=prefix_int,
            prefix_length_bits=prefix_length_bits_int,
            wireshark_resolution_alias=wireshark_resolution_alias,
            full_vendor_name=full_vendor_name,
        )
        manuf_database.setdefault(mac_address_block.upper(), [])
        if entry not in manuf_database[mac_address_block.upper()]:
            manuf_database[mac_address_block.upper()].append(entry)

    return manuf_database


class MacLookup:
    """Look up MAC address vendor information using the local manuf database."""

    def __init__(self, *, load_on_init: bool = False) -> None:
        """Initialize the MacLookup instance.

        Args:
            load_on_init: If `True`, fetch and load the manuf database immediately.
        """
        self.manuf_database: ManufDatabaseType | None = None
        if load_on_init:
            self._refresh_manuf_database()

    def _refresh_manuf_database(self) -> None:
        """Parse and load the manuf database."""
        self.manuf_database = _parse_and_load_manuf_database()

    def _find_best_match(self, mac_address: str) -> ManufEntry | None:
        """Find the best matching `ManufEntry` for the given MAC address, with support for longest-prefix matching."""
        if self.manuf_database is None:
            self._refresh_manuf_database()
        if self.manuf_database is None:
            return None

        mac_int = _mac_str_to_int(mac_address)

        best_entry: ManufEntry | None = None
        best_prefix_length_bits = -1

        for manuf_entries in self.manuf_database.values():
            for manuf in manuf_entries:
                if (
                    _matches_prefix(mac_int, manuf.prefix_int, manuf.prefix_length_bits)
                    and manuf.prefix_length_bits > best_prefix_length_bits
                ):
                    best_prefix_length_bits = manuf.prefix_length_bits
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
        return entry.full_vendor_name or None
