"""Provide functionality for MAC address lookup using the Wireshark manuf database.

Includes functions to fetch, parse, and search the database, with support for longest-prefix matching.
"""

import re
from typing import ClassVar, NamedTuple

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.networking.exceptions import (
    InvalidFullVendorNameError,
    InvalidMacAddressBlockError,
    InvalidPrefixLengthBitsError,
    ManufLineParseError,
)
from session_sniffer.networking.utils import is_mac_address

type ManufDatabaseType = dict[str, list[ManufEntry]]

MANUF_FILE_PATH = RESOURCES_DIR_PATH / 'manuf'
_MAC_SEPARATORS_TRANSLATION = str.maketrans('', '', ':-')
RE_MANUF_ENTRY_PATTERN = re.compile(
    r"""
        ^
        (?P<mac_address_block>  # MAC address block
            (?:[0-9A-Fa-f]{2}:){2}[0-9A-Fa-f]{2}  # 3-byte base
            (?::[0-9A-Fa-f]{2}){0,2}  # optional 4th and 5th byte for /28 and /36 bits wide
        )
        (?:/(?P<prefix_length_bits>24|28|36))?  # optional IEEE prefix length in bits; default 24 if missing
        [ \t]+
        \S+  # shortened name used by Wireshark for address name resolution
        [ \t]+
        (?P<full_vendor_name>[^\t]+)  # the full vendor name from the registry
        $
    """,
    re.VERBOSE,
)


class ManufEntry(NamedTuple):
    """Represent a parsed entry from the Wireshark manuf database."""

    prefix_int: int
    prefix_length_bits: int
    full_vendor_name: str


def _mac_str_to_int(mac: str) -> int:
    """Convert a MAC address string (with colons or dashes) to an integer."""
    return int(mac.translate(_MAC_SEPARATORS_TRANSLATION), 16)


def _mac_address_block_str_to_int(mac_address_block: str) -> int:
    """Convert the MAC address block string to a 48-bit-aligned integer."""
    hex_digits = mac_address_block.translate(_MAC_SEPARATORS_TRANSLATION)
    shift_amount = 48 - (len(hex_digits) * 4)
    return int(hex_digits, 16) << shift_amount


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

        mac_address_block, prefix_length_bits, full_vendor_name = match.group(
            'mac_address_block',
            'prefix_length_bits',
            'full_vendor_name',
        )
        if not isinstance(mac_address_block, str):
            raise InvalidMacAddressBlockError(mac_address_block)
        if not isinstance(prefix_length_bits, (str, type(None))):
            raise InvalidPrefixLengthBitsError(prefix_length_bits)
        if not isinstance(full_vendor_name, str):
            raise InvalidFullVendorNameError(full_vendor_name)

        prefix_length_bits_int = int(prefix_length_bits) if isinstance(prefix_length_bits, str) else 24
        prefix_int = _mac_address_block_str_to_int(mac_address_block)

        entry = ManufEntry(
            prefix_int=prefix_int,
            prefix_length_bits=prefix_length_bits_int,
            full_vendor_name=full_vendor_name,
        )
        block_key = mac_address_block.upper()
        bucket = manuf_database.setdefault(block_key, [])
        if entry not in bucket:
            bucket.append(entry)

    return manuf_database


class MacLookup:
    """App-wide MAC address vendor lookup backed by the Wireshark manuf database.

    The parsed database is held in a single class-level cache. Call `load()` once
    at startup; afterwards `lookup()` and `get_vendor_name()` are safe to call
    from any thread (the database is read-only after load).
    """

    _database: ClassVar[ManufDatabaseType | None] = None

    @classmethod
    def load(cls) -> None:
        """Parse and cache the manuf database. Idempotent."""
        if cls._database is None:
            cls._database = _parse_and_load_manuf_database()

    @classmethod
    def _find_best_match(cls, mac_address: str) -> ManufEntry | None:
        """Find the best matching `ManufEntry` for the given MAC address, with support for longest-prefix matching."""
        if cls._database is None:
            cls.load()
        if cls._database is None:
            return None

        mac_int = _mac_str_to_int(mac_address)
        normalized_mac = mac_address.replace('-', ':').upper()
        candidate_keys = (
            f'{normalized_mac[:13]}0',
            f'{normalized_mac[:10]}0',
            normalized_mac[:8],
        )

        best_entry: ManufEntry | None = None
        best_prefix_length_bits = -1

        for candidate_key in candidate_keys:
            for manuf in cls._database.get(candidate_key, ()):
                if _matches_prefix(mac_int, manuf.prefix_int, manuf.prefix_length_bits) and manuf.prefix_length_bits > best_prefix_length_bits:
                    best_prefix_length_bits = manuf.prefix_length_bits
                    best_entry = manuf

        return best_entry

    @classmethod
    def lookup(cls, mac_address: str) -> ManufEntry | None:
        """Lookup the MAC address in the manuf database.

        Args:
            mac_address: The MAC address to look up.

        Returns:
            The best matching entry, or `None` if no match is found.
        """
        is_mac_address(mac_address, raise_exception=True)
        return cls._find_best_match(mac_address)

    @classmethod
    def get_vendor_name(cls, mac_address: str) -> str | None:
        """Return the vendor name for a given MAC address, if available."""
        entry = cls.lookup(mac_address)
        if entry is None:
            return None
        return entry.full_vendor_name or None
