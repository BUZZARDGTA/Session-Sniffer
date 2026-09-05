"""PS3 packet payload name resolver for PlayStation usernames."""

import re

# PSN Online IDs are 3 to 16 characters long and may contain alphanumeric characters, underscores, and hyphens.
_PSN_USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{3,16}$')
_PS3_MAGIC = b'\xff\x83\xff\xfe\xff\xfe'
_PS3_TAG = b'ps3'
_OUTGOING_OFFSET = 36
_INCOMING_OFFSET = 4
_PSN_MAX_LENGTH = 16


def extract_ps3_username(payload: bytes, *, sent_by_local_host: bool) -> str | None:
    """Extract and validate a PlayStation username from a PS3 packet UDP payload.

    Args:
        payload: The raw UDP packet payload bytes.
        sent_by_local_host: True if the packet was sent by the local host to a remote player;
            False if received from a remote player.

    Returns:
        The resolved PlayStation username string if found and valid, otherwise None.
    """
    if _PS3_MAGIC not in payload or _PS3_TAG not in payload:
        return None

    magic_index = payload.find(_PS3_MAGIC)
    after_magic = payload[magic_index + len(_PS3_MAGIC):]

    offset = _OUTGOING_OFFSET if sent_by_local_host else _INCOMING_OFFSET

    if len(after_magic) < offset + _PSN_MAX_LENGTH:
        return None

    raw_bytes = after_magic[offset:offset + _PSN_MAX_LENGTH].rstrip(b'\x00')
    try:
        candidate_username = raw_bytes.decode('ascii')
    except UnicodeDecodeError:
        return None

    if _PSN_USERNAME_PATTERN.match(candidate_username):
        return candidate_username

    return None
