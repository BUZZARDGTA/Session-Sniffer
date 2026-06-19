"""Module for defining constants that require imports from third-party libraries."""

from typing import TYPE_CHECKING

from tzlocal import get_localzone

if TYPE_CHECKING:
    from datetime import tzinfo

LOCAL_TZ: tzinfo = get_localzone()
