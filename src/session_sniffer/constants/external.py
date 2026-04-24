"""Module for defining constants that require imports from third-party libraries."""
from datetime import tzinfo  # noqa: TC003

from tzlocal import get_localzone

LOCAL_TZ: tzinfo = get_localzone()
