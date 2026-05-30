"""Pydantic model for Looky GTA IP-to-player lookup API response."""

from datetime import datetime

from pydantic import BaseModel


class LookyPlayer(BaseModel):
    """A single GTA player entry returned by the Looky API for a given IP."""

    rockstarid: int
    name: str
    lastSeen: datetime  # noqa: N815
    lastCountry: str  # noqa: N815
    isModder: bool  # noqa: N815
    isEnhanced: bool  # noqa: N815
    isLegacy: bool  # noqa: N815
    isVpn: bool  # noqa: N815
