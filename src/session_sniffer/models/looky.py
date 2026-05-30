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


class LookyIpBatchResult(BaseModel):
    """One entry in a Looky `/api/search/ip-batch` response, mapping an IP to its player list."""

    ip: str
    players: list[LookyPlayer]


class LookyWhoAmI(BaseModel):
    """Raw response shape returned by `GET /api/whoami`."""

    authenticated: bool
    source: str
    apiAccess: bool  # noqa: N815
    status: bool
    username: str
    rid: int


class LookyUserData(BaseModel):
    """User account data derived from a successful Looky API key verification."""

    username: str
    apiAccess: bool  # noqa: N815
    rid: int


class LookyVerifyResponse(BaseModel):
    """Result of verifying a Looky API key via `GET /api/whoami`."""

    success: bool
    message: str | None = None
    userData: LookyUserData  # noqa: N815
