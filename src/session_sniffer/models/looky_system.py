"""Pydantic model for the Looky System IP-to-player lookup API response."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

LookyInstructionStatus = Literal['queued', 'running', 'completed', 'failed', 'canceled', 'unknown']


class LookyPlayer(BaseModel):
    """A single player entry returned by the Looky System API for a given IP."""

    model_config = ConfigDict(populate_by_name=True)

    rockstarid: int
    name: str
    last_seen: datetime = Field(validation_alias='lastSeen')
    last_country: str = Field(validation_alias='lastCountry')
    is_modder: bool = Field(validation_alias='isModder')
    is_enhanced: bool = Field(validation_alias='isEnhanced')
    is_legacy: bool = Field(validation_alias='isLegacy')
    is_vpn: bool = Field(validation_alias='isVpn')


class LookyIpBatchResult(BaseModel):
    """One entry in a Looky System `/api/search/ip-batch` response, mapping an IP to its player list."""

    ip: str
    players: list[LookyPlayer]


class LookyWhoAmI(BaseModel):
    """Raw response shape returned by `GET /api/whoami`."""

    model_config = ConfigDict(populate_by_name=True)

    api_access: bool = Field(validation_alias='apiAccess')
    status: bool
    username: str
    rid: int


class LookyInstructionStatusEventData(BaseModel):
    """Payload of a Looky System `status_update` SSE event."""

    status: LookyInstructionStatus
    result: str | None = None


class LookyInstructionStatusEvent(BaseModel):
    """Top-level shape of a Looky System SSE `status_update` event JSON line."""

    data: LookyInstructionStatusEventData


class LookyInstructionStatusInitialInstruction(BaseModel):
    """The instruction object returned by the initial status endpoint."""

    status: LookyInstructionStatus
    result: str | None = None


class LookyPlayerSighting(BaseModel):
    """A single session sighting entry inside `LookyPlayerProfile.users_by_rockstar_id`."""

    model_config = ConfigDict(populate_by_name=True)

    datetimestamp: datetime
    rockstarid: int
    name: str
    ip: str
    country: str = 'unknown'
    vpn: bool = False
    enhanced: bool = False
    relay: bool = False


class LookyPlayerProfile(BaseModel):
    """Player profile and session IP history returned by `GET /api/player/{rid}`."""

    model_config = ConfigDict(populate_by_name=True)

    rockstarid: int = 0
    last_name: str = Field(default='', validation_alias='lastName')
    last_seen: datetime | None = Field(default=None, validation_alias='lastSeen')
    last_country: str = Field(default='unknown', validation_alias='lastCountry')
    is_modder: bool = Field(default=False, validation_alias='isModder')
    has_enhanced: bool = Field(default=False, validation_alias='hasEnhanced')
    users_by_rockstar_id: list[LookyPlayerSighting] = Field(default_factory=list[LookyPlayerSighting], validation_alias='usersByRockstarId')


class LookyInstructionStatusInitialResponse(BaseModel):
    """Raw response shape returned by `GET /api/instruction-status-initial/...`."""

    success: bool
    instruction: LookyInstructionStatusInitialInstruction
