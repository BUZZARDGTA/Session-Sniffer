"""Pydantic models for Discord Rich Presence IPC payloads.

This module provides data models for Discord IPC communication,
including handshake, activity commands, close frames, and responses.
"""

from pydantic import BaseModel, Field, model_serializer


class DiscordHandshakePayload(BaseModel):
    """Handshake payload sent to Discord IPC pipe upon opening."""

    v: int = 1
    client_id: str


class DiscordActivityButton(BaseModel):
    """Button item displayed in Discord Rich Presence."""

    label: str
    url: str


class DiscordActivityTimestamps(BaseModel):
    """Timestamps for Discord Rich Presence elapsed time display."""

    start: int


class DiscordActivity(BaseModel):
    """Rich presence activity definition."""

    state: str
    details: str | None = None
    timestamps: DiscordActivityTimestamps
    buttons: list[DiscordActivityButton] = Field(default_factory=list[DiscordActivityButton])

    @model_serializer
    def serialize_activity(self) -> dict[str, object]:
        """Serialize the activity, excluding details when None."""
        activity_data: dict[str, object] = {
            'state': self.state,
            'timestamps': self.timestamps.model_dump(),
            'buttons': [button.model_dump() for button in self.buttons],
        }
        if self.details is not None:
            activity_data['details'] = self.details
        return activity_data


class DiscordActivityArgs(BaseModel):
    """Arguments for SET_ACTIVITY command."""

    pid: int
    activity: DiscordActivity | None = None


class DiscordCommandPayload(BaseModel):
    """Outgoing command payload sent to Discord IPC."""

    cmd: str
    args: DiscordActivityArgs
    nonce: str


class DiscordClosePayload(BaseModel):
    """Empty payload sent with CLOSE opcode."""


class DiscordResponsePayload(BaseModel):
    """Incoming response payload received from Discord IPC."""

    cmd: str | None = None
    evt: str | None = None
    data: dict[str, object] | None = None
    nonce: str | None = None
