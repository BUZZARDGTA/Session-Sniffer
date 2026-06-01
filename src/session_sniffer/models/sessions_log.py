"""Pydantic model for persisted session log JSON files."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SessionLogFile(BaseModel):
    """Validated shape for a saved sessions JSON file."""

    connected: dict[str, dict[str, Any]] = Field(default_factory=dict)
    disconnected: dict[str, dict[str, Any]] = Field(default_factory=dict)

    model_config = ConfigDict(extra='ignore')
