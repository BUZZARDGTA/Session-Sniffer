"""Pydantic model for persistent GUI state (gui_state.json)."""

from pydantic import BaseModel, ConfigDict


class GUIState(BaseModel):
    """Represents persistent GUI state saved across application launches."""

    userip_manager_geometry: str | None = None
    userip_manager_maximized: bool = False
    userip_manager_splitter: str | None = None

    model_config = ConfigDict(extra='allow')
