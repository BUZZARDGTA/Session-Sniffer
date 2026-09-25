"""Pydantic model for persistent GUI state (gui_state.json)."""

import logging

from pydantic import BaseModel, ConfigDict

logger = logging.getLogger(__name__)


class GUIState(BaseModel):
    """Represents persistent GUI state saved across application launches."""

    userip_manager_geometry: str | None = None
    userip_manager_maximized: bool = False
    userip_manager_splitter: str | None = None
    userip_manager_table_column_widths: dict[str, int] | None = None
    main_window_splitter_sizes: list[int] | None = None
    connected_table_column_widths: dict[str, int] | None = None
    disconnected_table_column_widths: dict[str, int] | None = None

    model_config = ConfigDict(extra='allow')

    @classmethod
    def load(cls) -> GUIState:
        """Load persistent GUI state from local app data."""
        from session_sniffer.constants.local import GUI_STATE_PATH  # noqa: PLC0415

        if not GUI_STATE_PATH.is_file():
            return cls()
        try:
            return cls.model_validate_json(GUI_STATE_PATH.read_text(encoding='utf-8'))
        except Exception as e:  # noqa: BLE001
            logger.warning('Failed to load GUI state from %s: %s', GUI_STATE_PATH, e)
            return cls()

    def save(self) -> None:
        """Save persistent GUI state to local app data."""
        from session_sniffer.constants.local import GUI_STATE_PATH  # noqa: PLC0415

        try:
            GUI_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
            GUI_STATE_PATH.write_text(self.model_dump_json(indent=2), encoding='utf-8')
        except OSError:
            logger.exception('Failed to save GUI state to %s', GUI_STATE_PATH)
