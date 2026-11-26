"""Pydantic models for persistent GUI layout state (gui_state.json)."""

import logging

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from session_sniffer.constants.local import GUI_STATE_PATH
from session_sniffer.utils import atomic_write_text

logger = logging.getLogger(__name__)


class WindowLayoutState(BaseModel):
    """Persistent layout state for an individual window or dialog."""

    geometry: str | None = None
    maximized: bool = False
    window_size: list[int] | None = None
    splitter: str | None = None
    splitter_sizes: list[int] | None = None
    always_on_top: bool | None = None
    active_tab: int | None = None
    active_tab_key: str | None = None
    max_history: int | None = None
    latency_all_time: bool | None = None

    model_config = ConfigDict(extra='ignore')


class TableLayoutState(BaseModel):
    """Persistent column widths, visual order, visibility, and sort state for a table or tree view."""

    column_widths: dict[str, int] | None = None
    column_order: list[str] | None = None
    hidden_columns: list[str] | None = None
    sort_column: str | None = None
    sort_order: int | None = None

    model_config = ConfigDict(extra='ignore')


class MainWindowExtraState(BaseModel):
    """Additional layout preferences specific to the main application window."""

    connected_expanded: bool = True
    disconnected_expanded: bool = True
    tables_merged: bool | None = None

    model_config = ConfigDict(extra='ignore')


class UserIPManagerExtraState(BaseModel):
    """Additional layout preferences specific to the UserIP Databases Manager."""

    group_accounts: bool = True
    settings_panel_expanded: bool = False

    model_config = ConfigDict(extra='ignore')


class GUIState(BaseModel):
    """Represents persistent GUI layout state saved across application launches."""

    windows: dict[str, WindowLayoutState] = Field(default_factory=dict)
    tables: dict[str, TableLayoutState] = Field(default_factory=dict)
    main_window: MainWindowExtraState = Field(default_factory=MainWindowExtraState)
    userip_manager: UserIPManagerExtraState = Field(default_factory=UserIPManagerExtraState)

    model_config = ConfigDict(extra='ignore')

    def get_window(self, key: str) -> WindowLayoutState | None:
        """Return the saved `WindowLayoutState` for *key*, or `None` if absent."""
        return self.windows.get(key)

    def ensure_window(self, key: str) -> WindowLayoutState:
        """Return the `WindowLayoutState` for *key*, creating a default entry if needed."""
        state = self.windows.get(key)
        if state is None:
            state = WindowLayoutState()
            self.windows[key] = state
        return state

    def get_table(self, key: str) -> TableLayoutState | None:
        """Return the saved `TableLayoutState` for *key*, or `None` if absent."""
        return self.tables.get(key)

    def ensure_table(self, key: str) -> TableLayoutState:
        """Return the `TableLayoutState` for *key*, creating a default entry if needed."""
        state = self.tables.get(key)
        if state is None:
            state = TableLayoutState()
            self.tables[key] = state
        return state

    @classmethod
    def load(cls) -> GUIState:
        """Load persistent GUI state from local app data."""
        if not GUI_STATE_PATH.is_file():
            return cls()
        try:
            return cls.model_validate_json(GUI_STATE_PATH.read_text(encoding='utf-8'))
        except (OSError, ValidationError) as e:
            logger.warning('Failed to load GUI state from %s: %s', GUI_STATE_PATH, e)
            return cls()

    def save(self) -> None:
        """Save persistent GUI state to local app data."""
        try:
            atomic_write_text(GUI_STATE_PATH, self.model_dump_json(indent=2, exclude_none=True))
        except OSError:
            logger.exception('Failed to save GUI state to %s', GUI_STATE_PATH)

    @classmethod
    def clear_file(cls) -> bool:
        """Delete the persisted `gui_state.json` file if it exists; return `True` on success."""
        try:
            if GUI_STATE_PATH.is_file():
                GUI_STATE_PATH.unlink()
        except OSError:
            logger.exception('Failed to delete GUI state file %s', GUI_STATE_PATH)
            return False
        return True
