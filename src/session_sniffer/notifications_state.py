"""Session-only visual and voice notification mute state shared between the GUI and background threads."""

from dataclasses import dataclass


@dataclass(slots=True)
class _NotificationsState:
    """Runtime notification toggles (quick "Do Not Disturb"), intentionally never persisted and reset on every launch."""

    visual_enabled: bool = True
    voice_enabled: bool = True


notifications_state = _NotificationsState()
