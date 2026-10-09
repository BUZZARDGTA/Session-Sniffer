"""Reason-based process suspension manager for the global GTA5 process."""

from typing import ClassVar, override

from session_sniffer.capture.suspend_manager import BaseSuspendManager
from session_sniffer.rendering_core.types import CaptureState


class GTASuspendManager(BaseSuspendManager):
    """Singleton suspend manager (thread-safe, reason-based) for GTA5."""

    _game_name: ClassVar[str] = 'GTA5'

    @classmethod
    @override
    def _get_target_pid(cls) -> int | None:
        return CaptureState.gta5_pid
