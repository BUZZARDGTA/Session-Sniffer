"""Reason-based process suspension manager for the global RDR2 process."""

from typing import ClassVar, override

from session_sniffer.capture.suspend_manager import BaseSuspendManager
from session_sniffer.rendering_core.types import CaptureState


class RDR2SuspendManager(BaseSuspendManager):
    """Singleton suspend manager (thread-safe, reason-based) for RDR2."""

    _game_name: ClassVar[str] = 'RDR2'

    @classmethod
    @override
    def _get_target_pid(cls) -> int | None:
        return CaptureState.rdr2_pid
