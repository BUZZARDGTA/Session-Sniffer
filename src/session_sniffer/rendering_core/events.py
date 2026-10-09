"""Events for coordinating rendering core execution and waking."""

from threading import Event

rendering_wake_event = Event()


def wake_rendering_core() -> None:
    """Wake the rendering core thread immediately to produce a new snapshot without waiting."""
    rendering_wake_event.set()
