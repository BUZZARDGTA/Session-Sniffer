"""Application-lifetime stop event shared across all background threads."""

from threading import Event

gui_closed__event = Event()
