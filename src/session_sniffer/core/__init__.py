"""Core infrastructure for crash state, exception handling and process control."""

from .control import (
    ScriptControl,
    terminate_on_uncaught_exception,
    terminate_script,
)

__all__ = [
    'ScriptControl',
    'terminate_on_uncaught_exception',
    'terminate_script',
]
