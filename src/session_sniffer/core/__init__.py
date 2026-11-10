"""Core infrastructure for crash state, exception handling and process control."""

from .control import (
    ScriptControl,
    install_exception_handlers,
    terminate_on_uncaught_exception,
    terminate_script,
)

__all__ = [
    'ScriptControl',
    'install_exception_handlers',
    'terminate_on_uncaught_exception',
    'terminate_script',
]
