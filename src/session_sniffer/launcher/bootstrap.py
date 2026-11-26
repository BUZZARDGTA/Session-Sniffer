"""Lightweight startup bootstrap that enforces single-instance before importing GUI or heavy modules."""

import importlib
import sys
from typing import TYPE_CHECKING, cast

from session_sniffer.launcher.single_instance import acquire_single_instance

if TYPE_CHECKING:
    from collections.abc import Callable


def bootstrap() -> None:
    """Enforce single-instance (except in `--smoke-test` mode) and launch the main application."""
    if '--smoke-test' not in sys.argv[1:] and not acquire_single_instance():
        sys.exit(0)

    main_module = importlib.import_module('session_sniffer.main')
    main_entry = cast('Callable[[], None]', vars(main_module)['main'])
    main_entry()


if __name__ == '__main__':
    bootstrap()
