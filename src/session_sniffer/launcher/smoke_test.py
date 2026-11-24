"""Internal startup smoke-test runner for verifying built Session Sniffer executables."""

import json
import logging
import sys
from pathlib import Path

from PySide6.QtSvg import QSvgRenderer

from session_sniffer.capture.utils.npcap_checker import (
    can_capture_packets_on_darwin,
    can_capture_packets_on_linux,
    is_npcap_installed,
)
from session_sniffer.constants.local import (
    BUILTIN_SCRIPTS_DIR_PATH,
    RESOURCES_DIR_PATH,
    SETTINGS_PATH,
    VERSION,
)
from session_sniffer.guis.app import app
from session_sniffer.settings import Settings
from session_sniffer.utils import is_pyinstaller_compiled

logger = logging.getLogger(__name__)


def _parse_smoke_test_output_path(argv: list[str]) -> Path | None:
    """Return the optional smoke-test JSON output path from CLI arguments."""
    prefix = '--smoke-test-output='
    for index, arg in enumerate(argv):
        if arg.startswith(prefix):
            raw_path = arg.removeprefix(prefix).strip()
            return Path(raw_path) if raw_path else None
        if arg == '--smoke-test-output' and index + 1 < len(argv):
            raw_path = argv[index + 1].strip()
            return Path(raw_path) if raw_path else None
    return None


def run_smoke_test(argv: list[str]) -> None:
    """Verify bundled resources, Qt runtime initialization, settings, and optional capture permissions."""
    require_capture_permissions = '--require-capture-permissions' in argv
    output_path = _parse_smoke_test_output_path(argv)

    required_dirs = (
        RESOURCES_DIR_PATH,
        BUILTIN_SCRIPTS_DIR_PATH,
        Path(__file__).resolve().parents[1] / 'webserver' / 'static',
    )
    for directory in required_dirs:
        if not directory.is_dir():
            message = f'Required bundled directory is missing: {directory}'
            raise FileNotFoundError(message)

    icon_svg_path = RESOURCES_DIR_PATH / 'icons' / 'app_icon.svg'
    if not icon_svg_path.is_file():
        message = f'Required bundled icon is missing: {icon_svg_path}'
        raise FileNotFoundError(message)

    svg_renderer = QSvgRenderer(str(icon_svg_path))
    if not svg_renderer.isValid():
        message = f'QtSvg failed to load bundled icon: {icon_svg_path}'
        raise RuntimeError(message)

    qt_platform = app.platformName()
    if not qt_platform:
        message = 'Qt platform plugin name is empty.'
        raise RuntimeError(message)

    Settings.load_from_settings_file(SETTINGS_PATH)

    if sys.platform == 'darwin':
        capture_ready = can_capture_packets_on_darwin()
    elif sys.platform == 'linux':
        capture_ready = can_capture_packets_on_linux()
    else:
        capture_ready = is_npcap_installed()

    if require_capture_permissions and not capture_ready:
        message = f'Packet capture permissions are not ready on {sys.platform}.'
        raise RuntimeError(message)

    result: dict[str, object] = {
        'status': 'ok',
        'platform': sys.platform,
        'qt_platform': qt_platform,
        'version': VERSION,
        'frozen': is_pyinstaller_compiled(),
        'capture_ready': capture_ready,
    }
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(f'{json.dumps(result, indent=2)}\n', encoding='utf-8')

    summary = f'SMOKE_TEST_OK platform={sys.platform} qt={qt_platform} version={VERSION} frozen={is_pyinstaller_compiled()} capture_ready={capture_ready}'
    logger.info('%s', summary)
    if sys.stdout is not None:
        sys.stdout.write(f'{summary}\n')
        sys.stdout.flush()
