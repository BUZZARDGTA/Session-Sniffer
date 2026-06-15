# Copilot Coding Agent Instructions for Session Sniffer

## Overview
Session Sniffer is a Windows‑only (PyQt6) packet sniffer focused on P2P game sessions. The entry point is `src/session_sniffer/main.py` (module execution via `python -m session_sniffer`), which orchestrates: environment checks, settings load, interface discovery, packet capture startup, background processing threads, and GUI initialization. Core logic lives under `src/session_sniffer/` in cohesive subpackages (capture, guis, networking, rendering_core, models, constants, discord). Data flows from live packet capture → player/session registries → rendering core → GUI worker thread signal → Qt table models/views.

Important import note: even with the `src/` layout, Python imports remain `from session_sniffer...`, not `from src.session_sniffer...`. The `src` directory is a source root on `PYTHONPATH`; it is not part of the package name.

## No Backward Compatibility — Ever
This project **never** maintains backward compatibility. When renaming, removing, or replacing anything (settings keys, field names, constants, APIs, file paths), always:
- Delete the old name/code outright.
- Update every call site to use the new name.
- Never add migration shims, alias wrappers, fallback lookups, or transitional validators.
- Never add code whose sole purpose is to handle the old form "just in case" users have old data.

If a user's saved data (e.g. `Settings.ini`) contains a stale key, it is treated as unknown and discarded by the existing rewrite logic — that is intentional and acceptable.

## Architecture & Data Flow
- Packet Capture: `PacketCapture` is constructed from an immutable `CaptureConfig` (see `src/session_sniffer/capture/packet_capture.py`) and invokes `config.callback` (created in `src/session_sniffer/main.py`) for each packet. That callback updates `PlayersRegistry`, detection warnings, and may spawn user IP processing threads.
- PacketCapture config/state: Read config via `capture.config` (e.g., `capture.config.interface`). Runtime state (threads/events/process handles) lives in an internal `_CaptureState` dataclass.
- Player State: Connected/disconnected movement handled via registry methods and `Player.left_event`. Rejoins call `mark_as_rejoined`; periodic packets call `mark_as_seen`.
- Rendering: Background thread `rendering_core` compiles `GUIUpdatePayload` objects using `GUIrenderingData` and emits them via `GUIWorkerThread.update_signal`. Avoid direct GUI mutations from non‑GUI threads.
- GUI: `MainWindow` owns two `SessionTableView` / `SessionTableModel` pairs (connected & disconnected). Heavy operations are skipped when a table is hidden; selection counts update headers. Respect existing optimization checks (`connected_count_changed`, visibility guards).
- Settings: Loaded frequently from `Settings.ini` via `Settings.load_from_settings_file`; after in‑memory changes call `Settings.reconstruct_settings()`. Feature toggles (detection flags, interface overrides) rely on this persistence.
- Screen Resolution: Always obtain via `get_screen_size()` which raises `UnsupportedScreenResolutionError` if below minimum; catch and display its `msgbox_text`.
- Concurrency: Threads are created as daemon named logically (e.g., `ProcessUserIPTask-<ip>-connected`). Uncaught exceptions in threads are handled automatically via `threading.excepthook` (installed in `src/session_sniffer/core/control.py`).

## Key Directories & Responsibilities
- `src/session_sniffer/capture/`: Interface selection, scapy/npcap checks, filter helpers.
- `src/session_sniffer/guis/`: Qt app bootstrap (`app.py`), size/util functions (`utils.py`), custom widgets, exceptions, stylesheets.
- `src/session_sniffer/networking/`: DNS, reverse DNS, MAC vendor (Wireshark `manuf`) lookup, ping management.
- `src/session_sniffer/rendering_core/`: Transforms registry + lookup results into GUI payloads.
- `src/session_sniffer/models/`: External API / release / lookup models (e.g., GitHub, IP APIs).
- `.github/workflows/Session_Sniffer.spec`: PyInstaller spec - update `datas` if adding runtime folders.

## User Data Storage (AppData)
Session Sniffer stores *all* user read/write data under the user's AppData, via constants in `src/session_sniffer/constants/local.py`.

- Local AppData (`scope='local'`) is for machine-specific and/or potentially large data (logs / databases / caches):
	- `Debug/` — debug log files (`errors.log`, `warnings.log`)
	- `Logging/` — application CSV logs (`Detection_Logging.csv`, `Protection_Logging.csv`, `UserIP_Logging.csv`) and `Sessions/` subdirectory
	- `GeoLite2 Databases/`
- Roaming AppData (`scope='roaming'`) is for user-owned and potentially syncable data (config / user-managed content):
	- `Settings.ini`
	- UserIP databases
	- User scripts

## Quality & Tooling Workflow
Use VS Code tasks instead of ad‑hoc commands:
- Run app: task `🚀 Launch Session Sniffer` (ensures `.venv` interpreter).
- Dependency check: `🔄 Check Project Dependencies` powershell script (read-only updates info).
- Install dependencies: `📦 Install Dependencies` after editing `pyproject.toml`.
- Unified quality run: `🔍 Run All Quality Checks` or individual tasks (Ruff, MyPy, Pyright, Flake8, Pylint, Vulture, Pip Audit, Safety, Snyk).

Ruff / Pyright / MyPy operate in strict modes; line length is 176; many docstring warnings are intentionally disabled. Preserve current suppression lists—do not re‑enable disabled IDs unless specifically requested.

## Dependency & Version Management
- Pin new dependencies exactly (match existing style) in `pyproject.toml` unless they are security libs (which may use `>=`).
- Python version is locked to `3.14`. Do not introduce syntax/features incompatible with tools expecting `py314` target.
- Release workflow builds a one‑file PyInstaller executable; additions to resources must be reflected in both repo and spec file.

## Patterns & Conventions
- **String Quotes**: Always use single quotes (`'`) for strings throughout the project. Use double quotes (`"`) only when the string itself contains single quotes.
- **Docstring Backticks**: Always use a single backtick (`` ` ``) to inline code in docstrings and comments. Never use RST-style double backticks (` `` `).
- **Future Imports**: Never use `from __future__ import annotations`. The project uses Python 3.14, which has native support for postponed annotation evaluation and does not require this import.
- **Type Hints**: Never use quoted forward references. Python 3.14 resolves annotations natively, so always use unquoted types (e.g., `selected_interface: SelectedInterface`).
- Avoid blocking operations or high‑latency lookups in the packet callback; offload to threads as done for user IP tasks.
- GUI updates: Generate data structures then call model methods (`refresh_view`, `remove_player_by_ip`, `reset_columns`); do not mutate Qt widgets from background threads.
- Reinitialize / recalc only when counts change or visibility demands (follow existing `connected_count_changed` / `disconnected_count_changed` logic).
- Settings mutation: After changing any `Settings.<attribute>` that persists, call `Settings.reconstruct_settings()` once per batch.
- User-data paths: Do not write into the repo/install directory. Use the path constants from `src/session_sniffer/constants/local.py`.
- AppData scope selection: Prefer Roaming for config/user-managed data, Local for logs/large databases.
- Capture filters: Compose lists then join with `and`; preserve conditional ordering (custom prepend filters first). When adding filters ensure symmetry with display filter logic if exclusion is related.
- Exceptions: Use project‑specific ones from `src/session_sniffer/guis/exceptions.py`. For new GUI error states, subclass similarly.
- Logging:
	- Configure once at startup via `session_sniffer.logging_setup.setup_logging(...)` (imported from `src/session_sniffer/logging_setup.py`; already done in `src/session_sniffer/main.py`).
	- Obtain loggers via `session_sniffer.logging_setup.get_logger(__name__)` (imported from `src/session_sniffer/logging_setup.py`; idempotent and safe anywhere).
	- Console output is Rich-formatted; file logging is split into `warnings.log` (WARNING only) and `errors.log` (ERROR+) under LOCALAPPDATA (the app data directory; not the current working directory).
	- Prefer `logger.debug/info/warning/error/exception(...)` over `print()` for diagnostics; use the shared Rich `console` only for intentional rich terminal output.

## Safe Extension Examples
- Adding a new player column: Append to `Settings.GUI_ALL_CONNECTED_COLUMNS`, add to `GUI_TOGGLEABLE_CONNECTED_COLUMNS` and/or `GUI_TOGGLEABLE_DISCONNECTED_COLUMNS`, update rendering_core mapping, and refresh header texts.
- Adding a resource directory: Place under repo root, then append to `datas` in `Session_Sniffer.spec` with correct relative path mapping.
- Adding a detection toggle: Create a flag in `GUIDetectionSettings`, add QAction in the Detection menu mirroring existing pattern, and integrate logic where warnings are issued.

## What to Avoid
- Direct modification of GUI widgets from non‑GUI threads.
- Long synchronous tasks inside `packet_callback`.
- Reformatting unrelated large sections (keeps diff noise low for PyInstaller & release processes).
- Changing constant naming style (mix of ALL_CAPS and CamelCase retained for backward compatibility).
- Using `assert` for runtime checks — always use `raise` with an appropriate exception (e.g., `raise RuntimeError(...)`, `raise ValueError(...)`) instead. `assert` is stripped by Python's optimizer (`-O`) and triggers Ruff S101.
- Adding `try/except` blocks defensively "just to be safe". Only catch exceptions that are explicitly documented or known to be raised by the called code (e.g., library APIs, I/O, external processes). Never wrap normal internal logic in broad `except Exception` or speculative `except (ValueError, RuntimeError)` guards. The project owner prefers a crash with a clear traceback over silent swallowing of unexpected errors.
- Creating shortcut/alias variables for attributes or functions that are only used inline. Never write `x = obj.attr` then use `x` — write `obj.attr` directly at every usage site. No exceptions.
- Adding any form of backward compatibility: migration validators, alias fields, fallback key lookups, shim functions, or transitional code paths. See **No Backward Compatibility — Ever** above.

## Before Committing Changes
1. Run `📦 Install Dependencies` if you changed dependency files.
2. Run `🔍 Run All Quality Checks` and ensure no regressions (ignore already ignored IDs).
3. Launch via `🚀 Launch Session Sniffer` to verify startup (screen resolution, interface selection, GUI render).
4. If resources/spec changed, dry‑run `pyinstaller Session_Sniffer.spec` locally (outside CI) if available.

Provide feedback if any section needs deeper detail (e.g., capture filter extension or rendering payload structure).

## Feature Addition
When adding or expanding features, make clean replacements. Replace older usage outright and remove obsolete code. See **No Backward Compatibility — Ever** above.
