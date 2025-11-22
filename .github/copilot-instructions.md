# Copilot Coding Agent Instructions for Session Sniffer

## Overview
Session Sniffer is a Windows‑only (PyQt6) packet sniffer focused on P2P game sessions. The entry point is `session_sniffer.py`, which orchestrates: environment checks, settings load, interface discovery, packet capture startup, background processing threads, and GUI initialization. Core logic lives under `modules/` in cohesive subpackages (capture, guis, networking, rendering_core, models, constants, discord). Data flows from live packet capture → player/session registries → rendering core → GUI worker thread signal → Qt table models/views.

## Architecture & Data Flow
- Packet Capture: `PacketCapture` (created in `session_sniffer.py`) invokes `packet_callback` for each packet. That callback updates `PlayersRegistry`, detection warnings, and may spawn user IP processing threads.
- Player State: Connected/disconnected movement handled via registry methods and `Player.left_event`. Rejoins call `mark_as_rejoined`; periodic packets call `mark_as_seen`.
- Rendering: Background thread `rendering_core` compiles `GUIUpdatePayload` objects using `GUIrenderingData` and emits them via `GUIWorkerThread.update_signal`. Avoid direct GUI mutations from non‑GUI threads.
- GUI: `MainWindow` owns two `SessionTableView` / `SessionTableModel` pairs (connected & disconnected). Heavy operations are skipped when a table is hidden; selection counts update headers. Respect existing optimization checks (`connected_count_changed`, visibility guards).
- Settings: Loaded frequently from `Settings.ini` via `Settings.load_from_settings_file`; after in‑memory changes call `Settings.reconstruct_settings()`. Feature toggles (detection flags, interface overrides) rely on this persistence.
- Screen Resolution: Always obtain via `get_screen_size()` which raises `UnsupportedScreenResolutionError` if below minimum; catch and display its `msgbox_text`.
- Concurrency: Threads are created as daemon named logically (e.g., `ProcessUserIPTask-<ip>-connected`). Use provided helpers (`ThreadsExceptionHandler`) for safe exception handling.

## Key Directories & Responsibilities
- `modules/capture/`: Interface selection, tshark/npcap checks, filter helpers.
- `modules/guis/`: Qt app bootstrap (`app.py`), size/util functions (`utils.py`), custom widgets, exceptions, stylesheets.
- `modules/networking/`: DNS, reverse DNS, manufacturer lookup, ping management.
- `modules/rendering_core/`: Transforms registry + lookup results into GUI payloads.
- `modules/models/`: External API / release / lookup models (e.g., GitHub, IP APIs).
- `UserIP Databases/`: INI‑based user IP tagging; processed asynchronously when first seen.
- `.github/workflows/Session_Sniffer.spec`: PyInstaller spec – update `datas` if adding runtime folders.

## Quality & Tooling Workflow
Use VS Code tasks instead of ad‑hoc commands:
- Run app: task `🚀 Launch Session Sniffer` (ensures `.venv` interpreter).
- Dependency check: `🔄 Check Dependencies` powershell script (read‑only updates info).
- Install deps: `📦 Install Dependencies` after editing `pyproject.toml` / `requirements.txt`.
- Unified quality run: `🔍 Run All Quality Checks` or individual tasks (Ruff, MyPy, Pyright, Flake8, Pylint, Vulture, Pydocstyle, Pip Audit, Safety, Snyk).

Ruff / Pyright / MyPy operate in strict modes; line length is 176; many docstring warnings are intentionally disabled. Preserve current suppression lists—do not re‑enable disabled IDs unless specifically requested.

## Dependency & Version Management
- Pin new dependencies exactly (match existing style) in both `pyproject.toml` and `requirements.txt` unless they are security libs (which may use `>=`).
- Python version is locked to `3.14`. Do not introduce syntax/features incompatible with tools expecting `py314` target.
- Release workflow builds a one‑file PyInstaller executable; additions to resources must be reflected in both repo and spec file.

## Patterns & Conventions
- Avoid blocking operations or high‑latency lookups in the packet callback; offload to threads as done for user IP tasks.
- GUI updates: Generate data structures then call model methods (`refresh_view`, `remove_player_by_ip`, `clear_all_data`); do not mutate Qt widgets from background threads.
- Reinitialize / recalc only when counts change or visibility demands (follow existing `connected_count_changed` / `disconnected_count_changed` logic).
- Settings mutation: After changing any `Settings.<FIELD>` that persists, call `Settings.reconstruct_settings()` once per batch.
- Capture filters: Compose lists then join with `and`; preserve conditional ordering (custom prepend filters first). When adding filters ensure symmetry with display filter logic if exclusion is related.
- Exceptions: Use project‑specific ones from `modules/guis/exceptions.py`. For new GUI error states, subclass similarly.

## Safe Extension Examples
- Adding a new player field: Append to `Settings.GUI_ALL_CONNECTED_FIELDS`, ensure not in `FIELDS_TO_HIDE`, update rendering_core mapping, and refresh header texts.
- Adding a resource directory: Place under repo root, then append to `datas` in `Session_Sniffer.spec` with correct relative path mapping.
- Adding a detection toggle: Create a flag in `GUIDetectionSettings`, add QAction in the Detection menu mirroring existing pattern, and integrate logic where warnings are issued.

## What to Avoid
- Direct modification of GUI widgets from non‑GUI threads.
- Long synchronous tasks inside `packet_callback`.
- Reformatting unrelated large sections (keeps diff noise low for PyInstaller & release processes).
- Changing constant naming style (mix of ALL_CAPS and CamelCase retained for backward compatibility).

## Before Committing Changes
1. Run `📦 Install Dependencies` if you changed dependency files.
2. Run `🔍 Run All Quality Checks` and ensure no regressions (ignore already ignored IDs).
3. Launch via `🚀 Launch Session Sniffer` to verify startup (screen resolution, interface selection, GUI render).
4. If resources/spec changed, dry‑run `pyinstaller Session_Sniffer.spec` locally (outside CI) if available.

Provide feedback if any section needs deeper detail (e.g., capture filter extension or rendering payload structure).

## Feature Addition & Backward Compatibility Preference
When adding or expanding features, prefer clean replacements over backward compatibility. Replace older usage outright and remove obsolete code.
