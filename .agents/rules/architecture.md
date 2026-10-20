---
trigger: model_decision
description: Use when changing subsystem boundaries, application data flow, threading architecture, shared state, major refactoring, moving functionality, new abstractions, or significant component integration.
---

# Architecture Rules

Apply these rules when a task involves subsystem boundaries, data flow, threading architecture, shared state, major refactoring, moving functionality, new abstractions, or significant integration between components.

## Existing Architecture

Session Sniffer is a mature codebase. Treat its existing architecture as intentional until investigation shows that a change is necessary.

Before making an architectural change:

* locate the current implementation,
* trace its callers and consumers,
* understand the data flow,
* identify ownership of state and lifecycle,
* inspect related configuration, models, workers, signals, and UI,
* search for existing abstractions serving a similar purpose.

Do not design a new architecture based only on the task description when the repository already contains the relevant implementation.

## Responsibilities

Preserve clear separation between existing subsystems.

The established application flow is:

packet capture → player/session state → rendering core → GUI worker signals → Qt models/views

Keep responsibilities within the subsystem that already owns them.

Do not move business logic into UI code merely because the UI consumes its results.

Do not move capture or network processing into GUI components.

Do not make background components directly manipulate Qt widgets.

## Low-Level vs High-Level Separation

Enforce a strict architectural separation between low-level native bindings and high-level Python logic:

* **Low-level native binding modules (`ctypes_*.py` and `capture/pcap.py`)** are restricted to `ctypes` / `ctypes.wintypes` definitions, `ctypes.Structure` layouts, COM vtable definitions, DLL/`CDLL` loading, and thin wrapper functions/handles that translate between C ABI calls and Python values. They must not contain `subprocess` calls, `winreg` queries, regex parsing, `/proc` or `/sys` file readers, or business logic.
* **High-level modules** own domain models, cross-platform dispatch, `/proc` and `/sys` file parsing, `subprocess` / `winreg` / `re` logic, workers, and UI integration. High-level modules must never import `ctypes` or `ctypes.wintypes` directly; they must call into the dedicated low-level modules (`session_sniffer.ctypes_windows`, `session_sniffer.ctypes_console`, `session_sniffer.ctypes_wintrust`, `session_sniffer.capture.ctypes_process`, `session_sniffer.capture.pcap`, `session_sniffer.capture.utils.ctypes_win32`, or `session_sniffer.networking.ctypes_adapters_info`).

## Abstractions

Prefer existing abstractions over introducing new ones.

Do not create a new:

* manager,
* service layer,
* registry,
* controller,
* wrapper,
* abstraction,
* event system,
* configuration mechanism

unless the existing architecture demonstrably cannot support the required behavior.

Avoid abstractions whose only purpose is to hide a small operation or reduce a few repeated lines.

## State and Lifecycle

Identify the owner of shared state before changing it.

Preserve existing:

* initialization order,
* shutdown behavior,
* worker lifetimes,
* thread ownership,
* event handling,
* configuration flow,
* persistence behavior.

Do not duplicate state that is already owned by an existing registry, configuration object, model, or worker.

## Configuration

Follow the project's existing settings architecture.

Settings are loaded through the existing `Settings` mechanisms and persistent changes are reconstructed through the established `Settings.rewrite_settings_file()` flow.

Do not introduce a parallel configuration or persistence mechanism.

## Refactoring

Architectural refactoring must remain focused on the requested problem.

Do not combine an architectural change with unrelated:

* formatting,
* renaming,
* cleanup,
* file movement,
* API redesign,
* dependency changes,
* or modernization.

When replacing an existing design, make a clean replacement rather than maintaining two implementations for compatibility.

## Validation

After architectural changes, verify the affected data flow and integration points rather than checking only whether the modified file passes static analysis.

Use the project's existing quality and launch/validation workflow where appropriate.
