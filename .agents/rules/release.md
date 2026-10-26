---
trigger: model_decision
description: Use when working on packaging, PyInstaller, module exclusions, release builds, runtime resources, executable generation, dependency releases, CI/release configuration, or release validation.
---

# Release and Build Rules

Apply these rules when working on packaging, PyInstaller, release builds, runtime resources, executable generation, dependency releases, or CI/release configuration.

## Dependencies and Versioning

* Dependency pinning rules are defined in `security.md` ("Dependencies").
* Do not change dependency versions without understanding their impact on the supported Python version and existing tooling.
* Release version bumps (including `uv.lock` synchronization and the published-tag check) follow the `release` skill (`.agents/skills/release/SKILL.md`).

## GitHub Release Title

Whenever a release is prepared (e.g. via `/release`), always provide the GitHub release title alongside the changelog, in its own fenced code block so it can be copied in one click.

The title is derived strictly from the new `version` in `pyproject.toml`, using the version without its `+` build metadata, followed by the UTC build timestamp:

`<version-without-build-metadata> - YYYY/MM/DD (HH:MM)`

Examples:

* `v1.5.0rc.92+20261026.1829` → `v1.5.0rc.92 - 2026/10/26 (18:29)`
* `v1.5.0+20261101.0915` → `v1.5.0 - 2026/11/01 (09:15)`

The date and time must come from the version's build timestamp (UTC), never from local time. The release tag itself remains the full `version` string, including the `+` build metadata.

## PyInstaller

The release workflow builds a one-file executable using:

`.github/workflows/Session_Sniffer.spec`

When adding or moving runtime resources:

* ensure the resource exists in the repository,
* update the PyInstaller `datas` configuration when required,
* preserve the correct runtime-relative paths.

Do not assume that a file present in the source repository will automatically be included in the packaged executable.

### Module Exclusions and Lossless Packaging

The `excludes` list in `.github/workflows/Session_Sniffer.spec` must be maintained to keep the compiled executable as lean as possible while guaranteeing strictly lossless runtime behavior:

* **Size and Dependency Minimization**: Explicitly excluding unused modules prevents PyInstaller from bundling unneeded DLLs, QML engines, Chromium WebEngine binaries, and plugin hierarchies, keeping the compiled executable lean and focused strictly on active dependencies.
* **Lossless Packaging Standard**:
  * Never exclude a module, subpackage, or resource that is actively imported or required at runtime.
  * The application requires **only** the PySide6 modules actively used by the UI:
    * `PySide6.QtCore`
    * `PySide6.QtGui`
    * `PySide6.QtWidgets`
    * `PySide6.QtSvg` (required for `QSvgRenderer`)
  * Never exclude `shiboken6` or `PySide6.support` as they are essential to PySide6 core runtime operation.
  * All other unused PySide6/Qt modules (such as `QtNetwork`, `QtQml`, `QtQuick`, `QtOpenGL`, `QtPdf`, `QtWebEngine*`, `QtMultimedia*`, `Qt3D*`, `QtSql`, `QtSvgWidgets`, etc.) must remain excluded.
* **Alternative Qt Bindings**:
  * Always exclude `PyQt5` and `PyQt6` to prevent accidental discovery, hook execution, or bundling by third-party libraries.
* **Unused Python Standard Library Modules**:
  * Exclude unused GUI toolkits (`tkinter`, `_tkinter`, `turtle`, `idlelib`).
  * Exclude test frameworks and interactive documentation servers (`unittest`, `test`, `doctest`, `pydoc`, `pydoc_data`).
  * Exclude unused database engines (`sqlite3`, `_sqlite3`).
  * Exclude debuggers and profilers (`pdb`, `cProfile`, `profile`, `pstats`).
  * Exclude unused protocol and terminal modules (`xmlrpc`, `curses`).
* **Lossless Build Flags**:
  * Keep `optimize=0` in `Session_Sniffer.spec` to preserve assertions, bytecode integrity, and docstrings required by dependencies like Pydantic.
  * Keep `strip=False` to preserve symbol tables across binary formats (PE/ELF/Mach-O) and avoid binary corruption.
  * Keep `upx=False` to avoid binary header manipulation and runtime startup decompression overhead.
* **Spec File Maintenance**:
  * Before modifying `excludes`, verify module reachability across `src/` and dependencies.
  * Test application imports and startup in an environment where candidate excluded modules are blocked in `sys.modules`.
  * Validate `.github/workflows/Session_Sniffer.spec` using `python -m py_compile` and `flake8`.

## Release Validation

When release-sensitive files are changed:

* run the relevant quality checks,
* verify application startup when appropriate,
* verify affected runtime resources,
* dry-run the PyInstaller build locally when available and relevant.

## CI and Workflows

Do not modify release or CI workflows merely to accommodate unrelated code changes.

When changing workflow behavior, inspect the existing workflow and understand its dependencies, build sequence, artifacts, and release assumptions before editing it.
