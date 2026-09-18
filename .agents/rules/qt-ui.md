---
trigger: glob
globs: src/session_sniffer/guis/**/*.py
---

# Qt / PySide6 UI Rules

## Framework

* Use PySide6, following the project's existing Qt architecture.
* Do not introduce PyQt, Tkinter, wxPython, Electron, webviews, HTML/CSS interfaces, or another UI framework unless explicitly requested.
* Reuse existing widgets, models, views, delegates, styles, utilities, and UI patterns before creating new ones.

## Threading

* Never directly mutate Qt GUI widgets from a background thread.
* Keep long-running, blocking, or high-latency operations off the Qt GUI thread.
* Follow the project's existing worker/thread/signal architecture.
* Generate or transform data in background work and communicate results to the GUI through the existing signal/model patterns.

## Existing Architecture

Before changing UI behavior, inspect:

* the relevant widget hierarchy,
* related models and views,
* signals and slots,
* worker threads,
* controllers or rendering code,
* existing reusable components.

Do not create a second architecture for functionality that already has an established project pattern.

## Session Tables

The main window owns separate connected and disconnected `SessionTableView` / `SessionTableModel` pairs.

Preserve their existing:

* signal connections,
* selection behavior,
* header count updates,
* visibility guards,
* connected/disconnected table behavior.

Do not replace the established table architecture with a parallel model or view system.

## Performance

Preserve existing UI optimization checks.

In particular, respect visibility guards and count-change checks such as `connected_count_changed` and `disconnected_count_changed`.

Avoid unnecessary widget updates, model refreshes, recalculation, or re-rendering when the relevant state has not changed.

## Behavior

When modifying an existing UI component, preserve its established behavior unless the task explicitly requires changing it.

Pay particular attention to:

* signals and slots,
* selection behavior,
* keyboard interaction,
* sorting and filtering,
* column configuration,
* persistent settings,
* connected/disconnected table behavior,
* visibility-dependent work.

## Styling

Follow the project's existing styling and stylesheet architecture.

Do not introduce a separate styling system or duplicate existing styles just to implement a local UI change.

## Icons and SVG Assets

* All SVG icon assets must always use CRLF (`\r\n`) line endings. Never commit or use LF line endings.
* Follow the project's established icon style: Lucide 24x24 viewBox (`viewBox="0 0 24 24"`), stroke `#a5b4c4`, stroke-width `2`, stroke-linecap `round`, stroke-linejoin `round`, and `fill="none"` (except deliberate small accent dots).
* Never leave unused SVG files in `resources/icons/`. Whenever an icon is replaced, superseded, or no longer referenced in code or stylesheets, delete its SVG file outright. When introducing, renaming, or removing icons or UI elements, audit `resources/icons/` to ensure every SVG asset is actively used.

## Errors

For GUI-specific error states, use the project's existing exception and message-box patterns.

Screen resolution must be obtained through the project's `get_screen_size()` helper. If `UnsupportedScreenResolutionError` is raised, display its `msgbox_text` using the existing application pattern.

## Changes

Keep UI changes focused.

Do not reformat unrelated sections, rename unrelated widgets, reorganize unrelated files, or perform broad UI cleanup unless explicitly requested.
