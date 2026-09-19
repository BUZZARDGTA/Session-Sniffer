---
trigger: glob
globs: **/*.py
---

# Python Development Rules

## Version and Tooling

* The project requires Python 3.14.
* `pyproject.toml` is authoritative for Python version, dependencies, formatting, linting, type checking, and static-analysis configuration.
* Follow the existing project tooling. Do not introduce competing formatters, linters, or type checkers.
* Preserve the existing suppression and configuration lists unless the task explicitly requires changing them.
* The project targets a line length of 176 characters.

## Project Imports

* The repository uses a `src` layout.
* Import project modules as `from session_sniffer...`.
* Never import project modules as `from src.session_sniffer...`.

## Style

* Use single quotes for strings throughout the project. Use double quotes only when the string itself contains a single quote.
* Never use `from __future__ import annotations`.
* Never use quoted forward references in type hints.
* Use precise type hints and prefer existing project types, protocols, models, and type aliases.
* Use descriptive variable names. Do not use abbreviations such as `res`, `net`, `ips`, `conn`, `msg`, or `err`.
* Single-letter variables are reserved for `i` and `j` as loop indices, and `e` for exception handling.
* Access attributes and functions directly; only use local aliases when necessary to preserve a value across changing state.

## Documentation Style

* In comments and docstrings, use single backticks for inline code.
* Never use RST double backticks for inline code.

## Exceptions and Error Handling

* Do not add defensive `try/except` blocks merely to prevent crashes.
* Only catch exceptions that are documented or known to be raised by the operation being performed.
* Never broadly catch unexpected internal failures with `except Exception`.
* Prefer a clear traceback over silently swallowing unexpected errors.
* Never use `assert` for runtime validation. Raise an appropriate exception such as `ValueError` or `RuntimeError`.

## Performance and Concurrency

* Do not perform blocking or high-latency operations in packet callbacks.
* Offload expensive or blocking work using the project's existing threading architecture.
* Preserve existing concurrency, worker, queue, and synchronization patterns.
* Do not introduce unnecessary allocations, repeated parsing, or expensive work into hot paths without a demonstrated need.

## Thread Exceptions

* Preserve the project's `threading.excepthook` handling in `src/session_sniffer/core/control.py` for uncaught thread exceptions.
* Do not replace or bypass the existing thread exception handling mechanism without an explicit reason.

## Logging

* Use `import logging` and `logger = logging.getLogger(__name__)` in every module that needs a logger. Do not import or call any project-specific logger shim.
* `setup_logging()` is called once at application startup in `main.py`. Do not call it from library modules or module-level code outside `main.py`.
* Prefer the existing logger methods — `debug`, `info`, `warning`, `error`, `exception` — over `print`.
* Use terminal output only for intentional console reporting.
* Choose log severity deliberately:
  * `debug` — expected, low-value operational noise (e.g. DNS timeouts, cache misses).
  * `warning` — something went wrong and could explain a user-visible problem, but the full traceback adds no value (`logger.warning('…: %s', e)`).
  * `exception` — an unexpected failure on a critical path where the full traceback is diagnostic (`logger.exception('…')`). Use this inside `except` blocks where you want the traceback captured.
* Do not silently swallow exceptions; prefer a clear traceback over `except ...: pass`.

## Dependencies

Before adding a dependency:

* Check whether the functionality already exists in the project or standard library.
* Inspect `pyproject.toml`.
* Keep new dependencies to a minimum.
* Pin new dependencies exactly to match the project's existing dependency style, except security libraries which may use `>=` when appropriate.

## General Python Changes

Prefer clear, explicit, maintainable Python over clever abstractions or metaprogramming.

Fix the underlying problem rather than suppressing a diagnostic or weakening type checking to make the code pass.
