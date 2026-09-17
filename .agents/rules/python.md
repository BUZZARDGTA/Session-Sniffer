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

* Use the project's logging system for diagnostics.
* Prefer the existing logger methods such as `debug`, `info`, `warning`, `error`, and `exception` over `print`.
* Use terminal output only for intentional console reporting.
* Follow the existing logging setup rather than creating a separate logging system.

## Dependencies

Before adding a dependency:

* Check whether the functionality already exists in the project or standard library.
* Inspect `pyproject.toml`.
* Keep new dependencies to a minimum.
* Pin new dependencies exactly to match the project's existing dependency style, except security libraries which may use `>=` when appropriate.

## General Python Changes

Prefer clear, explicit, maintainable Python over clever abstractions or metaprogramming.

Fix the underlying problem rather than suppressing a diagnostic or weakening type checking to make the code pass.
