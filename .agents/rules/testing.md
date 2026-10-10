---
trigger: model_decision
description: Use when adding, modifying, debugging, reviewing, or validating code, including static analysis, linting, type checking, quality checks, builds, or release-sensitive validation.
---

# Quality and Validation Rules

Apply these rules when adding, modifying, debugging, reviewing, or validating code.

## No Test Suite

* This project has no automated test suite (no `pytest`, `unittest`, or test runner).
* **Never run `pytest`**, `python -m pytest`, or attempt to execute tests. Pytest is not installed and does not exist in this project.
* Validation is performed exclusively through static analysis, linting, type checking, syntax checks, or running the application.

## Validation Strategy

Use the smallest relevant validation first.

Depending on the change, this may include:

* static analysis,
* linting,
* type checking,
* application startup,
* relevant integration checks,
* broader project quality checks.

Do not run unrelated expensive validation when it provides no useful signal.

For code changes, run targeted checks first when a specific tool provides the clearest signal. For significant code changes, run the full project quality script with `python code_quality_checks.py` after targeted checks pass.

For release-only changes that only update `pyproject.toml` and `uv.lock`, use release-specific validation instead of the full quality script: `uv lock --check` and CRLF line-ending verification for the modified release files.

For non-trivial changes, broaden validation when appropriate. When broadening to the full project quality suite, use `python code_quality_checks.py` rather than invoking every tool manually.

## Existing Tooling

Follow the project's existing tooling and configuration in `pyproject.toml`.

The project uses strict static-analysis and linting configurations including Ruff, MyPy, Pyrefly, Pyright, ty, Flake8, Pylint, and Vulture within the local `.venv`.

The individual validation commands in `.venv` are:
* Ruff: `ruff check .`
* Flake8: `flake8 . --config .flake8`
* Pylint: `pylint . --rcfile pyproject.toml`
* MyPy: `mypy . --config-file pyproject.toml`
* Pyright: `pyright --warnings`
* Pyrefly: `pyrefly check .`
* ty: `ty check .`
* Vulture: `vulture .`
* Full suite: `python code_quality_checks.py`

Do not introduce competing validation tools.

Preserve existing intentional suppression lists and disabled diagnostics unless the task explicitly requires changing them.

## Existing Behavior

When fixing a bug, verify the actual failure path before changing code.

Do not weaken assertions, type checking, or linting simply to make a change pass.

Fix the underlying problem whenever practical.

## Verification Claims

Only report checks that were actually performed.

If a check could not be run, state that clearly rather than implying it passed.

Do not claim that the application was launched, checks passed, or a build succeeded unless the corresponding operation was actually performed.

## Dependency Changes

If dependencies or `pyproject.toml` are changed, follow the project's dependency workflow and run the appropriate dependency installation and validation steps.

## Release-Sensitive Changes

If resources or PyInstaller configuration are changed, validate the relevant specification and resource inclusion.

The release build uses the project's one-file PyInstaller configuration, so runtime resources must remain correctly represented in the spec.

## Quality

Keep diffs focused.

Do not reformat unrelated code or modify unrelated configuration simply because a quality tool reports existing issues outside the scope of the change.

Always verify that all modified or newly generated files (including `uv.lock` and configuration files) have CRLF (`\r\n`) line endings.
