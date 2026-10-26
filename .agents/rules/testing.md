---
trigger: model_decision
description: Use when adding, modifying, debugging, reviewing, or validating code, including static analysis, linting, type checking, quality checks, builds, or release-sensitive validation.
---

# Quality and Validation Rules

Apply these rules when adding, modifying, debugging, reviewing, or validating code.

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

For code changes, run targeted checks first when a specific tool provides the clearest signal. For significant code changes, run the full project quality script with `python code_quality_checks.py` after targeted checks pass, rather than invoking every tool manually.

For release-only changes that only update `pyproject.toml` and `uv.lock`, use release-specific validation instead of the full quality script: `uv lock --check` and CRLF line-ending verification for the modified release files.

## Existing Tooling

Follow the project's existing tooling and configuration in `pyproject.toml`.

The project uses strict static-analysis and linting configurations. The individual validation commands in `.venv` are:
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

When fixing a bug, verify the actual failure path before changing code. Do not weaken assertions, type checking, or linting simply to make a change pass.

## Verification Claims

If a check could not be run, state that clearly rather than implying it passed.

## Dependency Changes

If dependencies or `pyproject.toml` are changed, follow the project's dependency workflow and run the appropriate dependency installation and validation steps.

## Release-Sensitive Changes

If resources or PyInstaller configuration are changed, follow the Release Validation rules in `release.md`.

## Quality

Do not reformat unrelated code or modify unrelated configuration simply because a quality tool reports existing issues outside the scope of the change.
