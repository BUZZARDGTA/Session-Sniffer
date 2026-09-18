---
trigger: always_on
---

# Session Sniffer Core Rules

## Project Context

Session Sniffer is a mature cross-platform (Windows and Linux) PySide6 desktop application for monitoring and analyzing P2P network sessions from games and other software.

Treat the existing codebase and architecture as intentional. Before making changes, inspect the relevant implementation, callers, data flow, and existing patterns.

## Change Discipline

- Make the smallest focused change that solves the requested problem.
- Preserve existing behavior unless the requested change explicitly requires
  changing it.
- Reuse existing abstractions and patterns before creating new ones.
- Do not perform unrelated refactors, cleanup, renames, or reorganizations.
- Do not silently remove existing functionality.
- Do not add unnecessary dependencies.
- Do not modify user changes that are unrelated to the task.

## No Backward Compatibility

This project never maintains backward compatibility.

When replacing, renaming, or removing something:
- Delete the old implementation outright.
- Update every call site.
- Do not add aliases, migration code, compatibility shims, fallback lookups, transitional validators, or dual code paths.
- Delete unused assets (such as SVG icons, images, or resource files) outright. Never leave orphaned or unreferenced assets in the repository.

## Line Endings

- Always use CRLF (`\r\n`) line endings for all files in the repository, including SVG assets, Python source files, configuration, and documentation. Never use or commit LF line endings.

## Investigation

For non-trivial changes:
1. Locate the relevant implementation.
2. Trace its callers and data flow.
3. Identify related models, configuration, workers, signals, and UI.
4. Search for existing implementations of similar behavior.
5. Make the smallest appropriate change.

Do not assume how the application works when the repository can answer the question.

## Verification

Use the project's existing tooling and validation workflow when appropriate.

Do not claim that tests, quality checks, builds, or application launches were performed unless they were actually performed.

## Git

Do not create commits, amend commits, reset, rebase, force-push, or otherwise rewrite Git history unless explicitly requested.

Do not discard or revert user changes unless explicitly requested.

## Communication

If ambiguity materially changes the implementation, ask for clarification. Otherwise proceed using the existing project conventions.

After completing work, briefly state:
- what changed,
- important implementation decisions,
- what was verified,
- and any remaining concerns.
