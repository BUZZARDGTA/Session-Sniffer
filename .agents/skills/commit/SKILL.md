---
name: commit
description: Organize and commit current Git changes by committing a requested feature alone or splitting all unrelated changes into separate logical commits.
---

# Session Sniffer Commit

Use this skill when the user wants to commit current Git changes.

## Commit Modes

Determine the user's intent from the request.

### Specific Change

If the user identifies a feature, fix, refactor, documentation change, or other specific change:

1. Inspect the Git working tree and full diff.
2. Identify the files and individual diff hunks belonging to the requested change.
3. Do not stage unrelated files or hunks.
4. If the requested change cannot be separated safely from unrelated changes, explain the overlap and ask how the user wants to proceed.
5. Propose one commit message describing only that change.
6. Stage only the intended changes and create exactly one commit.

### All Changes

If the user asks to commit everything, do not automatically create one large commit.

1. Inspect the Git working tree and full diff.
2. Group changes into logical, independently meaningful changes.
3. Separate unrelated features, fixes, refactors, tests, documentation, configuration, and other changes into different commits where practical.
4. Use file-level and hunk-level staging when necessary.
5. Do not force a separation when changes are tightly coupled and belong in the same commit.
6. Propose one commit message for each logical change.
7. Show the proposed groups, affected files, and commit messages.
8. Create the proposed commits in logical order.

## Commit Messages

Use concise Conventional Commit-style messages when appropriate:

* `feat:` for new functionality
* `fix:` for bug fixes
* `refactor:` for code restructuring without behavior change
* `perf:` for performance improvements
* `test:` for test-only changes
* `docs:` for documentation
* `build:` for build/dependency/package changes
* `chore:` for maintenance

Write the message from the actual diff. Do not invent functionality or motivation that is not supported by the changes.

## Safety

* Never modify files merely to make commits possible.
* Never include unrelated user changes.
* Preserve unstaged and uncommitted changes that are outside the selected commit.
* Use partial/hunk staging when files contain changes belonging to multiple commits.
* Inspect the staged diff before every commit.
* Do not use `git add .` or equivalent blanket staging when only part of the working tree belongs in a commit.
* Do not amend existing commits.
* Do not reset, rebase, force-push, or rewrite existing history.
* Do not push commits unless the user explicitly asks for a push as a separate action.

## Validation

Before committing:

1. Review the staged diff.
2. Run the smallest relevant validation available for the selected changes when practical.
3. Do not claim validation was performed unless it actually ran successfully.
4. If validation fails, stop before committing and report the failure.

For multiple commits, validate each staged change as appropriate before creating its commit.

## Final Report

After committing, report:

* commit hash
* commit message
* files included
* validation performed
* any remaining unstaged or uncommitted changes

The goal is to produce clean, focused commits while leaving unrelated work untouched.
