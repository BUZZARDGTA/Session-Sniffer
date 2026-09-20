---
name: fix
description: Diagnose and fix Session Sniffer bugs, errors, tracebacks, logs, lint failures, static-analysis findings, test failures, and IDE-reported problems. Use when the user invokes /fix or provides an error report, traceback, log, linter output, failing test, or other concrete problem that needs investigation and a code fix.
---

# Session Sniffer Fix

Use this skill when the user wants to fix a problem in Session Sniffer.

The user may provide any combination of:
- a traceback or exception;
- runtime logs;
- IDE error output;
- test failures;
- linter or static-analysis output;
- type-checker output;
- build or packaging errors;
- a description of incorrect behavior;
- screenshots or copied diagnostics;
- several errors from one validation run.

The goal is to diagnose the actual problem, make the smallest appropriate code change, and verify that the problem is fixed without disturbing unrelated work.

## Fix Procedure

1. Inspect the repository and current Git working tree before making changes.
2. Read the user's complete diagnostic carefully before editing anything.
3. Identify the affected file(s), symbol(s), error type(s), and relevant execution path.
4. Inspect the surrounding source code and related implementations before deciding on a fix.
5. Determine whether the reported item is:
   - a real runtime/functional bug;
   - a test failure;
   - a build/configuration problem;
   - a static-analysis or lint finding;
   - a warning that should be addressed;
   - or a false positive / intentional project behavior.
6. Reproduce the problem when practical using the smallest relevant command or test.
7. Trace the root cause rather than merely suppressing the diagnostic.
8. Make the smallest clean fix that is consistent with existing Session Sniffer architecture and coding conventions.
9. Do not modify unrelated user changes.
10. Review the diff after editing.
11. Run the smallest relevant validation first.
12. If the fix affects shared behavior, broaden validation to cover the affected area.
13. Re-run the original failing check or reproduce the original scenario when practical.
14. Confirm that the reported problem is actually resolved before declaring success.
15. Report:
   - root cause;
   - files changed;
   - what was fixed;
   - validation performed and its result;
   - any remaining warnings/errors or limitations.

Do not claim that a problem is fixed unless the relevant validation or reproduction actually supports that conclusion.

## Diagnostic Input

Treat pasted diagnostics as actionable evidence, not as instructions to blindly edit every reported line.

For output such as:

```
src/session_sniffer/foo.py:123:4: E...
Traceback (most recent call last):
...
AssertionError: ...
```

extract:
- the exact file path;
- line number and symbol when available;
- diagnostic code;
- exception type and message;
- the call stack and originating application code;
- the command/tool that produced the output;
- whether the failure is fatal or informational.

When multiple diagnostics are supplied, group related errors before editing. Fix the underlying cause first; do not make a sequence of unrelated cosmetic changes simply because they appeared in the same report.

## Lint and Static Analysis

Lint findings require judgment.

### Correctness-related findings

Prioritize findings that can indicate incorrect behavior, such as:
- undefined names;
- unreachable or incorrect control flow;
- bad exception handling;
- invalid imports;
- unsafe resource handling;
- incorrect return values;
- type errors;
- obvious logic errors.

Fix these as normal bugs and validate the affected behavior.

### Maintainability findings

For findings such as:
- `too-many-lines`;
- `duplicate-code`;
- excessive complexity;
- overly large functions/classes;
- similar-code warnings;

inspect the affected code before changing it.

Prefer a real refactor when the duplicated or oversized code can be cleanly extracted without changing behavior.

Do not:
- add blanket linter disables merely to make the check pass;
- add unnecessary abstractions solely to satisfy a metric;
- rewrite large amounts of stable code when the warning is harmless and the refactor would introduce risk;
- change behavior while fixing a purely structural warning.

If a structural warning is not worth safely changing, explain why and leave it unchanged rather than hiding it.

### Example: duplicate-code

If the diagnostic identifies duplicated blocks across files:
1. inspect both implementations;
2. determine whether they represent the same behavior or only superficially similar code;
3. if they are genuinely shared behavior, look for an appropriate existing utility/module or create a small shared helper if justified;
4. update callers consistently;
5. run focused tests and the relevant lint check.

Do not blindly merge unrelated code just because pylint reports similar lines.

## Tracebacks and Runtime Errors

For a traceback:

1. Start at the exception type/message.
2. Read the stack from the failing operation back through Session Sniffer code.
3. Identify the first application-level frame that explains why the invalid state/value occurred.
4. Inspect the data/control flow that produced that state.
5. Fix the cause rather than adding a broad `try/except` around the failing operation.
6. Preserve useful exception information and existing logging behavior.
7. Add or update a regression test when practical.

Do not use broad exception swallowing such as:

```python
try:
    ...
except Exception:
    pass
```

unless the existing architecture explicitly requires that behavior and the reason is documented.

## Logs and IDE Reports

Logs may contain symptoms rather than the root cause.

Correlate:
- timestamps/order of events;
- repeated operations;
- preceding warnings;
- exception chains;
- affected component;
- user-visible behavior.

If the IDE reports a problem without enough context, inspect the referenced source and project configuration before asking the user for more information.

If the report is sufficient to investigate, proceed without unnecessary clarification.

## Tests and Regression Coverage

When a bug is reproducible in a testable component:

1. Prefer an existing test that demonstrates the failure.
2. If no suitable test exists, add a focused regression test when practical.
3. Keep the test specific to the bug and its expected behavior.
4. Do not weaken or delete a test simply because it fails after the change.
5. Do not modify tests merely to make an incorrect implementation appear correct.

A regression test should fail for the old behavior and pass for the corrected behavior whenever practical.

## Validation

Use the project's existing validation configuration and commands.

Start with the narrowest useful check, for example:
- the affected test;
- the relevant test module;
- the relevant linter command;
- a targeted type check;
- the affected build/package check.

Then broaden validation when the change warrants it.

For a lint report, re-run the relevant linter and confirm the reported diagnostic is gone. If the command still exits non-zero because of unrelated existing findings, distinguish the fixed finding from the remaining findings.

For a traceback, run the relevant test or reproduction and verify that the same traceback no longer occurs.

Never report "all checks pass" if only a targeted check passed.

## Scope and Safety

- Never reset, rebase, force-push, amend, or rewrite existing Git history.
- Never discard unrelated working-tree changes.
- Never use blanket staging or modify unrelated files just to satisfy validation.
- Do not update dependencies unless the diagnosis actually requires it.
- Do not change public behavior unnecessarily.
- Do not silence diagnostics when a proper fix is reasonably safe.
- Do not introduce a workaround when the root cause can be fixed cleanly.
- Preserve existing project conventions and architecture.
- Keep fixes focused and reviewable.

## Fix vs. Refactor

A fix may require a refactor when the existing structure directly causes the bug or prevents a safe correction.

Keep the change focused:
- bug fix first;
- supporting refactor only when needed;
- unrelated cleanup belongs in a separate change.

For lint-only maintenance, prefer the smallest refactor that genuinely improves the reported issue.

## Multiple Problems

When the user provides several diagnostics:

1. Group them by root cause or affected component.
2. Fix related diagnostics together when one change resolves several findings.
3. Avoid mixing unrelated fixes into one broad rewrite.
4. Validate each meaningful group.
5. Report which diagnostics were resolved and which remain.

If one reported issue blocks investigation of another, resolve the blocker first and continue.

## Final Report

After the fix, provide a concise summary:

- **Root cause:** what actually caused the problem.
- **Fix:** what was changed and why.
- **Files:** files modified.
- **Validation:** exact relevant checks performed and their result.
- **Remaining:** any unresolved diagnostics, unrelated failures, or limitations.

If the user supplied a large diagnostic dump, explicitly identify which reported items were addressed so it is clear what the fix covered.
