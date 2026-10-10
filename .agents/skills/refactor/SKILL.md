---
name: refactor
description: Refactor Session Sniffer code to improve structure, readability, duplication, and maintainability while preserving existing behavior. Use when the user invokes /refactor or explicitly requests code restructuring without a behavior change.
---

# Session Sniffer Refactor

Use this skill when the user wants to refactor Session Sniffer.

The goal is to improve code structure and maintainability without changing externally observable behavior. Prefer small, justified changes that fit the existing architecture over broad rewrites.

## Refactor Procedure

1. Inspect the Git working tree and current diff before making changes. Preserve all unrelated user changes.
2. Identify the user's target and desired outcome. If no target is specified, inspect the reported area or identify a small, high-value refactor supported by concrete evidence; do not refactor the entire repository opportunistically.
3. Read the relevant implementation, callers, validation configuration, and applicable `.agents/rules/*.md` guidance before editing.
4. Trace data flow, state ownership, lifecycle, error handling, and side effects for the code being changed.
5. Identify a specific structural problem, such as:
   - duplicated logic with identical semantics;
   - a function or class combining separable responsibilities;
   - complex control flow that can be made clearer;
   - unclear naming or unnecessary indirection in the targeted code;
   - repeated conversion or setup logic that belongs in an existing abstraction.
6. Explain the intended structural change briefly when it is substantial; then make the smallest coherent refactor.
7. Prefer existing project abstractions and conventions. Do not introduce a new manager, service layer, registry, wrapper, base class, or helper module unless the code demonstrates a real need.
8. Update all affected call sites together following the No Backward Compatibility rules in `.agents/rules/core.md` (do not leave compatibility aliases, shims, or duplicate implementations).
9. Review the complete diff for accidental behavior changes, unrelated edits, and formatting churn.
10. Run the smallest relevant configured validation, then broaden it when the risk warrants it.
11. Report the structural problem, the refactor, files changed, checks actually run, and any remaining risk.

## Behavior-Preservation Requirements

Unless the user explicitly asks for a behavior change, preserve:

- public and internal behavior, return values, side effects, and error semantics;
- execution order where order can affect results;
- initialization and shutdown behavior;
- ownership and lifetime of state;
- signal/slot wiring and Qt thread boundaries;
- configuration loading, settings persistence, and data formats;
- logging meaning and severity;
- network and packet-processing behavior;
- resource cleanup and exception propagation.

Do not treat a refactor as permission to redesign APIs, change defaults, remove features, or modernize unrelated code. Do not combine performance optimization, bug fixes, dependency upgrades, or cosmetic cleanup with a structural refactor unless it is essential to the requested change; separate independent work.

## Architecture and Performance

- Follow the existing architecture documented in `.agents/rules/architecture.md` and applicable subsystem rules.
- Trace callers and consumers before moving code or changing ownership.
- Preserve threading, queue, synchronization, and worker-lifecycle patterns.
- Do not add allocations, repeated parsing, extra work in hot paths, or new blocking operations without a demonstrated reason.
- Do not change polling intervals, timers, retry behavior, or event frequency as part of a behavior-preserving refactor.
- Avoid abstractions that merely wrap a single simple operation or obscure a straightforward flow.
- Follow the file sizing rules in `.agents/rules/python.md` ("File Sizing and Structural Warnings"): leave cohesive data tables, schemas, and defaults registries intact; do not split files solely to satisfy line-count metrics.

## Code Quality

- Follow the project's authoritative `pyproject.toml` and `.agents/rules/` instructions.
- Reuse existing types, utilities, and error-handling patterns.
- Keep names precise and intent-revealing.
- Do not silence lint or type diagnostics just to make the refactor pass.
- Do not add dependencies unless the task explicitly requires them and existing functionality cannot reasonably be reused.
- Do not perform repository-wide formatting or unrelated renames.

## Validation

Follow the validation workflow and configured tooling in `.agents/rules/testing.md`.

- Start narrowly with targeted linter and type-checker runs against the touched paths.
- Broaden validation to the full suite (`python code_quality_checks.py`) when the risk warrants it.
- Never claim a check passed unless it actually ran successfully.
- Ensure all modified files retain CRLF (`\r\n`) line endings per `.agents/rules/core.md`.

## Scope and Safety

Follow the Git and Change Discipline rules in `.agents/rules/core.md`.

- Do not create commits or push changes unless explicitly requested.
- Do not modify files merely to make validation pass.
- Keep the diff focused and reviewable.

## Final Report

Summarize:

- **Structural issue:** what made the original code harder to maintain.
- **Refactor:** what moved, was extracted, simplified, or deduplicated.
- **Behavior:** why the observable behavior should remain unchanged, including any assumptions.
- **Files:** files changed.
- **Validation:** exact checks run and their results.
- **Remaining risks:** anything that could not be verified.
