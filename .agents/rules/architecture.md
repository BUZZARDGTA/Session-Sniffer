---
trigger: model_decision
description: Use when changing subsystem boundaries, application data flow, threading architecture, shared state, major refactoring, moving functionality, new abstractions, or significant component integration.
---

# Architecture Rules

Apply these rules when a task involves subsystem boundaries, data flow, threading architecture, shared state, major refactoring, moving functionality, new abstractions, or significant integration between components.

## Existing Architecture

Before making an architectural change, follow the Investigation steps in `core.md` and additionally identify the ownership of state and lifecycle.

Do not design a new architecture based only on the task description when the repository already contains the relevant implementation.

## Responsibilities

Preserve clear separation between existing subsystems.

The established application flow is:

packet capture → packet callback → player/session registries → rendering core → GUI worker signals → Qt models/views

Keep responsibilities within the subsystem that already owns them.

Do not move business logic into UI code merely because the UI consumes its results.

Do not move capture or network processing into GUI components.

Do not make background components directly manipulate Qt widgets.

The low-level native binding vs high-level module boundary is defined in `core.md` ("Low-Level vs High-Level Separation").

## Abstractions

Prefer existing abstractions over introducing new ones.

Do not create a new:

* manager,
* service layer,
* registry,
* controller,
* wrapper,
* abstraction,
* event system,
* configuration mechanism

unless the existing architecture demonstrably cannot support the required behavior.

Avoid abstractions whose only purpose is to hide a small operation or reduce a few repeated lines.

## State and Lifecycle

Identify the owner of shared state before changing it.

Preserve existing:

* initialization order,
* shutdown behavior,
* worker lifetimes,
* thread ownership,
* event handling,
* configuration flow,
* persistence behavior.

Do not duplicate state that is already owned by an existing registry, configuration object, model, or worker.

## Configuration

Follow the settings architecture defined in `data-storage.md`. Do not introduce a parallel configuration or persistence mechanism.

## Refactoring

Architectural refactoring must remain focused on the requested problem.

Do not combine an architectural change with unrelated:

* formatting,
* renaming,
* cleanup,
* file movement,
* API redesign,
* dependency changes,
* or modernization.

## Validation

After architectural changes, verify the affected data flow and integration points rather than checking only whether the modified file passes static analysis.

Use the project's existing quality and launch/validation workflow where appropriate.
