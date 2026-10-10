---
trigger: model_decision
description: Use when working on packet capture, packet parsing, networking, session detection, connection tracking, DNS, pinging, MAC vendor lookups, capture filters, or related network functionality.
---

# Networking and Packet Capture Rules

Apply these rules when working on packet capture, packet parsing, networking, session detection, connection tracking, IP processing, DNS, pinging, MAC vendor lookup, capture filters, or related network functionality.

## Packet Capture Architecture

Understand the existing packet-processing pipeline before changing it.

The established flow is:

packet capture → packet callback → player/session registries → rendering core → GUI worker signals → Qt models/views

Preserve the existing separation between:

* raw capture data,
* parsed network information,
* player/session state,
* rendering data,
* GUI presentation.

Do not couple packet capture directly to GUI widgets.

`PacketCapture` is configured through the project's existing immutable `CaptureConfig` pattern. Preserve this configuration/state separation rather than introducing parallel configuration mechanisms.

## Packet Callback

The packet callback is a performance-sensitive path.

Do not add:

* blocking operations,
* high-latency network requests,
* unnecessary synchronous DNS or IP lookups,
* expensive processing,
* unnecessary allocations,
* repeated parsing of data that can already be reused.

Follow the existing background-thread architecture for expensive user IP processing and other work that should not execute inside the packet callback.

## Concurrency

Preserve the project's existing worker, queue, thread, event, and synchronization patterns.

Do not move work between threads without understanding:

* who owns the state,
* which thread currently accesses it,
* how results are communicated,
* what synchronization already exists,
* and how thread lifetime is managed.

Do not introduce unnecessary concurrency abstractions.

## Packet and Protocol Handling

Do not assume that network behavior or protocol structure is universal.

Before modifying parsing or detection logic:

* inspect existing packet formats and parsing code,
* search for related protocol handling,
* understand which fields are actually available,
* preserve handling for existing supported cases.

When adding filters, follow the existing filter construction and ordering patterns. Preserve symmetry with the corresponding display-filter behavior when an exclusion is involved.

## Session and Player State

Preserve the established registry lifecycle.

Connected/disconnected movement must continue to use the project's existing registry methods and `Player.left_event` behavior.

Rejoins should use `mark_as_rejoined`.

Periodic packets should use `mark_as_seen`.

Do not create parallel session-tracking state when the existing registries already own that responsibility.

## Networking Operations

Follow existing abstractions for DNS, reverse DNS, MAC vendor lookups, pinging, and external IP processing.

Before introducing a new network operation, determine whether an existing project abstraction already provides the required behavior.

Avoid adding network requests to latency-sensitive paths.

Third-party integrations that transmit network metadata or IP addresses externally (such as Looky System)
must strictly follow their domain-specific rules and gating logic (see `.agents/rules/looky.md`).

## Data Sensitivity

Captured packet information, IP addresses, and session information can be sensitive.

Do not add unnecessary:

* persistence of captured data,
* logging of packet contents,
* external transmission,
* telemetry,
* diagnostic output containing network data.

Any new external network request must have an explicit purpose and must make clear what data is sent and where it is sent.

## Changes

Keep networking changes narrowly scoped.

Do not rewrite capture, parsing, or session architecture unless the task actually requires it.

Measure or identify a real bottleneck before making performance-driven changes to hot network paths.
