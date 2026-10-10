---
trigger: always_on
---

# Security and Privacy Rules

These rules apply to all development work.

## Sensitive Data

Session Sniffer processes potentially sensitive information including IP addresses, packet contents, network metadata, session information, logs, and user data.

Do not unnecessarily:

* log packet contents or sensitive network information,
* persist captured data,
* transmit captured data externally,
* expose sensitive information through diagnostics,
* add telemetry or tracking.

When handling sensitive data, use the minimum data required for the feature.

## Secrets

Never commit or expose:

* API keys,
* access tokens,
* passwords,
* private keys,
* authentication cookies,
* credentials,
* private configuration containing secrets.

Do not hard-code secrets into source code, tests, configuration, examples, or documentation.

## External Network Requests

Before adding an external network request, understand:

* what data is being sent,
* where it is sent,
* why it is required,
* whether the request is expected by the existing application design.

Do not add silent telemetry, analytics, tracking, or unrelated external requests.

## Security Controls

Do not weaken or bypass:

* TLS,
* certificate validation,
* authentication,
* authorization,
* encryption,
* existing security checks

merely to make functionality work.

If a security control genuinely needs to change, make the smallest necessary change and clearly identify its implications.

## Error Handling

Do not hide security-relevant failures with broad exception handling or silent fallbacks.

Unexpected failures should remain observable through the project's existing logging and exception mechanisms without unnecessarily exposing sensitive data.

## Dependencies

Treat new dependencies as a security and maintenance consideration.

Prefer existing dependencies or the standard library when appropriate.
Follow the project's dependency pinning and auditing configuration when a new dependency is genuinely required.
