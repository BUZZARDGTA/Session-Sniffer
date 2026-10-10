---
trigger: model_decision
description: Use when working on Looky System integration, IP lookups, crawler requests, token verification, Looky settings, gating logic, or player Looky actions.
---

# Looky System Rules and Guidelines

These rules govern all Looky System development, integration, security controls, and UI gating in Session Sniffer.

## Overview & Architecture

Looky System is a third-party service (`looky-gta.cc`) used to resolve IP addresses to Rockstar IDs and usernames for GTA V players:
* **Background Worker**: `looky_core()` in `session_sniffer.background.cores` polls connected eligible players and performs batch lookups (`lookup_ip_batch`).
* **Authentication Worker**: `looky_verify_token_core()` in `session_sniffer.background.cores`
  validates the configured API key on startup and setting changes, updating `LookyState`.
* **Manual Lookups & Dialogs**: `session_sniffer.guis.tables_player_actions.looky_system` provides
  manual lookup (`show_looky_lookup`), crawler requests (`show_crawler_request`, `show_crawlme_request`),
  and UserIP database lookups (`looky_refresh_userip_entries`).
* **UI Text & Gating Helpers**: Centralized in `session_sniffer.guis.looky_text` (`configure_looky_action`, message constants, tooltips).

## Strict Privacy and GTA V PID Gating (Non-Negotiable)

Session Sniffer sends captured IP addresses externally over the internet to the Looky System API.

### Anti-Leak Security Constraint
* In local capture mode (`CaptureState.is_local_capture()`), when `Settings.looky_exclusive_gta5_process` is True (default):
  * **No IP address must ever be transmitted to the Looky System API unless capture is actively filtering
    on the running GTA V process PID (`CaptureState.is_scanning_gta5_process()`).**
  * **Never relax or soften this restriction** to make Looky lookups work in the default "Sniff All Traffic" mode. Sniffing all traffic captures personal,
    non-game network connections (web browsers, Discord, Spotify, background software). Transmitting these arbitrary IPs to third-party Looky servers is a severe privacy leak.
  * **Never bypass the check** simply because players are present in `PlayersRegistry`, or because a player was previously seen or cached.
    If `not CaptureState.is_scanning_gta5_process()`, queries for local capture must halt immediately.

### Eligibility Gating (`is_looky_eligible`)
`is_looky_eligible(player)` in `session_sniffer.background.cores` must always check:
```python
def is_looky_eligible(player: Player) -> bool:
    if not Settings.looky_enabled or not Settings.is_gta5_feature_set():
        return False
    if player.is_third_party_server:
        return False
    if not CaptureState.is_local_capture():
        return False
    return not (
        Settings.looky_exclusive_gta5_process
        and not CaptureState.is_scanning_gta5_process()
    )
```

### Consoles & Non-Local Captures (Strictly Prohibited)
Looky System is strictly a PC-only feature. Consoles and external captures (ARP spoofing, bridged adapters, neighbour adapters, etc., where `CaptureState.is_local_capture()` is `False`) must never be permitted to access or support Looky System under any circumstances:
* Automated Looky background resolutions must immediately disqualify players when `not CaptureState.is_local_capture()`.
* Context menus must omit the Looky System submenu on non-local captures.
* All Looky manual entry points and action handlers (`configure_looky_action`, `check_looky_prerequisites`, `show_looky_lookup`, `show_crawler_request`, `show_crawlme_request`, `_rescan_all_looky_players`) must reject non-local captures with `LOOKY_MENU_TOOLTIP_RESTRICTED_NOT_LOCAL` or `LOOKY_WARNING_RESTRICTED_NOT_LOCAL`.

### Third-Party Server & Relay Restriction
Third-party server and relay players (`player.is_third_party_server` = True, such as Take-Two Interactive or Microsoft relay servers) must never be sent to Looky System.
Context menus and automated lookups must omit or suppress Looky System for them.

## Manual UI Actions and Pre-Flight Validation

All manual entry points that can query Looky System must strictly enforce the same gating logic:

1. **Context Menu Actions**:
   * The Looky System submenu in `session_sniffer.guis.tables_context_menu_mixin` must return early and omit itself entirely when `not CaptureState.is_local_capture()`.
   * "Lookup", "Lookup (All Selected)", and "Request Crawler" must use:
     `configure_looky_action(action, default_tooltip=action.toolTip(), check_gta5_restriction=True)`
   * When `check_gta5_restriction` triggers, the action is disabled with tooltip `LOOKY_MENU_TOOLTIP_RESTRICTED_NOT_LOCAL` (if non-local) or `LOOKY_MENU_TOOLTIP_RESTRICTED_GTA5_NOT_RUNNING` (if local without GTA V PID).

2. **Standalone Dialog Buttons**:
   * The "Looky Lookup…" button in `session_sniffer.guis.tables_player_actions._ip_lookup_dialog` must also be gated using:
     `configure_looky_action(lookup_button, default_tooltip=..., check_gta5_restriction=True)`.

3. **Background Lookup in Standalone Dialogs**:
   * Background threads in standalone dialogs (e.g. `_resolve_standalone_lookup` in `_ip_lookup_dialog.py`) must verify the PID restriction before dispatching `lookup_ip`:
     `not is_looky_gta5_restricted()`

4. **Pre-Flight Function `check_looky_prerequisites`**:
   * `check_looky_prerequisites(parent: QWidget, *, check_gta5_restriction: bool = False)` in `session_sniffer.guis.tables_player_actions.looky_system._looky_helpers`:
     * Checks API key presence, `Settings.looky_enabled`, `LookyState.api_access`.
     * Rejects non-local capture (`not CaptureState.is_local_capture()`) with `LOOKY_WARNING_RESTRICTED_NOT_LOCAL`.
     * When `check_gta5_restriction=True`, verifies `is_looky_gta5_restricted()` and shows `LOOKY_WARNING_RESTRICTED_GTA5_NOT_RUNNING` warning message box if unsatisfied.
   * `show_looky_lookup()`, `show_crawler_request()`, and `show_crawlme_request()` must always pass `check_gta5_restriction=True`.

5. **"Rescan All Players" Action**:
   * `_rescan_all_looky_players()` in `session_sniffer.guis._main_window_looky_mixin` must check:
     ```python
     if not CaptureState.is_local_capture():
         QMessageBox.warning(self, LOOKY_TITLE, LOOKY_WARNING_RESTRICTED_NOT_LOCAL)
         return

     if is_looky_gta5_restricted():
         QMessageBox.warning(self, LOOKY_TITLE, LOOKY_WARNING_RESTRICTED_GTA5_NOT_RUNNING)
         return
     ```
   * Never bypass this check when players exist in the registry.

## Shared UI Text and Constants

Always use centralized helpers and constants from `session_sniffer.guis.looky_text`. Do not duplicate string literals or gating expressions:
* `is_looky_gta5_restricted()`: Centralized check returning True when capture is non-local or local capture is active without GTA V scanning.
* `LOOKY_TITLE`
* `LOOKY_SETTINGS_AUTH_PATH`, `LOOKY_SETTINGS_GENERAL_PATH`
* `LOOKY_MENU_TOOLTIP_DISABLED`, `LOOKY_MENU_TOOLTIP_API_KEY_MISSING`, `LOOKY_MENU_TOOLTIP_API_KEY_INVALID_OR_NO_ACCESS`
* `LOOKY_MENU_TOOLTIP_GTA5_NOT_RUNNING`, `LOOKY_MENU_TOOLTIP_RESTRICTED_GTA5_NOT_RUNNING`, `LOOKY_MENU_TOOLTIP_RESTRICTED_NOT_LOCAL`
* `LOOKY_WARNING_DISABLED`, `LOOKY_WARNING_API_KEY_MISSING`, `LOOKY_WARNING_API_ACCESS_MISSING`, `LOOKY_WARNING_RESTRICTED_GTA5_NOT_RUNNING`, `LOOKY_WARNING_RESTRICTED_NOT_LOCAL`
* `LOOKY_LOG_API_KEY_INVALID`, `LOOKY_LOG_VERIFICATION_HTTP_FAILED_TEMPLATE`

## Rate Limiting & Error Handling

* **Rate Limits (HTTP 429)**:
  * Parse rate-limit responses with `extract_rate_limit_message(e)` and `extract_rate_limit_wait_seconds(e)`.
  * Use dynamic pluralization (`pluralize(wait_seconds)`) when displaying wait time to the user.
* **Server Errors (HTTP 5xx) & Connection Failures**:
  * Apply exponential backoff (e.g. starting at 30s up to 300s max) during token verification in `cores.py`.
  * Never spam or flood the Looky System API during server disruptions or downtime.
* **Instruction Status Watching**:
  * Crawler requests use Server-Sent Events (SSE) via `watch_instruction_status`.
    Always cleanly close the active socket and handle terminal failure statuses (`is_terminal_failure_instruction_status`).

## Repository Standards for Looky Code

* Line endings: Always CRLF (`\r\n`).
* Maximum line length: 176 characters.
* String quotes: Single quotes (`'`) unless containing a single quote.
* No backward compatibility shims or transitional dual paths.
* Dynamic pluralization: Always use `pluralize(count)` from `session_sniffer.text_utils` for user-facing counts.
