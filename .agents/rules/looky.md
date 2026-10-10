---
trigger: model_decision
description: Use when working on Looky System integration, IP lookups, crawler requests, token verification, Looky settings, gating logic, or player Looky actions.
---

# Looky System Rules and Guidelines

These rules govern all Looky System development, integration, security controls, and UI gating in Session Sniffer.

## Overview & Architecture

Looky System is a third-party service (`looky-gta.cc`) used to resolve IP addresses to Rockstar IDs and usernames for GTA V players:
* **Background Worker**: `looky_core()` in `session_sniffer.background.cores` validates the configured API key on startup and setting changes (updating `LookyState`), polls connected eligible players, and performs batch lookups (`lookup_ip_batch`).
* **Manual Lookups & Dialogs**: `session_sniffer.guis.tables_player_actions.looky_system` provides
  manual lookup (`show_looky_lookup`), crawler requests (`show_crawler_request`, `show_crawlme_request`),
  and UserIP database lookups (`looky_refresh_userip_entries`).
* **UI Text & Gating Helpers**: Centralized in `session_sniffer.guis.looky_text` (`configure_looky_action`, message constants, tooltips).

## Strict Privacy and GTA V PID Gating (Non-Negotiable)

Session Sniffer sends captured IP addresses externally over the internet to the Looky System API.

### Anti-Leak Security Constraint
* In local capture mode (`CaptureState.is_local_capture()`), when `Settings.looky_exclusive_gta5_process` is True (default):
  * **Automatic background capture queries must never be transmitted to the Looky System API unless capture is actively filtering
    on the running GTA V process PID (`CaptureState.is_scanning_gta5_process()`).**
  * **Never relax or soften this restriction** to make automated Looky lookups work in the default "Sniff All Traffic" mode. Sniffing all traffic captures personal,
    non-game network connections (web browsers, Discord, Spotify, background software). Transmitting these arbitrary IPs to third-party Looky servers is a severe privacy leak.
  * **Standalone arbitrary IP lookups** (`StandaloneIPLookup`) must also require GTA V process scanning.

### Confirmed GTA V Process Players vs Other Traffic and Arbitrary IPs
* **Confirmed GTA V Process Players (`player.is_gta5_process == True`)**:
  * In Session Sniffer, a player has `is_gta5_process == True` only when packet capture confirmed communication with the actively scanned GTA V PID (`local_port in CaptureState.gta5_udp_ports`).
  * Prior scanned confirmed GTA V PID players are permitted to be used with Looky System even when the sniffer is closed or GTA V is offline (commits `4699f1f9` and `ddced2e9`):
    * Manual context menu actions ("Lookup", "Lookup (All Selected)", and "Request Crawler") remain accessible for them.
    * "Request Crawler" sends the crawler bot to the target player's Rockstar ID in the cloud, so the local GTA V process does not need to be running.
    * "Rescan All Players" is permitted when at least one confirmed GTA V process player is present in `PlayersRegistry`.
* **Other P2P Traffic & Non-GTA Players (`player.is_gta5_process == False`)**:
  * Any P2P traffic captured from somewhere else than the GTA V PID (such as background applications, Discord, web browsers, or torrent clients captured during "Sniff All Traffic", where `player.is_gta5_process` is `False`).
  * These players must **never** be used with or transmitted to Looky System when the sniffer is closed or GTA V PID scanning is offline.
  * Context menu actions and lookup dialogs must enforce `check_gta5_restriction=True` for them (disabling actions with `LOOKY_MENU_TOOLTIP_RESTRICTED_GTA5_NOT_RUNNING` or showing `LOOKY_WARNING_RESTRICTED_GTA5_NOT_RUNNING` dialog).
* **Live Session & Standalone Arbitrary IP Actions**:
  * "Request Crawler in My Session" (`show_crawlme_request`) requires GTA V to be actively running and scanned (`CaptureState.gta5_is_running` and `CaptureState.is_scanning_gta5_process()`).
  * Standalone IP lookup for arbitrary uncaptured IPs (`StandaloneIPLookup`) strictly enforces `check_gta5_restriction=True`.

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
        and not (player.is_gta5_process and (not player.looky_system.is_initialized or player.looky_system.needs_refresh))
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

1. **Context Menu Actions**:
   * The Looky System submenu in `session_sniffer.guis.tables_context_menu_mixin` must return early and omit itself entirely when `not CaptureState.is_local_capture()`.
   * Actions operate on captured `Player` objects and use:
     `configure_looky_action(action, default_tooltip=action.toolTip(), check_gta5_restriction=any(not player.is_gta5_process for player in players))`

2. **Standalone Dialog Buttons**:
   * The "Looky Lookup…" button in `session_sniffer.guis.tables_player_actions._ip_lookup_dialog` gates based on target type:
     `configure_looky_action(lookup_button, default_tooltip=..., check_gta5_restriction=isinstance(self._target, StandaloneIPLookup) or not getattr(self._target, 'is_gta5_process', False))`.

3. **Background Lookup in Standalone Dialogs**:
   * Standalone IP background resolutions verify the PID restriction before dispatching `lookup_ip`:
     `not is_looky_gta5_restricted()`

4. **Pre-Flight Function `check_looky_prerequisites`**:
   * `check_looky_prerequisites(parent: QWidget, *, check_gta5_restriction: bool = False)` in `session_sniffer.guis.tables_player_actions.looky_system._looky_helpers`:
     * Checks API key presence, `Settings.looky_enabled`, `LookyState.api_access`.
     * Rejects non-local capture (`not CaptureState.is_local_capture()`) with `LOOKY_WARNING_RESTRICTED_NOT_LOCAL`.
     * When `check_gta5_restriction=True`, verifies `is_looky_gta5_restricted()` and shows `LOOKY_WARNING_RESTRICTED_GTA5_NOT_RUNNING` warning message box if unsatisfied.
   * `show_crawler_request()` enforces `check_gta5_restriction=not player.is_gta5_process`.
   * `show_crawlme_request()` always passes `check_gta5_restriction=True`.
   * `show_looky_lookup()` enforces `check_gta5_restriction=not isinstance(player, Player) or not player.is_gta5_process`.

5. **"Rescan All Players" Action**:
   * `_rescan_all_looky_players()` in `session_sniffer.guis._main_window_looky_mixin` must check:
     ```python
     if not CaptureState.is_local_capture():
         QMessageBox.warning(self, LOOKY_TITLE, LOOKY_WARNING_RESTRICTED_NOT_LOCAL)
         return

     players = PlayersRegistry.get_default_sorted_players()
     if is_looky_gta5_restricted() and not any(player.is_gta5_process for player in players):
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
