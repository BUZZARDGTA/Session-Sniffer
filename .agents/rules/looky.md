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
  proxy join requests (`show_proxy_join_request`), and UserIP database lookups (`looky_refresh_userip_entries`).
* **UI Text & Gating Helpers**: Centralized in `session_sniffer.guis.looky_text` (`configure_looky_action`, message constants, tooltips).

## Privacy Gating: Only Confirmed GTA V Traffic (Non-Negotiable)

Session Sniffer sends captured IP addresses externally over the internet to the Looky System API.

### Anti-Leak Security Constraint
* When `Settings.looky_exclusive_gta5_process` is True (default), a captured player IP may only be sent to Looky System when the player is
  **confirmed GTA V traffic** (`player.is_gta5_process == True`).
* "Sniff All Traffic" captures personal, non-game connections (web browsers, Discord, Spotify, background software). Transmitting those IPs to
  third-party Looky servers is a severe privacy leak. **Never relax the confirmed-GTA V-traffic requirement.**
* The privacy guarantee comes from the **GTA V socket port match**, not from the Target Process setting. Requiring the Target Process to be GTA V
  for captured players adds no protection, so do not reintroduce `CaptureState.is_scanning_gta5_process()` as a gate for captured players.

### Confirmed GTA V Traffic (`player.is_gta5_process`)
* `packet_callback` (`session_sniffer.main`) sets `is_gta5_process = True` when a packet's local port is one of the GTA V process's own UDP socket
  ports (`local_port in CaptureState.gta5_udp_ports`) on a local capture with the GTA V feature set.
* The process monitor resolves those ports from the Authenticode-verified GTA V process whenever the GTA V feature set is active, whether the
  Target Process is GTA V or set to sniff all traffic. `gta5_udp_ports` is empty while GTA V is not running, so no separate running check is needed.
* Tagged players stay usable with Looky System after GTA V exits or crashes (lookups, "Request Crawler", "Proxy Join", "Rescan All Players",
  and automatic lookups and refreshes). "Request Crawler" and "Proxy Join" target the player's Rockstar ID in the cloud, so GTA V does not need to be running.
* Untagged players (`is_gta5_process == False`) must never be sent to Looky System while the restriction is enabled.

### Standalone IP Lookups (`StandaloneIPLookup`)
* IP lookups opened outside the session tables (Player Leaderboard, Logs Manager, UserIP Manager, and other tables) have no port tag.
* While the restriction is enabled, they require capture to be filtering on the GTA V process (`CaptureState.is_scanning_gta5_process()`).

### "Request Crawler in My Session" (`show_crawlme_request`)
* It sends no captured IP, so it is not subject to the restriction. It only requires the usual prerequisites plus `CaptureState.gta5_is_running`.

### Single Source of Truth: `get_looky_restriction`
All restriction decisions go through `get_looky_restriction(targets)` in `session_sniffer.guis.looky_text`. It returns the reason (a user-facing
message) or `None` when every target is allowed:
* restriction disabled → `None`;
* a `Player` that is not `is_gta5_process` → `LOOKY_MENU_TOOLTIP_RESTRICTED_NOT_GTA5_PLAYER`;
* a `StandaloneIPLookup` while not scanning the GTA V process → `LOOKY_MENU_TOOLTIP_RESTRICTED_GTA5_NOT_RUNNING`.

Never duplicate this logic at call sites.

### Eligibility Gating (`is_looky_eligible`)
`is_looky_eligible(player)` in `session_sniffer.background.cores` is used by automatic lookups, refreshes, and "Rescan All Players":
```python
def is_looky_eligible(player: Player) -> bool:
    if not Settings.looky_enabled or not Settings.is_gta5_feature_set():
        return False
    if player.is_third_party_server:
        return False
    if not CaptureState.is_local_capture():
        return False
    return get_looky_restriction([player]) is None
```

### Consoles & Non-Local Captures (Strictly Prohibited)
Looky System is strictly a PC-only feature. Consoles and external captures (ARP spoofing, bridged adapters, neighbour adapters, etc., where `CaptureState.is_local_capture()` is `False`) must never be permitted to access or support Looky System under any circumstances:
* Automated Looky background resolutions must immediately disqualify players when `not CaptureState.is_local_capture()`.
* Context menus must omit the Looky System submenu on non-local captures.
* All Looky manual entry points and action handlers (`configure_looky_action`, `check_looky_prerequisites`, `show_looky_lookup`, `show_crawler_request`, `show_crawlme_request`, `_rescan_all_looky_players`) must reject non-local captures with `LOOKY_MENU_TOOLTIP_RESTRICTED_NOT_LOCAL` or `LOOKY_WARNING_RESTRICTED_NOT_LOCAL`.
* Standalone IP background lookups (`_resolve_standalone_lookup`) also require `CaptureState.is_local_capture()`.

### Third-Party Server & Relay Restriction
Third-party server and relay players (`player.is_third_party_server` = True, such as Take-Two Interactive or Microsoft relay servers) must never be sent to Looky System.
Context menus and automated lookups must omit or suppress Looky System for them.

## Manual UI Actions and Pre-Flight Validation

Both UI helpers take the restriction reason computed by `get_looky_restriction` through a `restriction: str | None` parameter:
* `configure_looky_action(action, default_tooltip, *, is_gta5_running=None, restriction=None)` in `session_sniffer.guis.looky_text`
  disables the action and shows `restriction` as its tooltip.
* `check_looky_prerequisites(parent, *, restriction=None)` in `session_sniffer.guis.tables_player_actions.looky_system._looky_helpers`
  checks the GTA V feature set, API key, `Settings.looky_enabled`, `LookyState.api_access`, and local capture, then shows `restriction` as a warning.

Call sites:
1. **Context menu** (`session_sniffer.guis.tables_context_menu_mixin`): omit the submenu on non-local captures; gate actions with
   `restriction=get_looky_restriction(players)`.
2. **IP Lookup dialog** (`session_sniffer.guis.tables_player_actions._ip_lookup_dialog`): the "Looky Lookup…" button uses
   `restriction=get_looky_restriction([self._target])`; the standalone background lookup requires `get_looky_restriction([lookup]) is None`.
3. **Lookup, crawler, and proxy join requests**: `show_looky_lookup()`, `show_crawler_request()`, `show_proxy_join_request()`,
   `show_crawler_by_rid()`, and `show_proxy_join_by_rid()` pass `restriction=get_looky_restriction([target])`.
4. **"Request Crawler in My Session"**: `show_crawlme_request()` passes no restriction and checks `CaptureState.gta5_is_running`.
5. **"Rescan All Players"** (`session_sniffer.guis._main_window_looky_mixin`): reject non-local captures with `LOOKY_WARNING_RESTRICTED_NOT_LOCAL`;
   allowed when at least one player passes `get_looky_restriction([player])`; `trigger_looky_rescan_all_players()` only queues `is_looky_eligible` players.

## Shared UI Text and Constants

Always use centralized helpers and constants from `session_sniffer.guis.looky_text`. Do not duplicate string literals or gating expressions:
* `get_looky_restriction(targets)`: the single restriction check (see above).
* `LOOKY_TITLE`
* `LOOKY_SETTINGS_AUTH_PATH`, `LOOKY_SETTINGS_GENERAL_PATH`
* `LOOKY_MENU_TOOLTIP_DISABLED`, `LOOKY_MENU_TOOLTIP_API_KEY_MISSING`, `LOOKY_MENU_TOOLTIP_API_KEY_INVALID_OR_NO_ACCESS`
* `LOOKY_MENU_TOOLTIP_GTA5_NOT_RUNNING`, `LOOKY_MENU_TOOLTIP_RESTRICTED_GTA5_NOT_RUNNING`, `LOOKY_MENU_TOOLTIP_RESTRICTED_NOT_GTA5_PLAYER`, `LOOKY_MENU_TOOLTIP_RESTRICTED_NOT_LOCAL`
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
