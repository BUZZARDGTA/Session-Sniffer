---
trigger: model_decision
description: Use when modifying Session Sniffer's desktop GUI, stylesheets, themes, icons, languages, menus, tables, status bar, header/search controls, or any files under website/, to keep the desktop app and the website's interactive live preview visually and structurally synchronized 1:1.
---

# Desktop App ↔ Website Visual Parity Rules

Session Sniffer ships an interactive live UI preview in `website/` (`website/index.html`, `website/styles.css`, `website/preview.css`, `website/preview.js`, `website/core.js`, and generated bundles in `website/assets/`).

**The desktop application and the `website/` live preview must stay visually and structurally identical (1:1).** Never finish a user-visible desktop GUI change without mirroring it in `website/` in the same task, and never fix or refine a UI detail in the `website/` preview without verifying whether the desktop app needs the matching change so neither side drifts.

## Bi-Directional Sync Rule

1. **Desktop app → Website:** Whenever you add, modify, restyle, rename, reorder, or remove any user-visible element in the desktop app that is represented in the website (menus, submenus, header, search bar, search column selector, notification toggles, live metric cards, section bars, pagination spinboxes/dividers/buttons, table columns, alignment, row tinting, rate coloring, empty states, context menu, status bar, built-in themes, theme color tokens, language switcher/flags, icons, or supported languages), update `website/` in the **same task** to match 1:1.
2. **Website → Desktop app:** Whenever you improve visual polish or parity in `website/` (for example: divider bars, disabled/at-bound spinbox arrow states, numeric column alignment, or country flags in the language selector), check whether the desktop app already matches; if not, update the desktop app as well (or confirm with the user if scope is ambiguous) so both stay visually identical.

## Component-by-Component Parity Map

Always inspect the corresponding desktop implementation and QSS before editing `website/`, and vice versa:

* **Main Window Shell & Menu Bar:**
  * Desktop: `src/session_sniffer/guis/main_window.py`, `_main_window_files_mixin.py`, `_main_window_game_mixin.py`, `_main_window_looky_mixin.py`, `_main_window_stats_mixin.py`, `stylesheets/_menus.py`, `theme.py`
  * Website: `.ss-window`, `.ss-titlebar`, `.ss-menubar`, `#ss-menubar` in `website/index.html`, `website/styles.css`, `website/app.js`
  * Keep exact menu titles, item order, submenus (including `GTA V` → `Looky System`), icons, and separators aligned. Desktop-only menu actions show the demo-only toast with Download CTA rather than faking results.
* **Main Header, Search Bar, Column Selector & Live Metrics:**
  * Desktop: `src/session_sniffer/guis/_main_header.py`, `stylesheets/_main_header.py`, `src/session_sniffer/constants/tables.py` (`SEARCHABLE_COLUMN_EXCLUSIONS`)
  * Website: `.ss-app-header`, `#ss-search-input`, custom Qt-styled `#ss-search-column` / `#ss-search-column-popup`, notification toggles, Uptime/Captured Packets cards
  * Mirror exact `QComboBox#headerSearchCombo` styling (never use an unstyled native browser `<select>` popup where Qt uses custom QSS) and keep the searchable column list and order 1:1 with `_populate_searchable_columns()`.
* **Section Bars, Pagination Spinboxes & Action Controls:**
  * Desktop: `src/session_sniffer/guis/_session_table_section.py`, `stylesheets/_section_bar.py`, `stylesheets/_misc.py`, `theme.py` (`chevron-up-disabled.svg`, `chevron-down-disabled.svg`)
  * Website: `.ss-section-header`, `Rows:` / `Page:` spinboxes (including greyed-out disabled/at-bound arrows), vertical `|` separator, `MERGE`/`SPLIT`, `CLEAR`, minimize/expand buttons, splitter
* **Session Tables, Columns, Alignment, Rate Gradients & Empty States:**
  * Desktop: `src/session_sniffer/guis/tables.py` (`_paint_empty_state`), `table_model.py`, `table_icons.py`, `colors.py`, `theme.py`
  * Website: `#ss-connected-table`, `#ss-disconnected-table`, numeric quantity right-alignment (`.num`) with comma thousands grouping (`44,912`, never on ports/identifiers), `PPS`/`BPS` red → yellow → green rate thresholds (`PPS_MAX_THRESHOLD`, `BPS_MAX_THRESHOLD`), row state tinting (host, relay, server, VPN, Looky, high-rate), and centered icon + title + subtitle empty states (`#ss-connected-empty`, `#ss-disconnected-empty`)
* **Row Right-Click Context Menu:**
  * Desktop: `src/session_sniffer/guis/tables_context_menu_mixin.py`, `table_context_menu.py`
  * Website: `#ss-context-menu` in `website/index.html`, `website/styles.css`, `website/app.js`
  * Keep exact action hierarchy, icons, shortcuts, and submenus (including `Looky System`, `Ping`, `UserIP`).
* **Status Bar:**
  * Desktop: `src/session_sniffer/rendering_core/status_bar_renderer.py`, `src/session_sniffer/guis/colors.py`
  * Website: `.ss-statusbar` (exact `Capture:`, `Config:`, `Performance:` segments and canonical Dark-theme colors)
* **Language Selector & Country Flags:**
  * Desktop: `src/session_sniffer/i18n.py` (`SUPPORTED_LANGUAGES`, `RTL_LANGUAGE_CODES`, `LANGUAGE_COUNTRY_FLAGS`), `settings_dialog.py`, `_settings_widget_builders.py`
  * Website: `#nav-lang-switcher` / `#lang-menu-dropdown` in `website/index.html`, `website/styles.css`, `website/app.js`
  * Always share the single source of truth `LANGUAGE_COUNTRY_FLAGS` from `src/session_sniffer/i18n.py` rather than duplicating flag mappings.
* **Built-in Themes:**
  * Desktop: `src/session_sniffer/models/themes.py` (`BUILTIN_THEMES`), `src/session_sniffer/guis/theme.py`
  * Website: `website/assets/themes.generated.css`, `website/assets/app-data.generated.js`, `#nav-theme-switcher`

## Shared Assets & Sync Pipeline (`website/sync_assets.py`)

`website/sync_assets.py` is the bridge between the desktop app and `website/`. Whenever synced data changes:

1. Update `SHARED_APP_MESSAGE_KEYS` / `SHARED_APP_PLURAL_SINGULAR_KEYS` in `website/sync_assets.py` whenever a desktop UI string shown in the website preview is added, renamed, or removed (and remove obsolete keys outright per `No Backward Compatibility` in `core.md`).
2. **No Inline Icon SVGs (Export Every Icon to an `.svg` File):**
   * **Never** inline raw `<svg>` icon paths or shapes directly in `website/*.html` or `website/*.js`. Every icon rendered on the website must live in its own standalone `.svg` file and be referenced via `<svg class="icon ..." aria-hidden="true"><use href="#icon-<name>"></use></svg>` (or `createIconSvg('<name>', ...)` in JS).
   * **Shared desktop + website icons:** Keep in `resources/icons/<name>.svg` and list in `SYNCED_ICONS` in `website/sync_assets.py` (and remove obsolete entries when no longer used by the website).
   * **Website-only icons** (brand/OS/platform/social logos or website-only UI icons not used in the desktop app): Export as standalone `.svg` files in `website/icons/<name>.svg` — never add unused icons to `resources/icons/` (which PyInstaller bundles into the desktop executable) and never duplicate an icon already present in `resources/icons/`.
     * Stroke icons use `viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"`.
     * Solid filled brand logos use `viewBox="0 0 24 24" fill="currentColor"`.
     * `website/sync_assets.py` automatically discovers all `website/icons/*.svg` files and compiles them alongside `app_icon` and `SYNCED_ICONS` into the shared inline SVG sprite in `website/assets/app-data.generated.js`.
     * Delete unused `.svg` files from `website/icons/` outright per `No Backward Compatibility` in `core.md`, and always enforce CRLF (`\r\n`) line endings.
3. Update `SYNCED_COUNTRY_FLAGS` in `website/sync_assets.py` whenever flags in `resources/images/country_flags/` used by the website change.
4. Run `python website/sync_assets.py` to regenerate:
   * `website/assets/themes.generated.css`
   * `website/assets/app-data.generated.js`
   * `website/assets/i18n/<lang>.js` (all 32 non-English bundles)
   * `website/assets/app_icon.svg` and `website/assets/flags/*.png`
5. Never edit generated files under `website/assets/` by hand when `python website/sync_assets.py` can regenerate them cleanly.
6. Whenever website-specific copy in `website/translations/en.json` changes, update all 32 `website/translations/<lang>.json` catalogs in the same task so `sync_assets.py` validation stays green.

## Styling, Themes, RTL & Verification

* Match desktop QSS tokens, colors, radii, borders, padding, hover/focus/selection/disabled states, and canonical Dark-theme overrides (`[data-theme='dark']`), while also keeping Light, Nord, Dracula, Midnight, and Solarized Light palettes legible.
* Preserve RTL layout mirroring (`[dir='rtl']`) for `ar`, `fa`, and `he` on every directional preview control (icons, arrows, padding, alignment, popups).
* Enforce **CRLF (`\r\n`)** line endings across all modified and generated files under `website/` (`core.md`).
* When `website/sync_assets.py` is modified, validate it with the project's `.venv` static-analysis/linting tools (`testing.md`).
* To preview and test `website/` locally, always run `.venv\Scripts\python.exe -m http.server 8080 --bind 0.0.0.0 --protocol HTTP/1.1 --directory website` (on Linux/macOS: `.venv/bin/python -m http.server 8080 --bind 0.0.0.0 --protocol HTTP/1.1 --directory website`) — always include `--protocol HTTP/1.1` so large HTML/JS assets (`index.html`, `app-data.generated.js`, `preview.js`) transfer cleanly without 64 KB truncation.
* Visually verify non-trivial website preview changes in a live browser across Dark and Light themes (and a non-English / RTL locale when text or directional layout changed) with zero console or network errors.
