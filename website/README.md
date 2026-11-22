# Session Sniffer Website

Static multi-page website for **Session Sniffer**, synced directly from the desktop application's real theme system, Lucide SVG icons, country flags, and metadata.

## Pages & Structure

- `index.html` — Focused landing page: Hero, 1:1 interactive desktop preview (`preview.css` / `preview.js`), core features, OS-aware downloads, Explore More hub, and FAQ.
- `games.html` (`/games`) — Supported Games & Software Explorer (`games.css` / `games.js`): cover marquee, searchable/filterable Wiki compatibility table & gallery, detail modal, and Username Resolving guide.
- `history.html` (`/history`) — Project History & Release Archive (`history.css` / `history.js`): 5-era screenshot showcase with lightbox, version-by-version release ledger, and 163-tag Git archive.
- `styles.css`, `core.js`, `theme-init.js` — Shared built-in theme switcher, 33-language i18n/RTL switcher, navigation chrome, toasts, tooltips, and live GitHub/Discord stats.

## What Is Shared From Session Sniffer

Run the sync script whenever you update themes, icons, version, or translations in the main app:

```powershell
.venv\Scripts\python.exe website\sync_assets.py
```

`sync_assets.py` generates/updates everything inside `website/assets/`:
- `assets/themes.generated.css` — All 6 built-in themes (`Dark`, `Light`, `Midnight`, `Dracula`, `Nord`, `Solarized Light`) and their 20 color tokens from `src/session_sniffer/models/themes.py`.
- `assets/app-data.generated.js` — Theme metadata, all 33 languages from `src/session_sniffer/i18n.py`, app version (`pyproject.toml`), full Git commit & release-tag history metadata (2021–2026), and the inline SVG sprite built from 71 icons in `resources/icons/`.
- `assets/i18n/<lang>.js` — 32 lazy-loaded per-language bundles merging shared desktop UI & theme translations from `resources/translations/<lang>.json` with website copy from `website/translations/<lang>.json` (full RTL support for `ar`, `fa`, `he`).
- `assets/app_icon.svg` — Verbatim radar icon copied from `resources/icons/app_icon.svg`.
- `assets/flags/*.png` — Demo country flags copied from `resources/images/country_flags/`.
- `assets/history/*.png` — Self-hosted historical UI screenshots spanning 2021 (`PS3 Blacklist Sniffer`) through `v1.5.0` (`PySide6`).

## Preview Locally (Testing)

Run a local HTTP/1.1 static server from the repository root:

**Windows (PowerShell / CMD):**
```powershell
.venv\Scripts\python.exe -m http.server 8080 --bind 0.0.0.0 --protocol HTTP/1.1 --directory website
```

**Linux / macOS:**
```bash
.venv/bin/python -m http.server 8080 --bind 0.0.0.0 --protocol HTTP/1.1 --directory website
```

Then open `http://127.0.0.1:8080` (or `http://localhost:8080`) in your browser.

> **Why `--protocol HTTP/1.1`?** Python's `http.server` defaults to `HTTP/1.0`, which can truncate responses larger than 64 KB (such as `index.html`, `assets/app-data.generated.js`, and `preview.js`) behind local HTTP filters/proxies (e.g. AdGuard) and prevent the inline SVG icon sprite and scripts from loading. Always pass `--protocol HTTP/1.1`.

## Deploy Free on Cloudflare Pages

1. Push this repository to GitHub.
2. In the [Cloudflare Dashboard](https://dash.cloudflare.com/), open **Workers & Pages** → **Create** → **Pages** → **Connect to Git**.
3. Select `BUZZARDGTA/Session-Sniffer` and configure:
   - **Production branch:** `main`
   - **Build command:** *(leave empty — pre-synced static files)*
   - **Build output directory:** `website`
4. *(Optional)* Under **Settings → Builds & deployments → Build watch paths**, include `website/*` so Cloudflare only redeploys when website files change.
5. Under **Custom domains**, add your domain (e.g. `sessionsniffer.com`). Cloudflare automatically sets up DNS, HTTPS/SSL, DDoS protection, and WAF.
6. To redirect both `sessionsniffer.pages.dev` and per-commit deployment URLs (`<hash>.sessionsniffer.pages.dev`) at the edge with HTTP `301`, open **Account Home → Bulk Redirects**, edit the redirect list entry for `sessionsniffer.pages.dev/` → `https://sessionsniffer.com/`, and enable **Include subdomains**, **Subpath matching**, **Preserve path suffix**, and **Preserve query string**. (`theme-init.js` also enforces a pre-paint fallback redirect for future deployments.)
7. Security headers (`CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `X-Robots-Tag: noindex` on `*.pages.dev`, caching) are automatically applied by Cloudflare Pages from `website/_headers`.
