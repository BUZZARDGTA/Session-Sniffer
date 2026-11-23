/* ==========================================================================
   Session Sniffer Website Core Controller (Shared across all pages)
   - Injects shared SVG icon sprite generated from resources/icons/
   - Powers all 33 Session Sniffer languages (lazy-loaded bundles + live RTL)
   - Powers global 6-theme switcher across pages
   - Powers sticky navbar dropdowns, mobile drawer, toasts & rich tooltips
   - Hydrates live release stats & OS-specific download links from GitHub + Discord
   ========================================================================== */

(function initSessionSnifferCore() {
    'use strict';

    var DATA = window.SESSION_SNIFFER_DATA;
    if (!DATA) {
        return;
    }

    var STORAGE_THEME_KEY = 'ss_website_theme';
    var STORAGE_LANG_KEY = 'ss_website_lang';
    /* Matches PPS_MAX_THRESHOLD / BPS_MAX_THRESHOLD in rendering_core/session_table_renderer.py */
    var PPS_MAX_THRESHOLD = 10;
    var BPS_MAX_THRESHOLD = 1024;
    var RELEASE_ASSETS = {
        windows: {
            labelKey: 'hero.cta_download_windows',
            file: 'Session_Sniffer.exe',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/latest/download/Session_Sniffer.exe',
        },
        linux: {
            labelKey: 'hero.cta_download_linux',
            file: 'Session_Sniffer',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/latest/download/Session_Sniffer',
        },
        macos: {
            labelKey: 'hero.cta_download_macos',
            file: 'Session_Sniffer_macOS',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/latest/download/Session_Sniffer_macOS',
        },
    };

    var PAGE_META_KEYS = {
        home: { title: 'meta.title', description: 'meta.description' },
        games: { title: 'meta.games_title', description: 'meta.games_description' },
        history: { title: 'meta.history_title', description: 'meta.history_description' },
    };

    var BUILTIN_BY_SLUG = {};
    DATA.builtinThemes.forEach(function registerTheme(theme) {
        BUILTIN_BY_SLUG[theme.slug] = theme;
    });

    var LANG_BY_CODE = {};
    var LANG_LOWER_TO_CODE = {};
    (DATA.languages || []).forEach(function registerLang(lang) {
        LANG_BY_CODE[lang.code] = lang;
        LANG_LOWER_TO_CODE[lang.code.toLowerCase()] = lang.code;
    });

    var languageListeners = [];
    var themeListeners = [];
    var closePopupListeners = [];

    function getPageId() {
        return document.documentElement.getAttribute('data-page') || 'home';
    }

    function onLanguageChange(fn) {
        if (typeof fn === 'function') {
            languageListeners.push(fn);
        }
    }

    function onThemeChange(fn) {
        if (typeof fn === 'function') {
            themeListeners.push(fn);
        }
    }

    function onClosePopups(fn) {
        if (typeof fn === 'function') {
            closePopupListeners.push(fn);
        }
    }

    function notifyClosePopups() {
        closePopupListeners.forEach(function invoke(fn) { fn(); });
    }

    function notifyThemeChange(reason) {
        themeListeners.forEach(function invoke(fn) { fn(reason); });
    }

    /* ----------------------------------------------------------------------
       Color & Formatting Helpers
       ---------------------------------------------------------------------- */

    function hexToRgb(hex) {
        var clean = hex.replace('#', '');
        return [
            parseInt(clean.slice(0, 2), 16),
            parseInt(clean.slice(2, 4), 16),
            parseInt(clean.slice(4, 6), 16),
        ];
    }

    function isLightColor(hex) {
        var rgb = hexToRgb(hex);
        return (0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2]) > 140;
    }

    function bestOnColor(bgHex) {
        var rgb = hexToRgb(bgHex).map(function linearize(channel) {
            var v = channel / 255;
            return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
        });
        var luminance = 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
        var contrastWhite = 1.05 / (luminance + 0.05);
        return contrastWhite >= 3.8 ? '#ffffff' : '#0b0d10';
    }

    /* Mirrors _get_rate_gradient_color() in rendering_core/session_table_renderer.py */
    function getRateGradientColor(rate, threshold, isLightBg) {
        var clamped = Math.min(Math.max(Number(rate) || 0, 0), threshold);
        var scaled = Math.floor((clamped * 0xFF) / threshold);
        if (isLightBg) {
            return 'rgb(' + Math.round((0xFF - scaled) * 0.72) + ', ' + Math.round(scaled * 0.58) + ', 0)';
        }
        return 'rgb(' + (0xFF - scaled) + ', ' + scaled + ', 0)';
    }

    function formatNumber(n) {
        return Math.round(n).toLocaleString('en-US');
    }

    function formatBytes(bytes) {
        if (bytes < 1024) {
            return bytes + ' B';
        }
        if (bytes < 1024 * 1024) {
            return (bytes / 1024).toFixed(1) + ' KB';
        }
        if (bytes < 1024 * 1024 * 1024) {
            return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        }
        return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
    }

    function formatUptime(totalSeconds) {
        var hrs = Math.floor(totalSeconds / 3600);
        var mins = Math.floor((totalSeconds % 3600) / 60);
        var secs = totalSeconds % 60;
        return [hrs, mins, secs]
            .map(function pad(v) { return String(v).padStart(2, '0'); })
            .join(':');
    }

    function formatElapsed(seconds) {
        if (seconds < 60) {
            return String(seconds).padStart(2, '0') + 's';
        }
        var mins = Math.floor(seconds / 60);
        var secs = seconds % 60;
        if (mins < 60) {
            return String(mins).padStart(2, '0') + 'm ' + String(secs).padStart(2, '0') + 's';
        }
        var hrs = Math.floor(mins / 60);
        return String(hrs).padStart(2, '0') + 'h ' + String(mins % 60).padStart(2, '0') + 'm';
    }

    function formatDuration(seconds) {
        var mins = Math.floor(seconds / 60);
        var secs = seconds % 60;
        if (mins < 60) {
            return mins + 'm ' + String(secs).padStart(2, '0') + 's';
        }
        var hrs = Math.floor(mins / 60);
        return hrs + 'h ' + String(mins % 60).padStart(2, '0') + 'm';
    }

    function createIconSvg(iconName, extraClass) {
        var ns = 'http://www.w3.org/2000/svg';
        var svg = document.createElementNS(ns, 'svg');
        svg.setAttribute('class', 'icon ' + (extraClass || 'icon-xs'));
        svg.setAttribute('aria-hidden', 'true');
        var use = document.createElementNS(ns, 'use');
        use.setAttribute('href', '#icon-' + iconName);
        svg.appendChild(use);
        return svg;
    }

    function showToast(message, options) {
        var region = document.getElementById('toast-region');
        if (!region) {
            return;
        }
        var opts = options || {};
        var card = document.createElement('div');
        card.className = 'toast-card' + (opts.variant ? ' toast-card--' + opts.variant : '');

        function dismissToast() {
            if (card.parentNode) {
                card.parentNode.removeChild(card);
            }
        }

        if (opts.actionLabel && opts.actionHref) {
            var body = document.createElement('div');
            body.className = 'toast-body';
            body.textContent = message;
            card.appendChild(body);

            var actionLink = document.createElement('a');
            actionLink.className = 'toast-action-btn';
            actionLink.href = opts.actionHref;
            actionLink.appendChild(createIconSvg('cloud-download', 'icon-xs'));
            var actionText = document.createElement('span');
            actionText.textContent = opts.actionLabel;
            actionLink.appendChild(actionText);
            actionLink.addEventListener('click', function onToastActionClick(ev) {
                ev.stopPropagation();
                dismissToast();
                if (opts.actionHref.charAt(0) === '#') {
                    var target = document.getElementById(opts.actionHref.slice(1));
                    if (target) {
                        ev.preventDefault();
                        target.scrollIntoView({ behavior: 'smooth' });
                    }
                }
            });
            card.appendChild(actionLink);
        } else {
            card.textContent = message;
        }

        card.addEventListener('click', dismissToast);
        region.appendChild(card);

        while (region.children.length > 3) {
            region.removeChild(region.firstChild);
        }

        window.setTimeout(dismissToast, opts.duration || 3800);
    }

    function showDemoFeatureToast(featureLabel) {
        var cleanLabel = String(featureLabel || '')
            .replace(/&&/g, '&')
            .replace(/(?:\u2026|\.\.\.)\s*$/, '')
            .trim();
        showToast(
            tSite('preview.toast_demo_only', { feature: cleanLabel }),
            {
                variant: 'demo',
                actionLabel: tSite('nav.download'),
                actionHref: getPageId() === 'home' ? '#download' : 'index.html#download',
                duration: 5500,
            },
        );
    }

    /* ----------------------------------------------------------------------
       Internationalization (All 33 Session Sniffer Languages + RTL)
       ---------------------------------------------------------------------- */

    var LOADED_LOCALES = {
        en: {
            app: {},
            site: DATA.enSite || {},
        },
    };
    var PENDING_LOCALE_CALLBACKS = {};
    var activeLang = DATA.defaultLanguage || 'en';
    var liveStatsState = {
        discordMembers: null,
        totalDownloads: null,
    };

    window.__ssRegisterLocale = function registerLocale(code, payload) {
        LOADED_LOCALES[code] = {
            app: (payload && payload.app) || {},
            site: (payload && payload.site) || {},
        };
        var waiters = PENDING_LOCALE_CALLBACKS[code];
        delete PENDING_LOCALE_CALLBACKS[code];
        if (Array.isArray(waiters)) {
            waiters.forEach(function notify(fn) { fn(); });
        }
    };

    function lookupLocaleTag(tag) {
        return LANG_LOWER_TO_CODE[tag] || (DATA.localeAliases && DATA.localeAliases[tag]) || null;
    }

    function normalizeLanguageCode(rawCode) {
        if (typeof rawCode !== 'string') {
            return null;
        }
        var cleaned = rawCode.trim().replace(/_/g, '-');
        if (!cleaned) {
            return null;
        }
        var lower = cleaned.toLowerCase();
        var exact = lookupLocaleTag(lower);
        if (exact) {
            return exact;
        }
        var parts = lower.split('-');
        for (var len = parts.length - 1; len > 0; len -= 1) {
            var matched = lookupLocaleTag(parts.slice(0, len).join('-'));
            if (matched) {
                return matched;
            }
        }
        return null;
    }

    function detectInitialLanguage() {
        try {
            var params = new URLSearchParams(window.location.search || '');
            var queryLang = normalizeLanguageCode(params.get('lang'));
            if (queryLang) {
                return queryLang;
            }
        } catch (_err) {
            /* Ignore URLSearchParams errors. */
        }

        try {
            var saved = normalizeLanguageCode(window.localStorage.getItem(STORAGE_LANG_KEY));
            if (saved) {
                return saved;
            }
        } catch (_err) {
            /* Ignore storage errors. */
        }

        var candidates = [];
        if (Array.isArray(navigator.languages)) {
            candidates = candidates.concat(navigator.languages);
        }
        if (navigator.language) {
            candidates.push(navigator.language);
        }
        for (var i = 0; i < candidates.length; i += 1) {
            var matched = normalizeLanguageCode(candidates[i]);
            if (matched) {
                return matched;
            }
        }
        return DATA.defaultLanguage || 'en';
    }

    function formatTemplate(template, vars) {
        if (!vars) {
            return template;
        }
        return String(template).replace(/\{([a-zA-Z0-9_]+)\}/g, function replaceVar(match, key) {
            return Object.prototype.hasOwnProperty.call(vars, key) ? String(vars[key]) : match;
        });
    }

    function hasSiteKey(key) {
        var active = LOADED_LOCALES[activeLang];
        return Boolean(
            (active && active.site && Object.prototype.hasOwnProperty.call(active.site, key))
            || (DATA.enSite && Object.prototype.hasOwnProperty.call(DATA.enSite, key))
        );
    }

    function tSite(key, vars) {
        var active = LOADED_LOCALES[activeLang];
        var raw = (active && active.site && active.site[key]) || (DATA.enSite && DATA.enSite[key]) || key;
        return formatTemplate(raw, vars);
    }

    function tApp(key, vars) {
        var active = LOADED_LOCALES[activeLang];
        var raw = (active && active.app && active.app[key]) || key;
        return formatTemplate(String(raw).replace(/&&/g, '&'), vars);
    }

    function ensureLocaleLoaded(code, callback) {
        if (LOADED_LOCALES[code]) {
            callback();
            return;
        }
        if (PENDING_LOCALE_CALLBACKS[code]) {
            PENDING_LOCALE_CALLBACKS[code].push(callback);
            return;
        }
        PENDING_LOCALE_CALLBACKS[code] = [callback];

        var script = document.createElement('script');
        var versionSuffix = DATA.assetVersion ? '?v=' + encodeURIComponent(DATA.assetVersion) : '';
        script.src = 'assets/i18n/' + encodeURIComponent(code) + '.js' + versionSuffix;
        script.async = true;
        script.onerror = function onLoadError() {
            var waiters = PENDING_LOCALE_CALLBACKS[code];
            delete PENDING_LOCALE_CALLBACKS[code];
            if (Array.isArray(waiters)) {
                waiters.forEach(function notify(fn) { fn(); });
            }
        };
        document.head.appendChild(script);
    }

    function setLanguage(code, options) {
        var normalized = normalizeLanguageCode(code) || (DATA.defaultLanguage || 'en');
        var opts = options || {};
        ensureLocaleLoaded(normalized, function afterLoad() {
            activeLang = LOADED_LOCALES[normalized] ? normalized : (DATA.defaultLanguage || 'en');
            if (!opts.skipSave) {
                try {
                    window.localStorage.setItem(STORAGE_LANG_KEY, activeLang);
                } catch (_err) {
                    /* Ignore storage restrictions. */
                }
            }
            applyLanguageToPage();
            if (opts.announce) {
                var meta = LANG_BY_CODE[activeLang];
                if (meta) {
                    showToast(meta.name);
                }
            }
        });
    }

    function applyLanguageToPage() {
        var meta = LANG_BY_CODE[activeLang] || { code: 'en', name: 'English', rtl: false };
        document.documentElement.setAttribute('lang', meta.code);
        document.documentElement.setAttribute('dir', meta.rtl ? 'rtl' : 'ltr');

        var pageMeta = PAGE_META_KEYS[getPageId()] || PAGE_META_KEYS.home;
        document.title = tSite(pageMeta.title);
        var metaDesc = document.querySelector('meta[name="description"]');
        if (metaDesc) {
            metaDesc.setAttribute('content', tSite(pageMeta.description));
        }

        var flagImg = document.getElementById('active-lang-flag');
        if (flagImg && meta.flag) {
            flagImg.src = 'assets/flags/' + meta.flag + '.png';
        }

        var codeBadge = document.getElementById('active-lang-code');
        if (codeBadge) {
            codeBadge.textContent = meta.code.toUpperCase();
        }

        document.querySelectorAll('[data-i18n]').forEach(function translateSiteNode(el) {
            var key = el.getAttribute('data-i18n');
            if (key && hasSiteKey(key)) {
                el.textContent = tSite(key);
            }
        });

        document.querySelectorAll('[data-i18n-app]').forEach(function translateAppNode(el) {
            var key = el.getAttribute('data-i18n-app');
            if (key) {
                el.textContent = tApp(key);
            }
        });

        document.querySelectorAll('[data-i18n-app-strip]').forEach(function translateStrippedAppNode(el) {
            var key = el.getAttribute('data-i18n-app-strip');
            if (key) {
                el.textContent = tApp(key).replace(/[:\uff1a \u00a0\u202f]+$/, '');
            }
        });

        document.querySelectorAll('[data-i18n-app-title]').forEach(function translateAppTitleNode(el) {
            var key = el.getAttribute('data-i18n-app-title');
            if (key) {
                el.setAttribute('title', tApp(key).replace(/[:\uff1a \u00a0\u202f]+$/, ''));
            }
        });

        document.querySelectorAll('[data-i18n-placeholder]').forEach(function translatePlaceholder(el) {
            var key = el.getAttribute('data-i18n-placeholder');
            if (key && hasSiteKey(key)) {
                el.setAttribute('placeholder', tSite(key));
            }
        });

        document.querySelectorAll('[data-i18n-title]').forEach(function translateTitle(el) {
            var key = el.getAttribute('data-i18n-title');
            if (key && hasSiteKey(key)) {
                var val = tSite(key);
                el.setAttribute('title', val);
                if (el.hasAttribute('aria-label')) {
                    el.setAttribute('aria-label', val);
                }
            }
        });

        var heroEyebrowLangs = document.getElementById('hero-eyebrow-langs');
        if (heroEyebrowLangs) {
            heroEyebrowLangs.textContent = tSite('hero.eyebrow_langs', { count: DATA.languagesCount });
        }

        if (liveStatsState.discordMembers !== null) {
            var statEl = document.getElementById('stat-discord-members');
            if (statEl) {
                statEl.textContent = tSite('hero.members_count', { count: formatNumber(liveStatsState.discordMembers) });
            }
        }
        if (liveStatsState.totalDownloads !== null) {
            var dlEl = document.getElementById('stat-total-downloads');
            if (dlEl) {
                dlEl.textContent = formatNumber(liveStatsState.totalDownloads) + '+';
            }
        }

        syncActiveThemeLabel();
        notifyClosePopups();
        applyOsRecommendation();
        buildThemeDropdown();
        updateThemeSelectionIndicators();
        renderLanguageDropdown();

        languageListeners.forEach(function invoke(fn) { fn(activeLang); });
    }

    /* ----------------------------------------------------------------------
       Inject Shared SVG Icon Sprite & Synced Static Metadata
       ---------------------------------------------------------------------- */

    function injectIconSprite() {
        var holder = document.createElement('div');
        holder.innerHTML = DATA.iconSprite;
        if (holder.firstChild) {
            document.body.insertBefore(holder.firstChild, document.body.firstChild);
        }
    }

    function formatProjectVersion(tagName, publishedAt) {
        var raw = String(tagName || '').trim();
        if (!raw) {
            return DATA.appVersion || DATA.version;
        }
        var plusIdx = raw.indexOf('+');
        var basePart = plusIdx >= 0 ? raw.slice(0, plusIdx) : raw;
        var localPart = plusIdx >= 0 ? raw.slice(plusIdx + 1) : '';
        var displayBase = /^v/i.test(basePart) ? 'v' + basePart.slice(1) : 'v' + basePart;
        var localMatch = /^(\d{4})(\d{2})(\d{2})\.(\d{1,4})$/.exec(localPart);
        if (localMatch) {
            var hhmm = localMatch[4].padStart(4, '0');
            return displayBase + ' - ' + localMatch[1] + '/' + localMatch[2] + '/' + localMatch[3] + ' (' + hhmm.slice(0, 2) + ':' + hhmm.slice(2, 4) + ')';
        }
        if (publishedAt) {
            var dt = new Date(publishedAt);
            if (!Number.isNaN(dt.getTime())) {
                var yyyy = dt.getUTCFullYear();
                var mm = String(dt.getUTCMonth() + 1).padStart(2, '0');
                var dd = String(dt.getUTCDate()).padStart(2, '0');
                var hh = String(dt.getUTCHours()).padStart(2, '0');
                var min = String(dt.getUTCMinutes()).padStart(2, '0');
                return displayBase + ' - ' + yyyy + '/' + mm + '/' + dd + ' (' + hh + ':' + min + ')';
            }
        }
        return displayBase;
    }

    function applyStaticMetadata() {
        document.querySelectorAll('[data-release-version]').forEach(function setVer(el) {
            el.textContent = DATA.version;
        });
        document.querySelectorAll('[data-app-version]').forEach(function setAppVer(el) {
            el.textContent = DATA.appVersion || DATA.version;
        });
        document.querySelectorAll('[data-languages-count]').forEach(function setLang(el) {
            el.textContent = String(DATA.languagesCount);
        });
        document.querySelectorAll('[data-themes-count]').forEach(function setThemeCount(el) {
            el.textContent = String(DATA.builtinThemes.length);
        });
    }

    /* ----------------------------------------------------------------------
       Theme Engine (6 Built-in Session Sniffer Themes)
       ---------------------------------------------------------------------- */

    var initialSlug = document.documentElement.getAttribute('data-theme') || DATA.defaultThemeSlug;
    if (!BUILTIN_BY_SLUG[initialSlug]) {
        initialSlug = DATA.defaultThemeSlug;
    }

    var themeState = {
        activeThemeSlug: initialSlug,
        activeTableIsLight: isLightColor(BUILTIN_BY_SLUG[initialSlug].colors.table || BUILTIN_BY_SLUG[initialSlug].colors.background),
    };

    function syncActiveThemeLabel() {
        var label = document.getElementById('active-theme-label');
        if (!label) {
            return;
        }
        if (BUILTIN_BY_SLUG[themeState.activeThemeSlug]) {
            label.textContent = tApp(BUILTIN_BY_SLUG[themeState.activeThemeSlug].name);
        }
    }

    function applyThemeColorsRuntime(colors) {
        var root = document.documentElement;
        var scheme = isLightColor(colors.background) ? 'light' : 'dark';
        root.setAttribute('data-scheme', scheme);
        root.style.setProperty('--ss-on-accent', bestOnColor(colors.accent));
        var metaTheme = document.querySelector('meta[name="theme-color"]');
        if (metaTheme) {
            metaTheme.setAttribute('content', colors.background);
        }
        themeState.activeTableIsLight = isLightColor(colors.table || colors.background);
    }

    function updateThemeSelectionIndicators() {
        document.querySelectorAll('.theme-option-btn').forEach(function markOpt(btn) {
            var match = btn.getAttribute('data-theme-slug') === themeState.activeThemeSlug;
            btn.classList.toggle('is-active', match);
            var icon = btn.querySelector('svg');
            if (icon) {
                icon.style.opacity = match ? '1' : '0';
            }
        });
    }

    function setBuiltinTheme(slug, options) {
        var theme = BUILTIN_BY_SLUG[slug];
        if (!theme) {
            return;
        }
        var opts = options || {};
        themeState.activeThemeSlug = slug;

        document.documentElement.setAttribute('data-theme', slug);
        applyThemeColorsRuntime(theme.colors);

        if (!opts.skipSave) {
            try {
                window.localStorage.setItem(STORAGE_THEME_KEY, slug);
            } catch (_err) {
                /* Ignore storage restrictions. */
            }
        }

        syncActiveThemeLabel();
        updateThemeSelectionIndicators();
        notifyThemeChange('builtin');
    }

    function buildThemeDropdown() {
        var list = document.getElementById('theme-dropdown-list');
        if (!list) {
            return;
        }
        list.innerHTML = '';

        DATA.builtinThemes.forEach(function addThemeOption(theme) {
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'theme-option-btn';
            btn.setAttribute('role', 'menuitem');
            btn.setAttribute('data-theme-slug', theme.slug);

            var left = document.createElement('span');
            left.className = 'theme-option-left';

            var swatch = document.createElement('span');
            swatch.className = 'theme-option-swatch';
            swatch.style.background = theme.colors.background;
            swatch.style.borderColor = theme.colors.border;
            var dot = document.createElement('span');
            dot.style.background = theme.colors.accent;
            swatch.appendChild(dot);

            var nameSpan = document.createElement('span');
            nameSpan.textContent = tApp(theme.name);

            left.appendChild(swatch);
            left.appendChild(nameSpan);
            btn.appendChild(left);

            var checkIcon = createIconSvg('check', 'icon-xs');
            checkIcon.style.opacity = theme.slug === themeState.activeThemeSlug ? '1' : '0';
            btn.appendChild(checkIcon);

            btn.addEventListener('click', function onSelectTheme() {
                setBuiltinTheme(theme.slug);
                closeThemeDropdown();
                showToast(tSite('nav.theme_applied', { name: tApp(theme.name) }));
            });

            list.appendChild(btn);
        });
    }

    /* ----------------------------------------------------------------------
       Navbar Language Switcher, Theme Dropdown & Mobile Drawer
       ---------------------------------------------------------------------- */

    function closeThemeDropdown() {
        var btn = document.getElementById('theme-menu-button');
        var dropdown = document.getElementById('theme-menu-dropdown');
        if (btn && dropdown) {
            dropdown.hidden = true;
            btn.setAttribute('aria-expanded', 'false');
        }
    }

    function closeLangDropdown() {
        var btn = document.getElementById('lang-menu-button');
        var dropdown = document.getElementById('lang-menu-dropdown');
        if (btn && dropdown) {
            dropdown.hidden = true;
            btn.setAttribute('aria-expanded', 'false');
        }
    }

    function renderLanguageDropdown(filterQuery) {
        var list = document.getElementById('lang-dropdown-list');
        if (!list) {
            return;
        }
        var q = (filterQuery || '').trim().toLowerCase();
        list.innerHTML = '';

        (DATA.languages || []).forEach(function addLangOpt(lang) {
            var flagCode = lang.flag || '';
            if (
                q
                && lang.name.toLowerCase().indexOf(q) === -1
                && lang.code.toLowerCase().indexOf(q) === -1
                && flagCode.toLowerCase().indexOf(q) === -1
            ) {
                return;
            }
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'lang-option-btn' + (lang.code === activeLang ? ' is-active' : '');
            btn.setAttribute('role', 'menuitem');
            btn.setAttribute('data-lang-code', lang.code);

            var leftSpan = document.createElement('span');
            leftSpan.className = 'lang-option-left';
            if (flagCode) {
                var optFlag = document.createElement('img');
                optFlag.className = 'lang-flag-img';
                optFlag.src = 'assets/flags/' + flagCode + '.png';
                optFlag.alt = '';
                optFlag.width = 18;
                optFlag.height = 12;
                optFlag.loading = 'lazy';
                leftSpan.appendChild(optFlag);
            }
            var nameSpan = document.createElement('span');
            nameSpan.className = 'lang-option-name';
            nameSpan.textContent = lang.name;
            leftSpan.appendChild(nameSpan);

            var metaSpan = document.createElement('span');
            metaSpan.className = 'lang-option-meta';
            if (lang.code === activeLang) {
                metaSpan.appendChild(createIconSvg('check', 'icon-xs'));
            }

            btn.appendChild(leftSpan);
            btn.appendChild(metaSpan);

            btn.addEventListener('click', function onSelectLang() {
                closeLangDropdown();
                setLanguage(lang.code, { announce: true });
            });

            list.appendChild(btn);
        });
    }

    function closeMobileNavDrawer() {
        var mobileToggle = document.getElementById('mobile-nav-toggle');
        var mobileDrawer = document.getElementById('mobile-nav-drawer');
        if (mobileDrawer) {
            mobileDrawer.hidden = true;
        }
        if (mobileToggle) {
            mobileToggle.setAttribute('aria-expanded', 'false');
        }
    }

    function openLanguageDropdown() {
        var btn = document.getElementById('lang-menu-button');
        var dropdown = document.getElementById('lang-menu-dropdown');
        var search = document.getElementById('lang-search-input');
        if (!btn || !dropdown) {
            return;
        }
        closeThemeDropdown();
        closeMobileNavDrawer();
        notifyClosePopups();
        dropdown.hidden = false;
        btn.setAttribute('aria-expanded', 'true');
        if (search) {
            search.value = '';
            renderLanguageDropdown('');
            search.focus();
        }
    }

    function initNavigationControls() {
        var langBtn = document.getElementById('lang-menu-button');
        var langDropdown = document.getElementById('lang-menu-dropdown');
        var langSearch = document.getElementById('lang-search-input');
        if (langBtn && langDropdown) {
            langBtn.addEventListener('click', function toggleLang(ev) {
                ev.stopPropagation();
                if (langDropdown.hidden) {
                    openLanguageDropdown();
                } else {
                    closeLangDropdown();
                }
            });
        }
        if (langSearch) {
            langSearch.addEventListener('input', function onFilterLang() {
                renderLanguageDropdown(langSearch.value);
            });
            langSearch.addEventListener('click', function keepOpen(ev) {
                ev.stopPropagation();
            });
        }

        var themeBtn = document.getElementById('theme-menu-button');
        var themeDropdown = document.getElementById('theme-menu-dropdown');
        if (themeBtn && themeDropdown) {
            themeBtn.addEventListener('click', function toggleDropdown(ev) {
                ev.stopPropagation();
                closeLangDropdown();
                closeMobileNavDrawer();
                notifyClosePopups();
                var willOpen = themeDropdown.hidden;
                themeDropdown.hidden = !willOpen;
                themeBtn.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
                if (willOpen) {
                    updateThemeSelectionIndicators();
                }
            });
        }

        var mobileToggle = document.getElementById('mobile-nav-toggle');
        var mobileDrawer = document.getElementById('mobile-nav-drawer');
        if (mobileToggle && mobileDrawer) {
            mobileToggle.addEventListener('click', function toggleDrawer(ev) {
                ev.stopPropagation();
                closeLangDropdown();
                closeThemeDropdown();
                var willOpen = mobileDrawer.hidden;
                mobileDrawer.hidden = !willOpen;
                mobileToggle.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
            });
            mobileDrawer.querySelectorAll('a').forEach(function closeOnLink(anchor) {
                anchor.addEventListener('click', closeMobileNavDrawer);
            });
        }

        document.addEventListener('click', function onGlobalClick(ev) {
            var langSwitcher = document.getElementById('nav-lang-switcher');
            if (langSwitcher && !langSwitcher.contains(ev.target)) {
                closeLangDropdown();
            }
            var switcher = document.getElementById('nav-theme-switcher');
            if (switcher && !switcher.contains(ev.target)) {
                closeThemeDropdown();
            }
            var navDrawer = document.getElementById('mobile-nav-drawer');
            var navBtn = document.getElementById('mobile-nav-toggle');
            if (navDrawer && !navDrawer.hidden && !navDrawer.contains(ev.target) && (!navBtn || !navBtn.contains(ev.target))) {
                closeMobileNavDrawer();
            }
        });

        document.addEventListener('keydown', function onKeyDown(ev) {
            if (ev.key === 'Escape') {
                hideRichTooltip();
                closeLangDropdown();
                closeThemeDropdown();
                closeMobileNavDrawer();
                notifyClosePopups();
            }
        });
    }

    /* ----------------------------------------------------------------------
       Rich Floating Tooltip Portal
       ---------------------------------------------------------------------- */

    function setRichTooltip(el, title, body, variant) {
        if (!el) {
            return;
        }
        if (!body) {
            el.removeAttribute('data-tip-title');
            el.removeAttribute('data-tip-body');
            el.removeAttribute('data-tip-variant');
            return;
        }
        el.setAttribute('data-tip-title', title || '');
        el.setAttribute('data-tip-body', body);
        el.setAttribute('data-tip-variant', variant || 'neutral');
    }

    var richTooltipState = {
        activeTarget: null,
        initialized: false,
    };

    function ensureRichTooltip() {
        var tip = document.getElementById('ss-rich-tooltip');
        if (!tip) {
            tip = document.createElement('div');
            tip.id = 'ss-rich-tooltip';
            tip.className = 'ss-tooltip';
            tip.setAttribute('role', 'tooltip');
            tip.setAttribute('aria-hidden', 'true');
            document.body.appendChild(tip);
        }
        var titleEl = document.getElementById('ss-tooltip-title');
        var bodyEl = document.getElementById('ss-tooltip-body');
        if (!titleEl || !bodyEl) {
            tip.innerHTML = '';
            var head = document.createElement('div');
            head.className = 'ss-tooltip-head';
            var dot = document.createElement('span');
            dot.className = 'ss-tooltip-dot';
            dot.setAttribute('aria-hidden', 'true');
            titleEl = document.createElement('strong');
            titleEl.className = 'ss-tooltip-title';
            titleEl.id = 'ss-tooltip-title';
            head.appendChild(dot);
            head.appendChild(titleEl);
            bodyEl = document.createElement('p');
            bodyEl.className = 'ss-tooltip-body';
            bodyEl.id = 'ss-tooltip-body';
            tip.appendChild(head);
            tip.appendChild(bodyEl);
        }
        return { tip: tip, titleEl: titleEl, bodyEl: bodyEl };
    }

    function getTooltipPortalHost(targetEl) {
        if (targetEl && typeof targetEl.closest === 'function') {
            var fullscreenStage = targetEl.closest('.ss-stage-shell.is-fullscreen');
            if (fullscreenStage) {
                return fullscreenStage;
            }
        }
        return document.body;
    }

    function hideRichTooltip() {
        var tip = document.getElementById('ss-rich-tooltip');
        richTooltipState.activeTarget = null;
        if (!tip) {
            return;
        }
        tip.classList.remove('is-visible');
        tip.setAttribute('aria-hidden', 'true');
        if (tip.parentNode && tip.parentNode !== document.body) {
            document.body.appendChild(tip);
        }
    }

    function positionRichTooltip(targetEl) {
        var tip = document.getElementById('ss-rich-tooltip');
        if (!tip || !targetEl) {
            return;
        }
        var host = getTooltipPortalHost(targetEl);
        if (tip.parentNode !== host) {
            host.appendChild(tip);
        }

        /* Reset coordinates before measuring so shrink-to-fit width isn't squeezed by prior placement. */
        tip.style.left = '0px';
        tip.style.top = '0px';

        var rawRect = targetEl.getBoundingClientRect();
        var tipWidth = tip.offsetWidth;
        var tipHeight = tip.offsetHeight;
        var margin = 10;
        var gap = 10;
        var vw = window.innerWidth || document.documentElement.clientWidth;
        var vh = window.innerHeight || document.documentElement.clientHeight;

        var boundsW = vw;
        var boundsH = vh;
        var rectLeft = rawRect.left;
        var rectTop = rawRect.top;
        var rectBottom = rawRect.bottom;
        var rectWidth = rawRect.width;

        if (host !== document.body) {
            var hostRect = host.getBoundingClientRect();
            var isRotated = host.classList.contains('is-rotated');
            boundsW = host.clientWidth || (isRotated ? vh : vw);
            boundsH = host.clientHeight || (isRotated ? vw : vh);
            if (isRotated) {
                /* Stage is rotated 90deg clockwise: local +x maps to viewport +y, local +y maps to viewport -x. */
                rectLeft = rawRect.top - hostRect.top;
                rectTop = hostRect.right - rawRect.right;
                rectBottom = hostRect.right - rawRect.left;
                rectWidth = rawRect.height;
            } else {
                rectLeft = rawRect.left - hostRect.left;
                rectTop = rawRect.top - hostRect.top;
                rectBottom = rawRect.bottom - hostRect.top;
                rectWidth = rawRect.width;
            }
        }

        var placement = 'top';
        var top = rectTop - tipHeight - gap;
        if (top < margin) {
            placement = 'bottom';
            top = rectBottom + gap;
            if (top + tipHeight > boundsH - margin) {
                top = Math.max(margin, boundsH - tipHeight - margin);
            }
        }

        var centerX = rectLeft + (rectWidth / 2);
        var left = centerX - (tipWidth / 2);
        if (left < margin) {
            left = margin;
        } else if (left + tipWidth > boundsW - margin) {
            left = Math.max(margin, boundsW - tipWidth - margin);
        }

        var arrowX = Math.max(16, Math.min(tipWidth - 16, centerX - left));
        tip.setAttribute('data-placement', placement);
        tip.style.setProperty('--tip-arrow-x', Math.round(arrowX) + 'px');
        tip.style.left = Math.round(left) + 'px';
        tip.style.top = Math.round(top) + 'px';
    }

    function showRichTooltip(targetEl) {
        if (!targetEl) {
            return;
        }
        var body = targetEl.getAttribute('data-tip-body');
        if (!body) {
            hideRichTooltip();
            return;
        }
        var parts = ensureRichTooltip();
        var host = getTooltipPortalHost(targetEl);
        if (parts.tip.parentNode !== host) {
            host.appendChild(parts.tip);
        }
        var title = targetEl.getAttribute('data-tip-title') || '';
        var variant = targetEl.getAttribute('data-tip-variant') || 'neutral';

        richTooltipState.activeTarget = targetEl;
        parts.tip.className = 'ss-tooltip ss-tooltip--' + variant + ' is-visible';
        parts.tip.setAttribute('aria-hidden', 'false');
        parts.titleEl.textContent = title;
        parts.bodyEl.textContent = body;
        positionRichTooltip(targetEl);
    }

    function syncRichTooltipOnScroll() {
        var target = richTooltipState.activeTarget;
        if (!target || !document.contains(target)) {
            hideRichTooltip();
            return;
        }
        var rect = target.getBoundingClientRect();
        var vw = window.innerWidth || document.documentElement.clientWidth;
        var vh = window.innerHeight || document.documentElement.clientHeight;
        if (
            rect.width === 0
            || rect.height === 0
            || rect.bottom < 0
            || rect.top > vh
            || rect.right < 0
            || rect.left > vw
        ) {
            hideRichTooltip();
            return;
        }
        var scrollClip = typeof target.closest === 'function'
            ? target.closest('.ss-table-scroll, .ss-stage-viewport')
            : null;
        if (scrollClip) {
            var clipRect = scrollClip.getBoundingClientRect();
            if (
                rect.right <= clipRect.left
                || rect.left >= clipRect.right
                || rect.bottom <= clipRect.top
                || rect.top >= clipRect.bottom
            ) {
                hideRichTooltip();
                return;
            }
        }
        positionRichTooltip(target);
    }

    function initRichTooltips() {
        if (richTooltipState.initialized) {
            return;
        }
        richTooltipState.initialized = true;
        ensureRichTooltip();

        function findTipTarget(node) {
            var el = node && node.nodeType === 1 ? node : (node && node.parentElement);
            if (!el || typeof el.closest !== 'function') {
                return null;
            }
            return el.closest('[data-tip-body]');
        }

        function handleEnter(ev) {
            var target = findTipTarget(ev.target);
            if (!target) {
                if (richTooltipState.activeTarget) {
                    hideRichTooltip();
                }
                return;
            }
            if (target !== richTooltipState.activeTarget) {
                showRichTooltip(target);
            }
        }

        function handleLeave(ev) {
            if (!richTooltipState.activeTarget) {
                return;
            }
            var nextTarget = findTipTarget(ev.relatedTarget);
            if (nextTarget !== richTooltipState.activeTarget) {
                if (nextTarget) {
                    showRichTooltip(nextTarget);
                } else {
                    hideRichTooltip();
                }
            }
        }

        document.addEventListener('pointerover', handleEnter);
        document.addEventListener('mouseover', handleEnter);
        document.addEventListener('pointerout', handleLeave);
        document.addEventListener('mouseout', handleLeave);

        document.addEventListener('focusin', function onTipFocus(ev) {
            var target = findTipTarget(ev.target);
            if (target) {
                showRichTooltip(target);
            }
        });

        document.addEventListener('focusout', function onTipBlur() {
            hideRichTooltip();
        });

        window.addEventListener('scroll', syncRichTooltipOnScroll, true);
        window.addEventListener('resize', syncRichTooltipOnScroll);
    }

    /* ----------------------------------------------------------------------
       OS Auto-Detection & Live GitHub / Discord Stats Hydration
       ---------------------------------------------------------------------- */

    function detectVisitorOs() {
        var ua = (navigator.userAgent || '').toLowerCase();
        var platform = (navigator.platform || '').toLowerCase();
        if (ua.indexOf('mac') !== -1 || platform.indexOf('mac') !== -1) {
            return 'macos';
        }
        if (ua.indexOf('linux') !== -1 && ua.indexOf('android') === -1) {
            return 'linux';
        }
        return 'windows';
    }

    function applyOsRecommendation() {
        var osKey = detectVisitorOs();
        var asset = RELEASE_ASSETS[osKey] || RELEASE_ASSETS.windows;

        var heroBtn = document.getElementById('hero-primary-download');
        var heroLabel = document.getElementById('hero-primary-download-label');
        if (heroBtn && heroLabel) {
            heroBtn.href = asset.url;
            heroLabel.textContent = tSite(asset.labelKey);
        }

        document.querySelectorAll('.download-card').forEach(function markCard(card) {
            var isMatch = card.getAttribute('data-os') === osKey;
            card.classList.toggle('is-recommended', isMatch);
            var badge = card.querySelector('.os-recommended-badge');
            if (badge) {
                badge.hidden = !isMatch;
            }
            var cta = card.querySelector('.btn');
            if (cta) {
                cta.classList.toggle('btn-primary', isMatch);
                cta.classList.toggle('btn-control', !isMatch);
            }
        });
    }

    function hydrateLiveCommunityStats() {
        /* GitHub Releases: latest version, binary sizes, and total downloads */
        window.fetch('https://api.github.com/repos/BUZZARDGTA/Session-Sniffer/releases?per_page=100')
            .then(function checkResp(resp) {
                if (!resp.ok) {
                    throw new Error('GitHub API status ' + resp.status);
                }
                return resp.json();
            })
            .then(function applyGitHub(releases) {
                if (!Array.isArray(releases) || releases.length === 0) {
                    return;
                }
                var totalDownloads = 0;
                releases.forEach(function sumRelease(rel) {
                    if (Array.isArray(rel.assets)) {
                        rel.assets.forEach(function sumAsset(a) {
                            totalDownloads += Number(a.download_count) || 0;
                        });
                    }
                });

                var totalEl = document.getElementById('stat-total-downloads');
                if (totalEl && totalDownloads > 0) {
                    liveStatsState.totalDownloads = totalDownloads;
                    totalEl.textContent = formatNumber(totalDownloads) + '+';
                }

                var latest = releases.find(function isStable(r) { return !r.draft && !r.prerelease; }) || releases[0];
                if (!latest) {
                    return;
                }

                if (latest.tag_name) {
                    var shortTag = String(latest.tag_name).split('+')[0];
                    var formattedAppVer = formatProjectVersion(latest.tag_name, latest.published_at);
                    document.querySelectorAll('[data-release-version]').forEach(function setTag(el) {
                        el.textContent = shortTag;
                    });
                    document.querySelectorAll('[data-app-version]').forEach(function setAppTag(el) {
                        el.textContent = formattedAppVer;
                    });
                }

                if (latest.published_at) {
                    var dateWrap = document.getElementById('release-date-wrap');
                    var dateText = document.getElementById('release-date-text');
                    var parsedDate = new Date(latest.published_at);
                    if (dateWrap && dateText && !Number.isNaN(parsedDate.getTime())) {
                        dateText.textContent = parsedDate.toLocaleDateString(activeLang || 'en-US', {
                            year: 'numeric',
                            month: 'short',
                            day: 'numeric',
                        });
                        dateWrap.hidden = false;
                    }
                }

                if (Array.isArray(latest.assets)) {
                    latest.assets.forEach(function applyAssetMeta(asset) {
                        var sizeEl = document.querySelector('[data-asset-size="' + asset.name + '"]');
                        if (sizeEl && typeof asset.size === 'number' && asset.size > 0) {
                            sizeEl.textContent = formatBytes(asset.size);
                        }

                        var rawDigest = typeof asset.digest === 'string' ? asset.digest.trim() : '';
                        var shaMatch = /^sha256:([0-9a-f]{64})$/i.exec(rawDigest);
                        if (!shaMatch) {
                            return;
                        }
                        var fullHash = shaMatch[1].toLowerCase();
                        var shortHash = fullHash.slice(0, 10) + '\u2026' + fullHash.slice(-10);
                        var hashWrap = document.querySelector('[data-asset-hash-wrap="' + asset.name + '"]');
                        var hashValEl = document.querySelector('[data-asset-hash="' + asset.name + '"]');
                        var hashCopyBtn = document.querySelector('[data-asset-hash-copy="' + asset.name + '"]');
                        if (!hashWrap || !hashValEl) {
                            return;
                        }

                        hashValEl.textContent = shortHash;
                        hashValEl.setAttribute('data-full-hash', fullHash);
                        setRichTooltip(hashValEl, 'SHA-256 · ' + asset.name, fullHash, 'full');
                        hashWrap.hidden = false;

                        function copyAssetHash() {
                            if (navigator.clipboard && navigator.clipboard.writeText) {
                                navigator.clipboard.writeText(fullHash).then(function copied() {
                                    if (hashCopyBtn) {
                                        var useEl = hashCopyBtn.querySelector('use');
                                        hashCopyBtn.classList.add('is-copied');
                                        if (useEl) {
                                            useEl.setAttribute('href', '#icon-check');
                                        }
                                        window.setTimeout(function restoreCopyIcon() {
                                            hashCopyBtn.classList.remove('is-copied');
                                            if (useEl) {
                                                useEl.setAttribute('href', '#icon-copy');
                                            }
                                        }, 1800);
                                    }
                                    showToast(tSite('download.toast_hash_copied', { file: asset.name }));
                                }).catch(function ignoreCopyErr() {
                                    showToast(fullHash);
                                });
                            } else {
                                showToast(fullHash);
                            }
                        }

                        hashValEl.addEventListener('click', copyAssetHash);
                        if (hashCopyBtn) {
                            hashCopyBtn.addEventListener('click', copyAssetHash);
                        }
                    });
                }
            })
            .catch(function ignoreOffline() {
                /* Keep synced fallback values when offline or rate-limited. */
            });

        /* Discord Invite API: live member count (only needed when hero stats tile exists) */
        var statEl = document.getElementById('stat-discord-members');
        if (!statEl) {
            return;
        }
        window.fetch('https://discord.com/api/v9/invites/hMZ7MsPX7G?with_counts=true')
            .then(function checkResp(resp) {
                if (!resp.ok) {
                    throw new Error('Discord API status ' + resp.status);
                }
                return resp.json();
            })
            .then(function applyDiscord(invite) {
                if (!invite || typeof invite.approximate_member_count !== 'number') {
                    return;
                }
                liveStatsState.discordMembers = invite.approximate_member_count;
                var formatted = formatNumber(invite.approximate_member_count);
                statEl.textContent = tSite('hero.members_count', { count: formatted });
            })
            .catch(function ignoreDiscordErr() {
                /* Keep fallback label when offline. */
            });
    }

    /* ----------------------------------------------------------------------
       FAQ Deep-Linking & Direct Link Copy
       ---------------------------------------------------------------------- */

    function copyTextToClipboard(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(text).then(function ok() {
                return true;
            }).catch(function fallbackCopy() {
                return legacyCopyText(text);
            });
        }
        return Promise.resolve(legacyCopyText(text));
    }

    function legacyCopyText(text) {
        try {
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.setAttribute('readonly', '');
            ta.style.position = 'fixed';
            ta.style.top = '-9999px';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            var copied = document.execCommand('copy');
            document.body.removeChild(ta);
            return Boolean(copied);
        } catch (_err) {
            return false;
        }
    }

    function initFaqAnchors() {
        var faqItems = document.querySelectorAll('details.faq-item[id]');
        if (!faqItems.length) {
            return;
        }

        var highlightTimer = null;
        var highlightedItem = null;
        var copyTimers = new WeakMap();

        function openFaqFromHash(options) {
            var opts = options || {};
            var rawHash = (window.location.hash || '').replace(/^#/, '');
            if (!rawHash) {
                return;
            }
            var decodedHash;
            try {
                decodedHash = decodeURIComponent(rawHash);
            } catch (_err) {
                decodedHash = rawHash;
            }
            var target = document.getElementById(decodedHash);
            if (!target || target.tagName !== 'DETAILS' || !target.classList.contains('faq-item')) {
                return;
            }

            target.open = true;

            if (!opts.realignOnly) {
                if (highlightedItem && highlightedItem !== target) {
                    highlightedItem.classList.remove('is-targeted');
                }
                target.classList.add('is-targeted');
                highlightedItem = target;
                if (highlightTimer) {
                    window.clearTimeout(highlightTimer);
                }
                highlightTimer = window.setTimeout(function clearHighlight() {
                    target.classList.remove('is-targeted');
                    if (highlightedItem === target) {
                        highlightedItem = null;
                    }
                    highlightTimer = null;
                }, 2400);
            }

            window.requestAnimationFrame(function scrollTarget() {
                target.scrollIntoView({
                    behavior: opts.instant ? 'auto' : 'smooth',
                    block: 'start',
                });
            });
        }

        document.querySelectorAll('[data-faq-copy]').forEach(function bindFaqCopy(btn) {
            btn.addEventListener('keydown', function preventSummaryKeyToggle(event) {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.stopPropagation();
                }
            });

            btn.addEventListener('click', function onCopyFaqLink(event) {
                event.preventDefault();
                event.stopPropagation();

                var faqId = btn.getAttribute('data-faq-copy');
                if (!faqId) {
                    return;
                }

                var shareUrlObj = new URL(window.location.href);
                shareUrlObj.hash = '#' + faqId;
                var shareUrl = shareUrlObj.toString();

                if (window.history && window.history.replaceState) {
                    window.history.replaceState(null, '', '#' + faqId);
                }

                copyTextToClipboard(shareUrl).then(function afterCopy(ok) {
                    var useEl = btn.querySelector('use');
                    btn.classList.add('is-copied');
                    if (useEl) {
                        useEl.setAttribute('href', '#icon-check');
                    }
                    var prevTimer = copyTimers.get(btn);
                    if (prevTimer) {
                        window.clearTimeout(prevTimer);
                    }
                    copyTimers.set(btn, window.setTimeout(function restoreLinkIcon() {
                        btn.classList.remove('is-copied');
                        if (useEl) {
                            useEl.setAttribute('href', '#icon-link');
                        }
                        copyTimers.delete(btn);
                    }, 1800));

                    showToast(ok ? tSite('faq.toast_link_copied') : shareUrl);
                });
            });
        });

        openFaqFromHash({ instant: true });
        window.addEventListener('hashchange', function onFaqHashChange() {
            openFaqFromHash({ instant: false });
        });

        /* Re-align once after the initial async locale finishes rendering if page height shifted. */
        var initialLangAligned = false;
        onLanguageChange(function realignFaqAfterInitialLang() {
            if (initialLangAligned) {
                return;
            }
            initialLangAligned = true;
            if (window.location.hash) {
                openFaqFromHash({ instant: true, realignOnly: true });
            }
        });
    }

    /* ----------------------------------------------------------------------
       Public Core API + Immediate Chrome Initialization
       ---------------------------------------------------------------------- */

    window.SSCore = {
        DATA: DATA,
        BUILTIN_BY_SLUG: BUILTIN_BY_SLUG,
        PPS_MAX_THRESHOLD: PPS_MAX_THRESHOLD,
        BPS_MAX_THRESHOLD: BPS_MAX_THRESHOLD,
        getPageId: getPageId,
        getActiveLang: function getActiveLang() { return activeLang; },
        tSite: tSite,
        tApp: tApp,
        formatTemplate: formatTemplate,
        formatNumber: formatNumber,
        formatBytes: formatBytes,
        formatUptime: formatUptime,
        formatElapsed: formatElapsed,
        formatDuration: formatDuration,
        formatProjectVersion: formatProjectVersion,
        hexToRgb: hexToRgb,
        isLightColor: isLightColor,
        bestOnColor: bestOnColor,
        getRateGradientColor: getRateGradientColor,
        createIconSvg: createIconSvg,
        showToast: showToast,
        showDemoFeatureToast: showDemoFeatureToast,
        setRichTooltip: setRichTooltip,
        hideRichTooltip: hideRichTooltip,
        getThemeState: function getThemeState() { return themeState; },
        setBuiltinTheme: setBuiltinTheme,
        closeThemeDropdown: closeThemeDropdown,
        closeLangDropdown: closeLangDropdown,
        closeMobileNavDrawer: closeMobileNavDrawer,
        openLanguageDropdown: openLanguageDropdown,
        onLanguageChange: onLanguageChange,
        onThemeChange: onThemeChange,
        onClosePopups: onClosePopups,
    };

    injectIconSprite();
    applyStaticMetadata();
    buildThemeDropdown();
    setBuiltinTheme(themeState.activeThemeSlug, { skipSave: true });

    initNavigationControls();
    initRichTooltips();

    /* Run initial translation & live hydration after deferred page scripts register hooks. */
    function finishBootstrap() {
        applyOsRecommendation();
        renderLanguageDropdown();
        initFaqAnchors();
        setLanguage(detectInitialLanguage(), { skipSave: true });
        hydrateLiveCommunityStats();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', finishBootstrap, { once: true });
    } else {
        window.setTimeout(finishBootstrap, 0);
    }
}());
