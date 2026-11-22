/* Restore saved theme (built-in or custom) and RTL direction before first paint to prevent flash. */
(function initSavedPreferences() {
    var HEX_RE = /^#[0-9a-f]{6}$/i;

    function hexToRgb(hex) {
        var clean = hex.slice(1);
        var num = parseInt(clean, 16);
        return [(num >> 16) & 255, (num >> 8) & 255, num & 255];
    }

    function isLight(hex) {
        var rgb = hexToRgb(hex);
        return (0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2]) > 140;
    }

    function bestOnColor(bgHex) {
        var rgb = hexToRgb(bgHex).map(function linearize(channel) {
            var v = channel / 255;
            return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
        });
        var luminance = 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
        return (1.05 / (luminance + 0.05)) >= 3.8 ? '#ffffff' : '#0b0d10';
    }

    try {
        var root = document.documentElement;
        var savedTheme = window.localStorage.getItem('ss_website_theme');
        if (savedTheme && /^[a-z0-9-]+$/.test(savedTheme)) {
            root.setAttribute('data-theme', savedTheme);
        }

        var rawCustom = window.localStorage.getItem('ss_website_custom_theme');
        if (rawCustom) {
            var parsed = JSON.parse(rawCustom);
            if (parsed && parsed.colors && typeof parsed.colors === 'object') {
                var keys = Object.keys(parsed.colors);
                var applied = 0;
                for (var i = 0; i < keys.length; i += 1) {
                    var key = keys[i];
                    var val = parsed.colors[key];
                    if (/^[a-z0-9_]+$/.test(key) && typeof val === 'string' && HEX_RE.test(val)) {
                        var cssKey = key.replace(/_/g, '-');
                        var rgb = hexToRgb(val);
                        root.style.setProperty('--ss-' + cssKey, val.toLowerCase());
                        root.style.setProperty('--ss-' + cssKey + '-rgb', rgb.join(', '));
                        applied += 1;
                    }
                }
                if (applied > 0) {
                    root.setAttribute('data-custom-theme', 'true');
                    if (typeof parsed.colors.background === 'string' && HEX_RE.test(parsed.colors.background)) {
                        root.setAttribute('data-scheme', isLight(parsed.colors.background) ? 'light' : 'dark');
                    }
                    if (typeof parsed.colors.accent === 'string' && HEX_RE.test(parsed.colors.accent)) {
                        root.style.setProperty('--ss-on-accent', bestOnColor(parsed.colors.accent));
                    }
                }
            }
        }

        var params = new URLSearchParams(window.location.search || '');
        var lang = params.get('lang') || window.localStorage.getItem('ss_website_lang') || '';
        if (lang && /^[a-zA-Z0-9-]+$/.test(lang)) {
            root.setAttribute('lang', lang);
            var lower = lang.toLowerCase();
            if (lower === 'ar' || lower === 'fa' || lower === 'he') {
                root.setAttribute('dir', 'rtl');
            }
        }
    } catch (_err) {
        /* Storage unavailable; fall back to defaults. */
    }
}());
