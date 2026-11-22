/* Restore saved built-in theme and RTL direction before first paint to prevent flash. */
(function initSavedPreferences() {
    try {
        var root = document.documentElement;
        var savedTheme = window.localStorage.getItem('ss_website_theme');
        if (savedTheme && /^[a-z0-9-]+$/.test(savedTheme)) {
            root.setAttribute('data-theme', savedTheme);
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
