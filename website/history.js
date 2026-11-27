/* ==========================================================================
   Session Sniffer Project History & Release Archive Controller (history.html)
   - Interactive 5-era visual evolution showcase & fullscreen screenshot lightbox
   - Searchable version-by-version release ledger & 163-tag Git archive
   ========================================================================== */

(function initSessionSnifferHistory() {
    'use strict';

    var Core = window.SSCore;
    if (!Core || !document.getElementById('history-era-stepper')) {
        return;
    }

    var DATA = Core.DATA;
    var tSite = Core.tSite;
    var formatNumber = Core.formatNumber;
    var createIconSvg = Core.createIconSvg;

    /* ----------------------------------------------------------------------
       5. Project History, Release Ledger & Screenshot Lightbox (2021 - 2026)
       ---------------------------------------------------------------------- */

    var HISTORY_ERAS = [
        {
            id: 'era1',
            year: '2021',
            shortVer: 'v1.0 → v2.2.4',
            shotTitle: 'PS3_Blacklist_Sniffer.bat',
            img: 'assets/history/2021-ps3-blacklist-sniffer.png',
            titleKey: 'history.era1_title',
            badgeKey: 'history.era1_badge',
            periodKey: 'history.era1_period',
            summaryKey: 'history.era1_summary',
            captionKey: 'history.era1_caption',
            highlightKeys: ['history.era1_h1', 'history.era1_h2', 'history.era1_h3'],
            tech: ['Windows Batch', 'TShark', 'PSN Usernames', 'Blacklist.ini', 'webMAN MOD'],
            links: [
                {
                    labelKey: 'history.era_view_repo',
                    url: 'https://github.com/Illegal-Services/PS3-Blacklist-Sniffer',
                    icon: 'github',
                },
            ],
        },
        {
            id: 'era2',
            year: '2023',
            shortVer: 'v1.0.0 → v1.0.6',
            shotTitle: 'GTA_V_Session_Sniffer.py',
            img: 'assets/history/2023-tui-v1-0.png',
            titleKey: 'history.era2_title',
            badgeKey: 'history.era2_badge',
            periodKey: 'history.era2_period',
            summaryKey: 'history.era2_summary',
            summaryLinks: {
                grub4k: {
                    label: 'Grub4K',
                    url: 'https://github.com/Grub4K',
                },
            },
            captionKey: 'history.era2_caption',
            highlightKeys: ['history.era2_h1', 'history.era2_h2', 'history.era2_h3'],
            tech: ['Python Console', 'Npcap / TShark', 'GeoLite2', 'PC & Consoles'],
            links: [
                {
                    labelKey: 'history.era_view_release',
                    url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.0.0',
                    icon: 'external-link',
                },
                {
                    labelKey: 'history.era_view_repo',
                    url: 'https://github.com/Illegal-Services/PC-Blacklist-Sniffer',
                    icon: 'github',
                },
            ],
        },
        {
            id: 'era3',
            year: '2024',
            shortVer: 'v1.1.0 → v1.2.9',
            shotTitle: 'GTA V Session Sniffer v1.1.8',
            img: 'assets/history/2024-tui-v1-1-8.png',
            titleKey: 'history.era3_title',
            badgeKey: 'history.era3_badge',
            periodKey: 'history.era3_period',
            summaryKey: 'history.era3_summary',
            captionKey: 'history.era3_caption',
            highlightKeys: ['history.era3_h1', 'history.era3_h2', 'history.era3_h3'],
            tech: ['Console Tables', 'Auto GeoLite2', 'Local Network Scan', 'VPN / Hosting', 'Discord Status'],
            links: [
                {
                    labelKey: 'history.era_view_release',
                    url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.2.0',
                    icon: 'external-link',
                },
            ],
        },
        {
            id: 'era4',
            year: '2025',
            shortVer: 'v1.3.0 → v1.4.3',
            shotTitle: 'Session Sniffer v1.3.0',
            img: 'assets/history/2025-gui-v1-3-pyqt6.png',
            titleKey: 'history.era4_title',
            badgeKey: 'history.era4_badge',
            periodKey: 'history.era4_period',
            summaryKey: 'history.era4_summary',
            captionKey: 'history.era4_caption',
            highlightKeys: ['history.era4_h1', 'history.era4_h2', 'history.era4_h3'],
            tech: ['PyQt6 + QDarkStyle', 'Standalone .exe', 'Ping Tools', 'Voice Alerts', 'Detailed Logs'],
            links: [
                {
                    labelKey: 'history.era_view_release',
                    url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.3.0',
                    icon: 'external-link',
                },
            ],
        },
        {
            id: 'era5',
            year: '2026',
            shortVer: 'v1.5.0',
            shotTitle: 'Session Sniffer v1.5.0',
            img: 'assets/history/2026-gui-v1-5-pyside6.png',
            titleKey: 'history.era5_title',
            badgeKey: 'history.era5_badge',
            periodKey: 'history.era5_period',
            summaryKey: 'history.era5_summary',
            captionKey: 'history.era5_caption',
            highlightKeys: ['history.era5_h1', 'history.era5_h2', 'history.era5_h3'],
            tech: ['PySide6', 'Native Packet Capture', 'Win · Linux · macOS', '33 Languages', '6 Themes', 'Web Dashboard'],
            links: [
                {
                    labelKey: 'history.era_try_live',
                    url: '/demo',
                    icon: 'circle-play',
                    primary: true,
                    internal: true,
                },
                {
                    labelKey: 'history.era_view_release',
                    url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.5.0%2B20261121.1136',
                    icon: 'external-link',
                },
            ],
        },
    ];

    var HISTORY_MILESTONES = [
        {
            series: 'v1.5',
            version: 'v1.5.0',
            isoDate: '2026-11-21',
            badgeType: 'latest',
            descKey: 'history.v_1_5_0',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.5.0%2B20261121.1136',
        },
        {
            series: 'v1.4',
            version: 'v1.4.3',
            isoDate: '2025-12-14',
            badgeType: 'minor',
            descKey: 'history.v_1_4_3',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.4.3%2B20251214.0958',
        },
        {
            series: 'v1.4',
            version: 'v1.4.2',
            isoDate: '2025-11-23',
            badgeType: 'minor',
            descKey: 'history.v_1_4_2',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.4.2%2B20251123.1721',
        },
        {
            series: 'v1.4',
            version: 'v1.4.1',
            isoDate: '2025-11-02',
            badgeType: 'minor',
            descKey: 'history.v_1_4_1',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.4.1%2B20251102.2013',
        },
        {
            series: 'v1.4',
            version: 'v1.4.0',
            isoDate: '2025-10-02',
            badgeType: 'major',
            descKey: 'history.v_1_4_0',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.4.0%2B20251002.1806',
        },
        {
            series: 'v1.3',
            version: 'v1.3.9',
            isoDate: '2025-08-22',
            badgeType: 'minor',
            descKey: 'history.v_1_3_9',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.3.9%2B20250822.0832',
        },
        {
            series: 'v1.3',
            version: 'v1.3.8',
            isoDate: '2025-07-18',
            badgeType: 'minor',
            descKey: 'history.v_1_3_8',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.3.8.post2%2B20250718.1117',
        },
        {
            series: 'v1.3',
            version: 'v1.3.7',
            isoDate: '2025-05-22',
            badgeType: 'minor',
            descKey: 'history.v_1_3_7',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.3.7post6%2B20250522.1808',
        },
        {
            series: 'v1.3',
            version: 'v1.3.3 – v1.3.6',
            isoDate: '2025-03-09',
            badgeType: 'minor',
            descKey: 'history.v_1_3_3',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.3.3',
        },
        {
            series: 'v1.3',
            version: 'v1.3.0',
            isoDate: '2025-01-06',
            badgeType: 'major',
            descKey: 'history.v_1_3_0',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.3.0',
        },
        {
            series: 'v1.2',
            version: 'v1.2.0 – v1.2.9',
            isoDate: '2024-11-21',
            badgeType: 'major',
            descKey: 'history.v_1_2_0',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.2.0',
        },
        {
            series: 'v1.1',
            version: 'v1.1.6 – v1.1.9',
            isoDate: '2024-10-18',
            badgeType: 'minor',
            descKey: 'history.v_1_1_6',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.1.6',
        },
        {
            series: 'v1.1',
            version: 'v1.1.0',
            isoDate: '2024-03-31',
            badgeType: 'major',
            descKey: 'history.v_1_1_0',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.1.0',
        },
        {
            series: 'v1.0',
            version: 'v1.0.4 – v1.0.6',
            isoDate: '2024-02-18',
            badgeType: 'minor',
            descKey: 'history.v_1_0_4',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.0.4',
        },
        {
            series: 'v1.0',
            version: 'v1.0.0',
            isoDate: '2023-01-10',
            badgeType: 'major',
            descKey: 'history.v_1_0_0',
            url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/v1.0.0',
        },
        {
            series: 'legacy',
            version: 'PC v1.0.0',
            isoDate: '2023-01-10',
            badgeType: 'legacy',
            descKey: 'history.v_pc',
            url: 'https://github.com/Illegal-Services/PC-Blacklist-Sniffer',
        },
        {
            series: 'legacy',
            version: 'PS3 v1.0 → v2.2.4',
            isoDate: '2021-11-30',
            badgeType: 'legacy',
            descKey: 'history.v_ps3',
            url: 'https://github.com/Illegal-Services/PS3-Blacklist-Sniffer',
        },
    ];

    var HISTORY_SERIES_FILTERS = [
        { key: 'all', labelKey: 'history.filter_all' },
        { key: 'v1.5', label: 'v1.5' },
        { key: 'v1.4', label: 'v1.4' },
        { key: 'v1.3', label: 'v1.3' },
        { key: 'v1.2', label: 'v1.2' },
        { key: 'v1.1', label: 'v1.1' },
        { key: 'v1.0', label: 'v1.0' },
        { key: 'legacy', labelKey: 'history.filter_legacy' },
    ];

    var HISTORY_BADGE_MAP = {
        latest: { cls: 'badge-success', key: 'history.badge_latest' },
        major: { cls: 'badge-accent', key: 'history.badge_major' },
        minor: { cls: 'badge-muted', key: 'history.badge_minor' },
        legacy: { cls: 'badge-looky', key: 'history.badge_legacy' },
    };

    var historyState = {
        activeEraIndex: 0,
        activeSeries: 'all',
        searchQuery: '',
        allTagsOpen: false,
        lightboxOpen: false,
        lastFocusedBeforeLightbox: null,
    };

    function formatHistoryDate(isoDate) {
        if (!isoDate) {
            return '';
        }
        try {
            var dt = new Date(isoDate + 'T12:00:00Z');
            if (!Number.isNaN(dt.getTime())) {
                return dt.toLocaleDateString(Core.getActiveLang() || 'en-US', {
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric',
                    timeZone: 'UTC',
                });
            }
        } catch (_err) {
            /* Fall back to ISO date string on unsupported Intl locale tags. */
        }
        return isoDate;
    }

    function updateHistoryStatsAndCopy() {
        var hist = DATA.history || {};
        var totalCommits = typeof hist.totalCommits === 'number' && hist.totalCommits > 0 ? hist.totalCommits : 3405;
        var totalTags = typeof hist.totalTags === 'number' && hist.totalTags > 0 ? hist.totalTags : 163;

        var commitsEl = document.getElementById('history-stat-commits');
        if (commitsEl) {
            commitsEl.textContent = formatNumber(totalCommits) + '+';
        }
        var tagsEl = document.getElementById('history-stat-tags');
        if (tagsEl) {
            tagsEl.textContent = formatNumber(totalTags);
        }

        var subtitleEl = document.getElementById('history-releases-subtitle');
        if (subtitleEl) {
            subtitleEl.textContent = tSite('history.releases_subtitle', {
                version: DATA.version || 'v1.5.0',
                tags: formatNumber(totalTags),
            });
        }

        var toggleLabel = document.getElementById('history-all-tags-toggle-label');
        if (toggleLabel) {
            toggleLabel.textContent = historyState.allTagsOpen
                ? tSite('history.all_tags_toggle_hide')
                : tSite('history.all_tags_toggle_show', { count: formatNumber(totalTags) });
        }
    }

    function renderHistoryEraStepper() {
        var stepper = document.getElementById('history-era-stepper');
        if (!stepper) {
            return;
        }
        stepper.innerHTML = '';

        HISTORY_ERAS.forEach(function addEraTab(era, idx) {
            var isActive = idx === historyState.activeEraIndex;
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'history-era-tab' + (isActive ? ' is-active' : '');
            btn.setAttribute('role', 'tab');
            btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
            btn.setAttribute('tabindex', isActive ? '0' : '-1');

            var top = document.createElement('div');
            top.className = 'history-era-tab-top';

            var yearEl = document.createElement('span');
            yearEl.className = 'history-era-tab-year';
            yearEl.textContent = era.year;

            var dot = document.createElement('span');
            dot.className = 'history-era-tab-dot';
            dot.setAttribute('aria-hidden', 'true');

            top.appendChild(yearEl);
            top.appendChild(dot);

            var nameEl = document.createElement('span');
            nameEl.className = 'history-era-tab-name';
            nameEl.textContent = tSite(era.titleKey);

            var techEl = document.createElement('span');
            techEl.className = 'history-era-tab-tech';
            techEl.setAttribute('dir', 'ltr');
            techEl.textContent = era.shortVer;

            btn.appendChild(top);
            btn.appendChild(nameEl);
            btn.appendChild(techEl);

            btn.addEventListener('click', function onSelectEra() {
                setHistoryEra(idx);
            });

            btn.addEventListener('keydown', function onEraTabKey(ev) {
                var isRtl = document.documentElement.getAttribute('dir') === 'rtl';
                var nextIdx = null;
                if (ev.key === 'ArrowRight') {
                    nextIdx = isRtl ? idx - 1 : idx + 1;
                } else if (ev.key === 'ArrowLeft') {
                    nextIdx = isRtl ? idx + 1 : idx - 1;
                } else if (ev.key === 'Home') {
                    nextIdx = 0;
                } else if (ev.key === 'End') {
                    nextIdx = HISTORY_ERAS.length - 1;
                }
                if (nextIdx !== null) {
                    ev.preventDefault();
                    var bounded = Math.max(0, Math.min(HISTORY_ERAS.length - 1, nextIdx));
                    setHistoryEra(bounded);
                    var tabs = stepper.querySelectorAll('.history-era-tab');
                    if (tabs[bounded]) {
                        tabs[bounded].focus();
                    }
                }
            });

            stepper.appendChild(btn);
        });
    }

    function renderTextWithLinks(container, text, linkMap) {
        container.textContent = '';
        if (!linkMap) {
            container.textContent = text;
            return;
        }
        var parts = String(text).split(/(\{[a-zA-Z0-9_]+\})/g);
        parts.forEach(function appendPart(part) {
            if (!part) {
                return;
            }
            var match = /^\{([a-zA-Z0-9_]+)\}$/.exec(part);
            var cfg = match && Object.prototype.hasOwnProperty.call(linkMap, match[1]) ? linkMap[match[1]] : null;
            if (cfg) {
                var a = document.createElement('a');
                a.href = cfg.url;
                a.className = 'history-inline-link';
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
                a.setAttribute('dir', 'ltr');
                a.textContent = cfg.label;
                container.appendChild(a);
            } else {
                container.appendChild(document.createTextNode(part));
            }
        });
    }

    function renderHistoryEraStage() {
        var era = HISTORY_ERAS[historyState.activeEraIndex] || HISTORY_ERAS[0];
        if (!era) {
            return;
        }

        var shotTitle = document.getElementById('history-era-shot-title');
        if (shotTitle) {
            shotTitle.textContent = era.shotTitle;
        }

        var shotVer = document.getElementById('history-era-shot-ver');
        if (shotVer) {
            shotVer.textContent = era.shortVer;
        }

        var img = document.getElementById('history-era-img');
        var captionText = tSite(era.captionKey);
        if (img) {
            if (img.getAttribute('src') !== era.img) {
                img.src = era.img;
            }
            img.alt = captionText;
        }

        var shotBtn = document.getElementById('history-era-shot-btn');
        if (shotBtn) {
            shotBtn.title = tSite('history.era_screenshot_hint');
            shotBtn.setAttribute('aria-label', tSite('history.era_view_screenshot') + ' — ' + tSite(era.titleKey));
        }

        var captionEl = document.getElementById('history-era-caption');
        if (captionEl) {
            captionEl.textContent = captionText;
        }

        var badgeEl = document.getElementById('history-era-badge');
        if (badgeEl) {
            badgeEl.textContent = tSite(era.badgeKey);
        }

        var periodEl = document.getElementById('history-era-period');
        if (periodEl) {
            periodEl.textContent = tSite(era.periodKey);
        }

        var titleEl = document.getElementById('history-era-title');
        if (titleEl) {
            titleEl.textContent = tSite(era.titleKey);
        }

        var summaryEl = document.getElementById('history-era-summary');
        if (summaryEl) {
            renderTextWithLinks(summaryEl, tSite(era.summaryKey), era.summaryLinks);
        }

        var highlightsEl = document.getElementById('history-era-highlights');
        if (highlightsEl) {
            highlightsEl.innerHTML = '';
            era.highlightKeys.forEach(function addHighlight(hKey) {
                var li = document.createElement('li');
                li.appendChild(createIconSvg('check', 'icon-xs'));
                var txt = document.createElement('span');
                txt.textContent = tSite(hKey);
                li.appendChild(txt);
                highlightsEl.appendChild(li);
            });
        }

        var tagsEl = document.getElementById('history-era-tags');
        if (tagsEl) {
            tagsEl.innerHTML = '';
            era.tech.forEach(function addTechChip(label) {
                var chip = document.createElement('span');
                chip.className = 'history-tech-chip';
                chip.textContent = label;
                tagsEl.appendChild(chip);
            });
        }

        var linksEl = document.getElementById('history-era-links');
        if (linksEl) {
            linksEl.innerHTML = '';
            era.links.forEach(function addEraLink(linkCfg) {
                var a = document.createElement('a');
                a.href = linkCfg.url;
                a.className = 'btn btn-sm ' + (linkCfg.primary ? 'btn-primary' : 'btn-control');
                if (!linkCfg.internal) {
                    a.target = '_blank';
                    a.rel = 'noopener noreferrer';
                }
                a.appendChild(createIconSvg(linkCfg.icon || 'external-link', 'icon-xs'));
                var labelSpan = document.createElement('span');
                labelSpan.textContent = tSite(linkCfg.labelKey);
                a.appendChild(labelSpan);
                linksEl.appendChild(a);
            });
        }

        var prevBtn = document.getElementById('history-era-prev');
        var nextBtn = document.getElementById('history-era-next');
        if (prevBtn) {
            prevBtn.disabled = historyState.activeEraIndex <= 0;
        }
        if (nextBtn) {
            nextBtn.disabled = historyState.activeEraIndex >= HISTORY_ERAS.length - 1;
        }
    }

    function renderHistoryLightbox() {
        var era = HISTORY_ERAS[historyState.activeEraIndex] || HISTORY_ERAS[0];
        if (!era) {
            return;
        }
        var yearEl = document.getElementById('history-lightbox-year');
        var captionEl = document.getElementById('history-lightbox-caption');
        var imgEl = document.getElementById('history-lightbox-img');
        var prevBtn = document.getElementById('history-lightbox-prev');
        var nextBtn = document.getElementById('history-lightbox-next');
        var closeBtn = document.getElementById('history-lightbox-close');
        var captionText = tSite(era.captionKey);

        if (yearEl) {
            yearEl.textContent = era.year + ' · ' + era.shortVer;
        }
        if (captionEl) {
            captionEl.textContent = captionText;
        }
        if (imgEl) {
            imgEl.src = era.img;
            imgEl.alt = captionText;
        }
        if (prevBtn) {
            prevBtn.disabled = historyState.activeEraIndex <= 0;
            prevBtn.setAttribute('aria-label', tSite('history.lightbox_prev'));
        }
        if (nextBtn) {
            nextBtn.disabled = historyState.activeEraIndex >= HISTORY_ERAS.length - 1;
            nextBtn.setAttribute('aria-label', tSite('history.lightbox_next'));
        }
        if (closeBtn) {
            closeBtn.setAttribute('aria-label', tSite('history.lightbox_close'));
        }
    }

    function setHistoryEra(idx) {
        var clamped = Math.max(0, Math.min(HISTORY_ERAS.length - 1, idx));
        historyState.activeEraIndex = clamped;
        renderHistoryEraStepper();
        renderHistoryEraStage();
        if (historyState.lightboxOpen) {
            renderHistoryLightbox();
        }
    }

    function stepHistoryEra(delta) {
        setHistoryEra(historyState.activeEraIndex + delta);
    }

    function openHistoryLightbox() {
        var overlay = document.getElementById('history-lightbox');
        if (!overlay) {
            return;
        }
        historyState.lastFocusedBeforeLightbox = document.activeElement;
        historyState.lightboxOpen = true;
        renderHistoryLightbox();
        overlay.hidden = false;
        var closeBtn = document.getElementById('history-lightbox-close');
        if (closeBtn) {
            closeBtn.focus();
        }
    }

    function closeHistoryLightbox() {
        if (!historyState.lightboxOpen) {
            return;
        }
        var overlay = document.getElementById('history-lightbox');
        if (overlay) {
            overlay.hidden = true;
        }
        historyState.lightboxOpen = false;
        if (historyState.lastFocusedBeforeLightbox && typeof historyState.lastFocusedBeforeLightbox.focus === 'function') {
            historyState.lastFocusedBeforeLightbox.focus();
        }
        historyState.lastFocusedBeforeLightbox = null;
    }

    function renderHistoryFilterBar() {
        var bar = document.getElementById('history-filter-bar');
        if (!bar) {
            return;
        }
        bar.innerHTML = '';

        var counts = { all: HISTORY_MILESTONES.length };
        HISTORY_MILESTONES.forEach(function countMilestone(m) {
            counts[m.series] = (counts[m.series] || 0) + 1;
        });

        HISTORY_SERIES_FILTERS.forEach(function addFilterPill(cfg) {
            var isActive = historyState.activeSeries === cfg.key;
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'history-filter-pill' + (isActive ? ' is-active' : '');
            btn.setAttribute('role', 'tab');
            btn.setAttribute('aria-selected', isActive ? 'true' : 'false');

            var labelSpan = document.createElement('span');
            labelSpan.textContent = cfg.labelKey ? tSite(cfg.labelKey) : cfg.label;
            btn.appendChild(labelSpan);

            var countSpan = document.createElement('span');
            countSpan.className = 'history-filter-count';
            countSpan.textContent = String(counts[cfg.key] || 0);
            btn.appendChild(countSpan);

            btn.addEventListener('click', function onSelectSeries() {
                historyState.activeSeries = cfg.key;
                renderHistoryFilterBar();
                renderHistoryReleaseList();
                renderHistoryTagsCloud();
            });

            bar.appendChild(btn);
        });
    }

    function renderHistoryReleaseList() {
        var list = document.getElementById('history-release-list');
        if (!list) {
            return;
        }
        list.innerHTML = '';

        var q = historyState.searchQuery.trim().toLowerCase();
        var filtered = HISTORY_MILESTONES.filter(function matchMilestone(item) {
            if (historyState.activeSeries !== 'all' && item.series !== historyState.activeSeries) {
                return false;
            }
            if (!q) {
                return true;
            }
            var desc = tSite(item.descKey).toLowerCase();
            var formattedDate = formatHistoryDate(item.isoDate).toLowerCase();
            return (
                item.version.toLowerCase().indexOf(q) !== -1
                || item.series.toLowerCase().indexOf(q) !== -1
                || item.isoDate.toLowerCase().indexOf(q) !== -1
                || formattedDate.indexOf(q) !== -1
                || desc.indexOf(q) !== -1
            );
        });

        if (filtered.length === 0) {
            var empty = document.createElement('div');
            empty.className = 'history-empty-state';
            empty.textContent = tSite('history.empty_filter');
            list.appendChild(empty);
            return;
        }

        filtered.forEach(function renderItem(item) {
            var badgeInfo = HISTORY_BADGE_MAP[item.badgeType] || HISTORY_BADGE_MAP.minor;
            var card = document.createElement('article');
            card.className = 'history-release-item' + (item.badgeType === 'latest' ? ' is-latest' : '');

            var verCol = document.createElement('div');
            verCol.className = 'history-release-vercol';

            var verRow = document.createElement('div');
            verRow.className = 'history-release-verrow';

            var verSpan = document.createElement('span');
            verSpan.className = 'history-release-version';
            verSpan.setAttribute('dir', 'ltr');
            verSpan.textContent = item.version;

            var badgeSpan = document.createElement('span');
            badgeSpan.className = 'badge ' + badgeInfo.cls;
            badgeSpan.textContent = tSite(badgeInfo.key);

            verRow.appendChild(verSpan);
            verRow.appendChild(badgeSpan);

            var dateEl = document.createElement('time');
            dateEl.className = 'history-release-date';
            dateEl.setAttribute('datetime', item.isoDate);
            dateEl.textContent = formatHistoryDate(item.isoDate);

            verCol.appendChild(verRow);
            verCol.appendChild(dateEl);

            var descEl = document.createElement('p');
            descEl.className = 'history-release-desc';
            descEl.textContent = tSite(item.descKey);

            var link = document.createElement('a');
            link.className = 'history-release-link';
            link.href = item.url;
            link.target = '_blank';
            link.rel = 'noopener noreferrer';
            var linkText = document.createElement('span');
            linkText.textContent = tSite('history.view_tag');
            link.appendChild(linkText);
            link.appendChild(createIconSvg('external-link', 'icon-xs'));

            card.appendChild(verCol);
            card.appendChild(descEl);
            card.appendChild(link);
            list.appendChild(card);
        });
    }

    function renderHistoryTagsCloud() {
        var cloud = document.getElementById('history-tags-cloud');
        if (!cloud) {
            return;
        }
        cloud.innerHTML = '';

        var hist = DATA.history || {};
        var rawTags = Array.isArray(hist.tags) ? hist.tags : [];
        var q = historyState.searchQuery.trim().toLowerCase();

        var entries = [];
        if (historyState.activeSeries === 'legacy') {
            entries = [
                {
                    t: 'PC-Blacklist-Sniffer v1.0.0',
                    d: '2023-01-10',
                    k: 'stable',
                    url: 'https://github.com/Illegal-Services/PC-Blacklist-Sniffer',
                },
                {
                    t: 'PS3-Blacklist-Sniffer v1.0 → v2.2.4',
                    d: '2021-11-30',
                    k: 'stable',
                    url: 'https://github.com/Illegal-Services/PS3-Blacklist-Sniffer',
                },
            ];
        } else {
            rawTags.forEach(function collectTag(tag) {
                if (historyState.activeSeries !== 'all' && tag.s !== historyState.activeSeries) {
                    return;
                }
                entries.push({
                    t: tag.t,
                    d: tag.d,
                    k: tag.k || 'stable',
                    url: 'https://github.com/BUZZARDGTA/Session-Sniffer/releases/tag/' + encodeURIComponent(tag.t),
                });
            });
        }

        if (q) {
            entries = entries.filter(function matchTag(entry) {
                return (
                    entry.t.toLowerCase().indexOf(q) !== -1
                    || entry.d.toLowerCase().indexOf(q) !== -1
                );
            });
        }

        if (entries.length === 0) {
            var empty = document.createElement('div');
            empty.className = 'history-empty-state';
            empty.textContent = tSite('history.empty_filter');
            cloud.appendChild(empty);
            return;
        }

        entries.forEach(function addTagChip(entry) {
            var kindLabel = entry.k === 'pre'
                ? tSite('history.badge_rc')
                : (entry.k === 'post' ? tSite('history.badge_post') : tSite('history.badge_major'));

            var chip = document.createElement('a');
            chip.className = 'history-tag-chip history-tag-chip--' + entry.k;
            chip.href = entry.url;
            chip.target = '_blank';
            chip.rel = 'noopener noreferrer';
            chip.setAttribute('dir', 'ltr');
            chip.title = entry.t + ' · ' + entry.d + ' (' + kindLabel + ')';

            var dot = document.createElement('span');
            dot.className = 'history-tag-dot';
            dot.setAttribute('aria-hidden', 'true');

            var nameSpan = document.createElement('span');
            nameSpan.textContent = entry.t;

            var dateSpan = document.createElement('span');
            dateSpan.className = 'history-tag-date';
            dateSpan.textContent = entry.d;

            chip.appendChild(dot);
            chip.appendChild(nameSpan);
            chip.appendChild(dateSpan);
            cloud.appendChild(chip);
        });
    }

    function renderHistorySection() {
        updateHistoryStatsAndCopy();
        renderHistoryEraStepper();
        renderHistoryEraStage();
        renderHistoryFilterBar();
        renderHistoryReleaseList();
        renderHistoryTagsCloud();
        if (historyState.lightboxOpen) {
            renderHistoryLightbox();
        }
    }

    function initHistorySection() {
        var prevEraBtn = document.getElementById('history-era-prev');
        var nextEraBtn = document.getElementById('history-era-next');
        if (prevEraBtn) {
            prevEraBtn.addEventListener('click', function onPrevEra() {
                stepHistoryEra(-1);
            });
        }
        if (nextEraBtn) {
            nextEraBtn.addEventListener('click', function onNextEra() {
                stepHistoryEra(1);
            });
        }

        var shotBtn = document.getElementById('history-era-shot-btn');
        if (shotBtn) {
            shotBtn.addEventListener('click', openHistoryLightbox);
        }

        var lbBackdrop = document.getElementById('history-lightbox-backdrop');
        var lbClose = document.getElementById('history-lightbox-close');
        var lbPrev = document.getElementById('history-lightbox-prev');
        var lbNext = document.getElementById('history-lightbox-next');

        if (lbBackdrop) {
            lbBackdrop.addEventListener('click', closeHistoryLightbox);
        }
        if (lbClose) {
            lbClose.addEventListener('click', closeHistoryLightbox);
        }
        if (lbPrev) {
            lbPrev.addEventListener('click', function onLightboxPrev() {
                stepHistoryEra(-1);
            });
        }
        if (lbNext) {
            lbNext.addEventListener('click', function onLightboxNext() {
                stepHistoryEra(1);
            });
        }

        var searchInput = document.getElementById('history-search-input');
        if (searchInput) {
            searchInput.addEventListener('input', function onHistorySearch() {
                historyState.searchQuery = searchInput.value;
                renderHistoryReleaseList();
                renderHistoryTagsCloud();
            });
        }

        var allTagsBtn = document.getElementById('history-all-tags-toggle');
        var allTagsPanel = document.getElementById('history-all-tags-panel');
        if (allTagsBtn && allTagsPanel) {
            allTagsBtn.addEventListener('click', function onToggleAllTags() {
                historyState.allTagsOpen = !historyState.allTagsOpen;
                allTagsPanel.hidden = !historyState.allTagsOpen;
                allTagsBtn.setAttribute('aria-expanded', historyState.allTagsOpen ? 'true' : 'false');
                updateHistoryStatsAndCopy();
            });
        }

        renderHistorySection();
    }


    document.addEventListener('keydown', function onHistoryKeyDown(ev) {
        if (ev.key === 'Escape') {
            closeHistoryLightbox();
        } else if (historyState.lightboxOpen && (ev.key === 'ArrowLeft' || ev.key === 'ArrowRight')) {
            ev.preventDefault();
            var isRtl = document.documentElement.getAttribute('dir') === 'rtl';
            var step = ev.key === 'ArrowRight' ? 1 : -1;
            if (isRtl) {
                step = -step;
            }
            stepHistoryEra(step);
        }
    });

    Core.onLanguageChange(renderHistorySection);

    initHistorySection();
}());
