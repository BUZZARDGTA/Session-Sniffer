/* ==========================================================================
   Session Sniffer Live Interactive Desktop Preview Controller (index.html)
   - Runs 1:1 PySide6 MainWindow simulation + real right-click context menu
   - Handles presets, live ticks, sorting, pagination, merge/split & mobile stage
   ========================================================================== */

(function initSessionSnifferPreview() {
    'use strict';

    var Core = window.SSCore;
    if (!Core || !document.getElementById('ss-live-window')) {
        return;
    }

    var PPS_MAX_THRESHOLD = Core.PPS_MAX_THRESHOLD;
    var BPS_MAX_THRESHOLD = Core.BPS_MAX_THRESHOLD;
    var tSite = Core.tSite;
    var tApp = Core.tApp;
    var formatNumber = Core.formatNumber;
    var formatBytes = Core.formatBytes;
    var formatUptime = Core.formatUptime;
    var formatElapsed = Core.formatElapsed;
    var formatDuration = Core.formatDuration;
    var createIconSvg = Core.createIconSvg;
    var showToast = Core.showToast;
    var showDemoFeatureToast = Core.showDemoFeatureToast;
    var setRichTooltip = Core.setRichTooltip;
    var hideRichTooltip = Core.hideRichTooltip;
    var getRateGradientColor = Core.getRateGradientColor;
    var closeThemeDropdown = Core.closeThemeDropdown;
    var closeLangDropdown = Core.closeLangDropdown;
    var closeMobileNavDrawer = Core.closeMobileNavDrawer;

    var APP_SUBTITLE_KEY = 'The best <span style="color: #22c55e; font-weight: 600;">FREE</span> and <span style="color: #22c55e; font-weight: 600;">Open-Source</span> packet sniffer';

    function renderAppSubtitle() {
        var subtitleEl = document.getElementById('ss-app-subtitle');
        if (!subtitleEl) {
            return;
        }
        var raw = tApp(APP_SUBTITLE_KEY);
        subtitleEl.textContent = '';
        var tokenRe = /<span[^>]*>(.*?)<\/span>/gi;
        var lastIndex = 0;
        var match;
        while ((match = tokenRe.exec(raw)) !== null) {
            if (match.index > lastIndex) {
                subtitleEl.appendChild(document.createTextNode(raw.slice(lastIndex, match.index)));
            }
            var hi = document.createElement('span');
            hi.className = 'ss-subtitle-hi';
            hi.textContent = match[1];
            subtitleEl.appendChild(hi);
            lastIndex = tokenRe.lastIndex;
        }
        if (lastIndex < raw.length) {
            subtitleEl.appendChild(document.createTextNode(raw.slice(lastIndex)));
        }
    }

    function refreshRateCellColors() {
        var isLightScheme = document.documentElement.getAttribute('data-scheme') === 'light';
        var tableIsLight = Core.getThemeState().activeTableIsLight;
        document.querySelectorAll('td[data-rate-value]').forEach(function updateRateCell(td) {
            var rate = Number(td.getAttribute('data-rate-value'));
            var threshold = Number(td.getAttribute('data-rate-threshold')) || PPS_MAX_THRESHOLD;
            var isServer = td.getAttribute('data-rate-server') === 'true';
            td.style.color = getRateGradientColor(rate, threshold, isServer ? isLightScheme : tableIsLight);
        });
    }

    /* ----------------------------------------------------------------------
       4. Interactive Session Sniffer Desktop Window Simulation
       Note: All demo IPs use RFC 5737 documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x).
       ---------------------------------------------------------------------- */

    var PRESETS = {
        gta5: {
            modeLabel: 'GTA V',
            gameMenuLabel: 'GTA V',
            ifaceLabel: 'Ethernet 3',
            localIp: '192.168.1.42',
            connected: [
                {
                    id: 'gta-1',
                    username: 'NovaDrift_99',
                    note: 'Crew',
                    source: 'userip',
                    isHost: true,
                    isRelay: false,
                    isServer: false,
                    firstSeenSec: 940,
                    rejoinSec: 862,
                    rejoins: 1,
                    ip: '198.51.100.14',
                    hostname: 'c-198-51-100-14.hsd1.va.comcast.net',
                    packets: 42810,
                    pps: 26,
                    bytes: 18420900,
                    bps: 11240,
                    ports: '6672, 61455',
                    countryCode: 'US',
                    country: 'United States (US)',
                    region: 'Virginia',
                    isp: 'Comcast Cable',
                    mobile: false,
                    vpn: false,
                    hosting: false,
                    ping: 28,
                    pinging: true,
                    highRate: false,
                },
                {
                    id: 'gta-2',
                    username: 'Kestrel_FR',
                    note: '',
                    source: 'looky',
                    isHost: false,
                    isRelay: false,
                    isServer: false,
                    firstSeenSec: 540,
                    rejoinSec: 514,
                    rejoins: 0,
                    ip: '203.0.113.88',
                    hostname: 'lfbn-idf1-1-88.w203-0.abo.wanadoo.fr',
                    packets: 29450,
                    pps: 138,
                    bytes: 14910200,
                    bps: 68400,
                    ports: '6672, 51920',
                    countryCode: 'FR',
                    country: 'France (FR)',
                    region: 'Île-de-France',
                    isp: 'Orange S.A.',
                    mobile: false,
                    vpn: false,
                    hosting: false,
                    ping: 36,
                    pinging: true,
                    highRate: true,
                },
                {
                    id: 'gta-3',
                    username: 'Valkyrie_DE',
                    note: 'Friend',
                    source: 'userip',
                    isHost: false,
                    isRelay: false,
                    isServer: false,
                    firstSeenSec: 405,
                    rejoinSec: 405,
                    rejoins: 0,
                    ip: '192.0.2.71',
                    hostname: 'p200300c8.dip0.t-ipconnect.de',
                    packets: 19305,
                    pps: 18,
                    bytes: 8234100,
                    bps: 7940,
                    ports: '6672',
                    countryCode: 'DE',
                    country: 'Germany (DE)',
                    region: 'North Rhine-Westphalia',
                    isp: 'Telekom DE',
                    mobile: false,
                    vpn: false,
                    hosting: false,
                    ping: 31,
                    pinging: false,
                    highRate: false,
                },
                {
                    id: 'gta-4',
                    username: 'ShadowByte_UK',
                    note: '',
                    source: 'looky',
                    isHost: false,
                    isRelay: false,
                    isServer: false,
                    firstSeenSec: 312,
                    rejoinSec: 238,
                    rejoins: 1,
                    ip: '198.51.100.203',
                    hostname: 'unn-198-51-100-203.cdn77.com',
                    packets: 12040,
                    pps: 14,
                    bytes: 5120440,
                    bps: 5820,
                    ports: '6672, 58012',
                    countryCode: 'GB',
                    country: 'United Kingdom (GB)',
                    region: 'England',
                    isp: 'M247 Europe',
                    mobile: false,
                    vpn: true,
                    hosting: true,
                    ping: 49,
                    pinging: false,
                    highRate: false,
                },
                {
                    id: 'gta-5',
                    username: 'AkiraZero',
                    note: '',
                    source: 'default',
                    isHost: false,
                    isRelay: false,
                    isServer: false,
                    firstSeenSec: 121,
                    rejoinSec: 121,
                    rejoins: 0,
                    ip: '203.0.113.45',
                    hostname: 'p1045-ipngn.tokyo.ocn.ne.jp',
                    packets: 6840,
                    pps: 12,
                    bytes: 2940120,
                    bps: 4610,
                    ports: '6672',
                    countryCode: 'JP',
                    country: 'Japan (JP)',
                    region: 'Tokyo',
                    isp: 'NTT Comm.',
                    mobile: false,
                    vpn: false,
                    hosting: false,
                    ping: 112,
                    pinging: true,
                    highRate: false,
                },
                {
                    id: 'gta-6',
                    username: '',
                    note: '',
                    source: 'default',
                    isHost: false,
                    isRelay: true,
                    isServer: true,
                    firstSeenSec: 408,
                    rejoinSec: 291,
                    rejoins: 2,
                    ip: '192.0.2.250',
                    hostname: '192.0.2.250',
                    packets: 2575,
                    pps: 2,
                    bytes: 591200,
                    bps: 890,
                    ports: '61455',
                    countryCode: 'US',
                    country: 'United States (US)',
                    region: 'North Holland',
                    isp: 'Take-Two Interactive',
                    mobile: false,
                    vpn: false,
                    hosting: false,
                    ping: 19,
                    pinging: false,
                    highRate: false,
                },
                {
                    id: 'gta-7',
                    username: 'TulipDrift_NL',
                    note: '',
                    source: 'default',
                    isHost: false,
                    isRelay: false,
                    isServer: false,
                    firstSeenSec: 44,
                    rejoinSec: 44,
                    rejoins: 0,
                    ip: '192.0.2.159',
                    hostname: '192-0-2-159.fixed.kpn.net',
                    packets: 1920,
                    pps: 9,
                    bytes: 842900,
                    bps: 3190,
                    ports: '6672',
                    countryCode: 'NL',
                    country: 'Netherlands (NL)',
                    region: 'South Holland',
                    isp: 'KPN B.V.',
                    mobile: true,
                    vpn: false,
                    hosting: false,
                    ping: 24,
                    pinging: false,
                    highRate: false,
                },
            ],
            disconnected: [
                {
                    id: 'gta-d1',
                    username: 'Riptide_BR',
                    note: '',
                    source: 'looky',
                    isServer: false,
                    firstSeenSec: 790,
                    rejoinSec: 790,
                    lastSeenSec: 48,
                    totalSessionSec: 742,
                    sessionSec: 742,
                    rejoins: 0,
                    pastSession: false,
                    ip: '198.51.100.91',
                    hostname: 'c633645b.virtua.com.br',
                    packets: 21490,
                    bytes: 9410220,
                    ports: '6672, 49210',
                    countryCode: 'BR',
                    country: 'Brazil (BR)',
                    region: 'São Paulo',
                    isp: 'Claro S.A.',
                    mobile: false,
                    vpn: false,
                    hosting: false,
                    pinging: false,
                },
                {
                    id: 'gta-d2',
                    username: '',
                    note: '',
                    source: 'default',
                    isServer: true,
                    firstSeenSec: 351,
                    rejoinSec: 31,
                    lastSeenSec: 17,
                    totalSessionSec: 48,
                    sessionSec: 14,
                    rejoins: 7,
                    pastSession: false,
                    ip: '198.51.100.251',
                    hostname: '198.51.100.251',
                    packets: 18,
                    bytes: 6240,
                    ports: '61456',
                    countryCode: 'US',
                    country: 'United States (US)',
                    region: 'North Holland',
                    isp: 'Take-Two Interactive',
                    mobile: false,
                    vpn: false,
                    hosting: false,
                    pinging: false,
                },
                {
                    id: 'gta-d3',
                    username: 'FrostByte_CA',
                    note: 'Saved',
                    source: 'userip',
                    isServer: false,
                    firstSeenSec: 1320,
                    rejoinSec: 1320,
                    lastSeenSec: 215,
                    totalSessionSec: 1105,
                    sessionSec: 1105,
                    rejoins: 0,
                    pastSession: false,
                    ip: '203.0.113.112',
                    hostname: 'bas1-toronto.dsl.bell.ca',
                    packets: 34200,
                    bytes: 15220800,
                    ports: '6672',
                    countryCode: 'CA',
                    country: 'Canada (CA)',
                    region: 'Ontario',
                    isp: 'Bell Canada',
                    mobile: false,
                    vpn: false,
                    hosting: false,
                    pinging: false,
                },
                {
                    id: 'gta-d4',
                    username: 'NordicPulse',
                    note: '',
                    source: 'default',
                    isServer: false,
                    firstSeenSec: 1120,
                    rejoinSec: 1120,
                    lastSeenSec: 690,
                    totalSessionSec: 430,
                    sessionSec: 430,
                    rejoins: 1,
                    pastSession: false,
                    ip: '192.0.2.214',
                    hostname: 'h-192-0-2-214.a146.priv.bahnhof.se',
                    packets: 9810,
                    bytes: 4120000,
                    ports: '6672',
                    countryCode: 'SE',
                    country: 'Sweden (SE)',
                    region: 'Stockholm',
                    isp: 'Telia Company',
                    mobile: false,
                    vpn: false,
                    hosting: false,
                    pinging: false,
                },
            ],
        },
        rdr2: {
            modeLabel: 'RDR2',
            gameMenuLabel: 'RDR2',
            ifaceLabel: 'Ethernet 3',
            localIp: '192.168.1.42',
            connected: [
                {
                    id: 'rdr-1',
                    username: 'Arthur_Morgan88',
                    note: 'Posse',
                    source: 'userip',
                    isHost: true,
                    isRelay: false,
                    isServer: false,
                    firstSeenSec: 940,
                    rejoinSec: 940,
                    rejoins: 0,
                    ip: '198.51.100.32',
                    hostname: '198-51-100-32.lightspeed.austtx.sbcglobal.net',
                    packets: 36120,
                    pps: 22,
                    bytes: 15440200,
                    bps: 9840,
                    ports: '6672, 61456',
                    countryCode: 'US',
                    country: 'United States (US)',
                    region: 'Texas',
                    isp: 'AT&T Services',
                    mobile: false,
                    vpn: false,
                    hosting: false,
                    ping: 33,
                    pinging: true,
                    highRate: false,
                },
                {
                    id: 'rdr-2',
                    username: 'CanyonFox',
                    note: 'Friend',
                    source: 'userip',
                    isHost: false,
                    isRelay: false,
                    isServer: false,
                    firstSeenSec: 520,
                    rejoinSec: 480,
                    rejoins: 1,
                    ip: '203.0.113.64',
                    hostname: 'cpe203011364.cpe.net.cable.rogers.com',
                    packets: 18420,
                    pps: 16,
                    bytes: 7940100,
                    bps: 6920,
                    ports: '6672',
                    countryCode: 'CA',
                    country: 'Canada (CA)',
                    region: 'Ontario',
                    isp: 'Rogers Cable',
                    mobile: false,
                    vpn: false,
                    hosting: false,
                    ping: 41,
                    pinging: false,
                    highRate: false,
                },
                {
                    id: 'rdr-3',
                    username: 'OutbackRanger',
                    note: '',
                    source: 'default',
                    isHost: false,
                    isRelay: false,
                    isServer: false,
                    firstSeenSec: 175,
                    rejoinSec: 175,
                    rejoins: 0,
                    ip: '192.0.2.88',
                    hostname: 'n192-0-2-88.syd.telstra.net',
                    packets: 8930,
                    pps: 14,
                    bytes: 3820400,
                    bps: 5210,
                    ports: '6672, 54011',
                    countryCode: 'AU',
                    country: 'Australia (AU)',
                    region: 'New South Wales',
                    isp: 'Telstra Corp.',
                    mobile: false,
                    vpn: false,
                    hosting: false,
                    ping: 148,
                    pinging: false,
                    highRate: false,
                },
                {
                    id: 'rdr-4',
                    username: 'IronSpur_DE',
                    note: '',
                    source: 'default',
                    isHost: false,
                    isRelay: false,
                    isServer: false,
                    firstSeenSec: 92,
                    rejoinSec: 92,
                    rejoins: 0,
                    ip: '198.51.100.177',
                    hostname: 'ip-198-51-100-177.hsi.unitymediagroup.de',
                    packets: 4180,
                    pps: 11,
                    bytes: 1790300,
                    bps: 4120,
                    ports: '6672',
                    countryCode: 'DE',
                    country: 'Germany (DE)',
                    region: 'Bavaria',
                    isp: 'Vodafone GmbH',
                    mobile: false,
                    vpn: false,
                    hosting: false,
                    ping: 29,
                    pinging: true,
                    highRate: false,
                },
            ],
            disconnected: [
                {
                    id: 'rdr-d1',
                    username: 'DustDevil_GB',
                    note: '',
                    source: 'default',
                    isServer: false,
                    firstSeenSec: 725,
                    rejoinSec: 725,
                    lastSeenSec: 110,
                    totalSessionSec: 615,
                    sessionSec: 615,
                    rejoins: 0,
                    pastSession: false,
                    ip: '203.0.113.19',
                    hostname: 'host203-0-113-19.range203-0.btcentralplus.com',
                    packets: 14120,
                    bytes: 6012000,
                    ports: '6672',
                    countryCode: 'GB',
                    country: 'United Kingdom (GB)',
                    region: 'England',
                    isp: 'British Telecom',
                    mobile: false,
                    vpn: false,
                    hosting: false,
                    pinging: false,
                },
            ],
        },
        p2p: {
            modeLabel: null,
            gameMenuLabel: '',
            ifaceLabel: 'Hotspot (PS5)',
            localIp: '192.168.137.48',
            connected: [
                {
                    id: 'p2p-1',
                    username: 'PS5_CoopPartner',
                    note: 'Console',
                    source: 'userip',
                    isHost: false,
                    isRelay: false,
                    isServer: false,
                    firstSeenSec: 620,
                    rejoinSec: 620,
                    rejoins: 0,
                    ip: '198.51.100.55',
                    hostname: '198-51-100-55.subs.proxad.net',
                    packets: 31200,
                    pps: 34,
                    bytes: 14200400,
                    bps: 15800,
                    ports: '3074, 52104',
                    countryCode: 'FR',
                    country: 'France (FR)',
                    region: 'Auvergne-Rhône-Alpes',
                    isp: 'Free SAS',
                    mobile: false,
                    vpn: false,
                    hosting: false,
                    ping: 22,
                    pinging: true,
                    highRate: false,
                },
                {
                    id: 'p2p-2',
                    username: 'Peer_NL_01',
                    note: '',
                    source: 'default',
                    isHost: false,
                    isRelay: false,
                    isServer: false,
                    firstSeenSec: 295,
                    rejoinSec: 295,
                    rejoins: 0,
                    ip: '203.0.113.140',
                    hostname: '203-0-113-140.cable.dynamic.v4.ziggo.nl',
                    packets: 15480,
                    pps: 21,
                    bytes: 6910200,
                    bps: 9120,
                    ports: '3074',
                    countryCode: 'NL',
                    country: 'Netherlands (NL)',
                    region: 'North Holland',
                    isp: 'Liberty Global',
                    mobile: false,
                    vpn: false,
                    hosting: false,
                    ping: 26,
                    pinging: false,
                    highRate: false,
                },
                {
                    id: 'p2p-3',
                    username: 'TunnelPeer_SE',
                    note: '',
                    source: 'default',
                    isHost: false,
                    isRelay: false,
                    isServer: false,
                    firstSeenSec: 88,
                    rejoinSec: 88,
                    rejoins: 0,
                    ip: '192.0.2.123',
                    hostname: 'se-sto-wg-001.relays.mullvad.net',
                    packets: 4210,
                    pps: 13,
                    bytes: 1940100,
                    bps: 5400,
                    ports: '3659, 44120',
                    countryCode: 'SE',
                    country: 'Sweden (SE)',
                    region: 'Stockholm',
                    isp: 'Mullvad VPN',
                    mobile: false,
                    vpn: true,
                    hosting: true,
                    ping: 44,
                    pinging: false,
                    highRate: false,
                },
            ],
            disconnected: [
                {
                    id: 'p2p-d1',
                    username: 'ConsolePeer_US',
                    note: '',
                    source: 'default',
                    isServer: false,
                    firstSeenSec: 676,
                    rejoinSec: 676,
                    lastSeenSec: 164,
                    totalSessionSec: 512,
                    sessionSec: 512,
                    rejoins: 0,
                    pastSession: false,
                    ip: '198.51.100.240',
                    hostname: 'syn-198-051-100-240.res.spectrum.com',
                    packets: 11240,
                    bytes: 4910000,
                    ports: '3074',
                    countryCode: 'US',
                    country: 'United States (US)',
                    region: 'California',
                    isp: 'Charter Comm.',
                    mobile: false,
                    vpn: false,
                    hosting: false,
                    pinging: false,
                },
            ],
        },
    };

    var ROWS_LIMIT_STEPS = [0, 3, 5, 10];
    var MIN_SECTION_HEIGHT_PX = 110;
    var DEFAULT_SPLITTER_RATIO = 0.57;

    var simState = {
        presetKey: 'gta5',
        merged: false,
        connectedExpanded: true,
        disconnectedExpanded: true,
        splitterRatio: DEFAULT_SPLITTER_RATIO,
        visualAlerts: true,
        voiceAlerts: true,
        uptimeSeconds: 872,
        totalPackets: 184920,
        searchQuery: '',
        searchColumn: 'all',
        connectedRowLimit: 0,
        disconnectedRowLimit: 0,
        connectedPage: 1,
        disconnectedPage: 1,
        connectedSort: { col: 'lastRejoin', dir: 'desc' },
        disconnectedSort: { col: 'lastSeen', dir: 'asc' },
        selectedId: null,
        connected: [],
        disconnected: [],
    };

    function cloneRows(rows) {
        return rows.map(function copy(r) { return Object.assign({}, r); });
    }

    function syncColumnHeaderTooltips() {
        var tooltipsMap = (Core.DATA && Core.DATA.columnTooltips) || {};
        document.querySelectorAll('th[data-sort-table]').forEach(function applyColTip(th) {
            var labelSpan = th.querySelector('[data-i18n-app]');
            var canonicalCol = labelSpan ? labelSpan.getAttribute('data-i18n-app') : '';
            var englishTip = canonicalCol ? tooltipsMap[canonicalCol] : '';
            if (!englishTip) {
                setRichTooltip(th, '', '');
                return;
            }
            var tableKey = th.getAttribute('data-sort-table');
            var variant = tableKey === 'disconnected' ? 'danger' : 'full';
            setRichTooltip(th, tApp(canonicalCol), tApp(englishTip), variant);
        });
    }

    function syncPresetMenusAndStatus() {
        var preset = PRESETS[simState.presetKey];
        if (!preset) {
            return;
        }
        var featureWrap = document.getElementById('ss-status-feature-wrap');
        var modeEl = document.getElementById('ss-status-mode');
        var ifaceEl = document.getElementById('ss-status-iface');
        var ipEl = document.getElementById('ss-status-ip');
        var gameWrap = document.getElementById('ss-game-menu-wrap');
        var gameTrigger = document.getElementById('ss-game-menu-trigger');
        var gameStatusText = document.getElementById('ss-game-status-text');
        var lookyWrap = document.getElementById('ss-menu-looky-wrap');
        var processLabel = document.getElementById('ss-menu-game-process-label');
        var settingsGameItem = document.getElementById('ss-settings-game-item');
        var settingsGameLabel = document.getElementById('ss-settings-game-label');
        var detectionsRelaysItem = document.getElementById('ss-detections-relays-item');

        if (featureWrap) {
            featureWrap.hidden = !preset.modeLabel;
        }
        if (modeEl && preset.modeLabel) {
            modeEl.textContent = preset.modeLabel;
        }
        if (ifaceEl) {
            ifaceEl.textContent = preset.ifaceLabel;
        }
        if (ipEl) {
            ipEl.textContent = preset.localIp;
        }
        if (gameWrap && gameTrigger) {
            gameWrap.hidden = !preset.gameMenuLabel;
            if (preset.gameMenuLabel) {
                gameTrigger.textContent = preset.gameMenuLabel;
            }
        }
        if (gameStatusText) {
            gameStatusText.textContent = simState.presetKey === 'rdr2' ? 'RDR2' : 'GTA V Enhanced';
        }
        if (lookyWrap) {
            lookyWrap.hidden = simState.presetKey !== 'gta5';
        }
        if (processLabel) {
            processLabel.textContent = tApp('{game} Process', { game: simState.presetKey === 'rdr2' ? 'RDR2' : 'GTA5' });
        }
        if (settingsGameItem && settingsGameLabel) {
            settingsGameItem.hidden = !preset.gameMenuLabel;
            if (preset.gameMenuLabel) {
                settingsGameItem.setAttribute('data-feature-app', preset.gameMenuLabel);
                settingsGameLabel.setAttribute('data-i18n-app', preset.gameMenuLabel);
                settingsGameLabel.textContent = tApp(preset.gameMenuLabel);
            }
        }
        if (detectionsRelaysItem) {
            detectionsRelaysItem.hidden = simState.presetKey !== 'gta5';
        }
    }

    function loadPreset(presetKey) {
        var preset = PRESETS[presetKey];
        if (!preset) {
            return;
        }
        closeContextMenu();
        simState.presetKey = presetKey;
        simState.connected = cloneRows(preset.connected);
        simState.disconnected = cloneRows(preset.disconnected);
        simState.connectedPage = 1;
        simState.disconnectedPage = 1;
        simState.selectedId = null;

        syncPresetMenusAndStatus();

        document.querySelectorAll('[data-preset]').forEach(function markPreset(btn) {
            btn.classList.toggle('is-active', btn.getAttribute('data-preset') === presetKey);
        });

        renderPreviewTables();
    }

    function getDisplayHostname(player) {
        return player.hostname || player.ip;
    }

    function matchesSearch(player) {
        var q = simState.searchQuery.trim().toLowerCase();
        if (!q) {
            return true;
        }
        var col = simState.searchColumn;
        var portsRaw = (player.ports || '').toLowerCase();
        var portParts = portsRaw
            ? portsRaw.split(',').map(function trimPort(part) { return part.trim(); }).filter(Boolean)
            : [];
        var ispText = (player.isp || '').toLowerCase();
        var fields = {
            username: (player.username + ' ' + (player.note || '')).toLowerCase(),
            ip: player.ip.toLowerCase(),
            hostname: getDisplayHostname(player).toLowerCase(),
            ports: portsRaw,
            lastPort: portParts.length > 0 ? portParts[portParts.length - 1] : '',
            middlePorts: portParts.length > 2 ? portParts.slice(1, -1).join(', ') : '',
            firstPort: portParts.length > 0 ? portParts[0] : '',
            continent: (player.continent || '').toLowerCase(),
            country: player.country.toLowerCase(),
            region: (player.region || '').toLowerCase(),
            regionCode: (player.regionCode || '').toLowerCase(),
            city: (player.city || '').toLowerCase(),
            district: (player.district || '').toLowerCase(),
            zipCode: (player.zipCode || '').toLowerCase(),
            timeZone: (player.timeZone || '').toLowerCase(),
            currency: (player.currency || '').toLowerCase(),
            organization: (player.organization || player.isp || '').toLowerCase(),
            ispName: ispText,
            isp: ispText,
            as: (player.as || '').toLowerCase(),
            asn: (player.asn || '').toLowerCase(),
        };
        if (col !== 'all') {
            return (fields[col] || '').indexOf(q) !== -1;
        }
        return (
            fields.username.indexOf(q) !== -1
            || fields.ip.indexOf(q) !== -1
            || fields.hostname.indexOf(q) !== -1
            || fields.ports.indexOf(q) !== -1
            || fields.country.indexOf(q) !== -1
            || fields.region.indexOf(q) !== -1
            || fields.isp.indexOf(q) !== -1
        );
    }

    function buildUsernameCell(player) {
        var td = document.createElement('td');
        td.className = 'col-user';
        var wrap = document.createElement('span');
        wrap.className = 'cell-user-wrap';

        if (player.source === 'looky' && !player.isServer && simState.presetKey === 'gta5') {
            var lookyIcon = createIconSvg('eye', 'icon-xs looky-row-icon');
            lookyIcon.setAttribute('title', tApp('Looky System'));
            wrap.appendChild(lookyIcon);
        }

        var nameText = document.createElement('span');
        var baseName = player.username || '';
        nameText.textContent = player.note && baseName ? baseName + ' (' + player.note + ')' : baseName;
        wrap.appendChild(nameText);

        td.appendChild(wrap);
        return td;
    }

    function buildIpCell(player, isDisconnected) {
        var td = document.createElement('td');
        td.className = 'mono';
        var wrap = document.createElement('span');
        wrap.className = 'ip-cell-wrap';

        if (!isDisconnected) {
            if (player.isHost) {
                wrap.appendChild(createIconSvg('crown', 'icon-xs host-crown'));
            }
            if (player.isRelay) {
                wrap.appendChild(createIconSvg('route', 'icon-xs relay-icon'));
            }
            if (player.highRate) {
                wrap.appendChild(createIconSvg('gauge', 'icon-xs spike-alert-icon'));
            }
        }

        var ipText = document.createElement('span');
        ipText.textContent = player.ip;
        wrap.appendChild(ipText);
        td.appendChild(wrap);
        return td;
    }

    function buildCountryCell(player) {
        var td = document.createElement('td');
        var wrap = document.createElement('span');
        wrap.className = 'flag-cell';

        var img = document.createElement('img');
        img.className = 'flag-img';
        img.src = 'assets/flags/' + player.countryCode + '.png';
        img.alt = player.countryCode;
        img.width = 18;
        img.height = 12;

        var label = document.createElement('span');
        label.textContent = player.country;

        wrap.appendChild(img);
        wrap.appendChild(label);
        td.appendChild(wrap);
        return td;
    }

    function makeTextCell(text, className, title) {
        var td = document.createElement('td');
        if (className) {
            td.className = className;
        }
        if (title) {
            td.title = title;
        }
        td.textContent = text;
        return td;
    }

    function makeRateCell(text, rate, threshold, isServer) {
        var td = makeTextCell(text, 'num');
        var isLightBg = isServer
            ? document.documentElement.getAttribute('data-scheme') === 'light'
            : Core.getThemeState().activeTableIsLight;
        td.setAttribute('data-rate-value', String(rate));
        td.setAttribute('data-rate-threshold', String(threshold));
        if (isServer) {
            td.setAttribute('data-rate-server', 'true');
        }
        td.style.color = getRateGradientColor(rate, threshold, isLightBg);
        return td;
    }

    /* ----------------------------------------------------------------------
       Real Session Sniffer Right-Click Context Menu
       Mirrors src/session_sniffer/guis/tables_context_menu_mixin.py
       ---------------------------------------------------------------------- */

    var LONG_PRESS_DELAY_MS = 450;
    var LONG_PRESS_MOVE_TOLERANCE_PX = 12;

    var touchLongPressState = {
        timer: null,
        pointerId: null,
        startX: 0,
        startY: 0,
        triggered: false,
        suppressClickUntil: 0,
        suppressContextMenuUntil: 0,
    };

    var contextMenuLayout = null;

    function clearTouchLongPressTimer() {
        if (touchLongPressState.timer !== null) {
            window.clearTimeout(touchLongPressState.timer);
            touchLongPressState.timer = null;
        }
        touchLongPressState.pointerId = null;
    }

    function findPlayerForRow(playerId, tableKind) {
        if (!playerId) {
            return null;
        }
        if (tableKind === 'disconnected') {
            for (var i = 0; i < simState.disconnected.length; i += 1) {
                if (simState.disconnected[i].id === playerId) {
                    return { player: simState.disconnected[i], isDisconnected: true };
                }
            }
            return null;
        }
        for (var j = 0; j < simState.connected.length; j += 1) {
            if (simState.connected[j].id === playerId) {
                return { player: simState.connected[j], isDisconnected: false };
            }
        }
        if (simState.merged) {
            for (var k = 0; k < simState.disconnected.length; k += 1) {
                if (simState.disconnected[k].id === playerId) {
                    return { player: simState.disconnected[k], isDisconnected: true };
                }
            }
        }
        return null;
    }

    function getContextMenuSizingSpec(boundsW, boundsH, stageShell) {
        var shortSide = Math.min(boundsW, boundsH);
        var isFullscreen = Boolean(stageShell);
        var isDesktopViewport = !isFullscreen && boundsW >= PREVIEW_STAGE_BREAKPOINT_PX && boundsH >= 620;
        var isCompact = shortSide <= 540 || (!isDesktopViewport && boundsW <= 680);
        var margin = shortSide <= 480 ? 8 : 10;

        var topInset = margin;
        if (stageShell) {
            var stageBar = stageShell.querySelector('.ss-stage-bar');
            var stageBarH = stageBar ? stageBar.offsetHeight : 0;
            topInset = stageBarH > 0 ? (stageBarH + margin) : margin;
        } else {
            var siteHeader = document.querySelector('.site-header');
            if (siteHeader) {
                var headerBottom = Math.round(siteHeader.getBoundingClientRect().bottom);
                if (headerBottom > 0) {
                    topInset = Math.max(margin, Math.min(headerBottom + 6, 84));
                }
            }
        }

        var availW = Math.max(140, boundsW - (margin * 2));
        var availH = Math.max(140, boundsH - topInset - margin);

        var baseScale = 1;
        var maxMenuW = availW;
        var maxMenuH = availH;

        if (isCompact) {
            baseScale = Math.max(0.72, Math.min(1, shortSide / 425));
            maxMenuH = Math.min(availH, Math.max(180, Math.round(shortSide * 0.77)));
            maxMenuW = Math.min(availW, Math.max(150, Math.round(boundsW * (boundsW <= 540 ? 0.54 : 0.38))));
        } else if (!isDesktopViewport) {
            baseScale = Math.max(0.84, Math.min(1, shortSide / 820));
            maxMenuH = Math.min(availH, Math.max(280, Math.round(boundsH * 0.78)));
            maxMenuW = Math.min(availW, Math.max(200, Math.round(boundsW * 0.48)));
        }

        return {
            compact: isCompact,
            margin: margin,
            topInset: topInset,
            baseScale: baseScale,
            maxMenuW: maxMenuW,
            maxMenuH: maxMenuH,
        };
    }

    function positionCtxSubmenu(wrap) {
        if (!wrap || !contextMenuLayout) {
            return;
        }
        var sub = wrap.querySelector('.ss-ctx-submenu');
        if (!sub) {
            return;
        }
        var layout = contextMenuLayout;
        var scale = layout.scale || 1;
        var margin = layout.margin || 8;
        var topInset = layout.topInset || margin;
        var padOffset = layout.compact ? 4 : 5;

        sub.style.left = '';
        sub.style.right = '';
        sub.classList.remove('open-up');

        var fallbackSubW = layout.compact ? 146 : 210;
        var subW = (sub.offsetWidth || fallbackSubW) * scale;
        var subH = sub.offsetHeight || 0;
        var spaceRight = layout.boundsW - (layout.left + layout.width) - margin;
        var spaceLeft = layout.left - margin;

        var openLeft = layout.isRtl
            ? (spaceLeft >= subW || spaceLeft >= spaceRight)
            : (spaceRight < subW && spaceLeft > spaceRight);
        sub.classList.toggle('open-left', openLeft);

        /* On narrow viewports where neither side fits, slide submenu toward the roomier side inside bounds. */
        if (Math.max(spaceLeft, spaceRight) < subW) {
            var desiredScreenLeft = spaceLeft > spaceRight
                ? margin
                : Math.max(margin, layout.boundsW - margin - subW);
            sub.classList.remove('open-left');
            sub.style.right = 'auto';
            sub.style.left = Math.round((desiredScreenLeft - layout.left) / scale) + 'px';
        }

        if (subH > 0) {
            var downBottom = layout.top + ((wrap.offsetTop - padOffset + subH) * scale);
            var upTop = layout.top + ((wrap.offsetTop + wrap.offsetHeight + padOffset - subH) * scale);
            var overflowDown = downBottom - (layout.boundsH - margin);
            var overflowUp = topInset - upTop;
            sub.classList.toggle('open-up', overflowDown > 0 && overflowUp < overflowDown);
        } else {
            sub.classList.remove('open-up');
        }
    }

    function closeContextMenu() {
        contextMenuLayout = null;
        var menu = document.getElementById('ss-context-menu');
        if (menu) {
            menu.hidden = true;
            menu.innerHTML = '';
            menu.classList.remove('is-compact');
            menu.style.transform = '';
            menu.style.transformOrigin = '';
            if (menu.parentNode && menu.parentNode !== document.body) {
                document.body.appendChild(menu);
            }
        }
    }

    function copyToClipboard(text, successMsg) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(function done() {
                showToast(successMsg);
            }).catch(function err() {
                showToast(successMsg);
            });
        } else {
            showToast(successMsg);
        }
    }

    function createCtxItem(iconName, label, onClick, options) {
        var opts = options || {};
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'ss-ctx-item' + (opts.danger ? ' ss-ctx-item--danger' : '');
        btn.setAttribute('role', 'menuitem');

        var left = document.createElement('span');
        left.className = 'ss-ctx-item-left';
        left.appendChild(createIconSvg(iconName, 'icon-xs'));
        var textSpan = document.createElement('span');
        textSpan.textContent = label;
        left.appendChild(textSpan);
        btn.appendChild(left);

        if (opts.shortcut) {
            var sc = document.createElement('span');
            sc.className = 'ss-ctx-shortcut';
            sc.textContent = opts.shortcut;
            btn.appendChild(sc);
        }

        btn.addEventListener('click', function handleItem(ev) {
            ev.stopPropagation();
            closeContextMenu();
            onClick();
        });
        return btn;
    }

    function createCtxSeparator() {
        var sep = document.createElement('div');
        sep.className = 'ss-ctx-sep';
        sep.setAttribute('role', 'separator');
        return sep;
    }

    function createCtxSubmenu(iconName, label, items, openLeft) {
        var wrap = document.createElement('div');
        wrap.className = 'ss-ctx-submenu-wrap';

        var trigger = document.createElement('button');
        trigger.type = 'button';
        trigger.className = 'ss-ctx-item';
        trigger.setAttribute('aria-haspopup', 'menu');
        trigger.setAttribute('aria-expanded', 'false');

        var left = document.createElement('span');
        left.className = 'ss-ctx-item-left';
        left.appendChild(createIconSvg(iconName, 'icon-xs'));
        var textSpan = document.createElement('span');
        textSpan.textContent = label;
        left.appendChild(textSpan);
        trigger.appendChild(left);
        trigger.appendChild(createIconSvg('chevron-right', 'icon-xs'));

        var sub = document.createElement('div');
        sub.className = 'ss-ctx-submenu' + (openLeft ? ' open-left' : '');
        sub.setAttribute('role', 'menu');
        items.forEach(function appendChild(node) { sub.appendChild(node); });

        trigger.addEventListener('click', function onSubmenuTriggerClick(ev) {
            ev.preventDefault();
            ev.stopPropagation();
            var menu = document.getElementById('ss-context-menu');
            var willOpen = !wrap.classList.contains('is-open');
            if (menu) {
                menu.querySelectorAll('.ss-ctx-submenu-wrap.is-open').forEach(function closeOther(other) {
                    if (other !== wrap) {
                        other.classList.remove('is-open');
                        var otherBtn = other.querySelector('.ss-ctx-item');
                        if (otherBtn) {
                            otherBtn.setAttribute('aria-expanded', 'false');
                        }
                    }
                });
            }
            wrap.classList.toggle('is-open', willOpen);
            trigger.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
            if (willOpen) {
                positionCtxSubmenu(wrap);
            }
        });

        wrap.addEventListener('mouseenter', function onSubmenuHover() {
            positionCtxSubmenu(wrap);
        });

        wrap.appendChild(trigger);
        wrap.appendChild(sub);
        return wrap;
    }

    function openRowContextMenu(rawClientX, rawClientY, player, isDisconnected, clickedCellText) {
        hideRichTooltip();
        closeAllAppMenus();
        closeThemeDropdown();
        closeLangDropdown();
        closeMobileNavDrawer();
        closeSearchColumnPopup();

        simState.selectedId = player.id;
        renderPreviewTables();

        var menu = document.getElementById('ss-context-menu');
        if (!menu) {
            return;
        }
        menu.innerHTML = '';

        var stageShell = previewStageState.fullscreen ? document.getElementById('ss-stage-shell') : null;
        var menuHost = stageShell || document.body;
        if (menu.parentNode !== menuHost) {
            menuHost.appendChild(menu);
        }

        var clickX = rawClientX;
        var clickY = rawClientY;
        var boundsW = window.innerWidth;
        var boundsH = window.innerHeight;
        if (stageShell) {
            var stageRect = stageShell.getBoundingClientRect();
            boundsW = stageShell.clientWidth || (previewStageState.rotated ? window.innerHeight : window.innerWidth);
            boundsH = stageShell.clientHeight || (previewStageState.rotated ? window.innerWidth : window.innerHeight);
            if (previewStageState.rotated) {
                clickX = rawClientY - stageRect.top;
                clickY = stageRect.right - rawClientX;
            } else {
                clickX = rawClientX - stageRect.left;
                clickY = rawClientY - stageRect.top;
            }
        }

        var sizingSpec = getContextMenuSizingSpec(boundsW, boundsH, stageShell);
        var displayName = player.username || player.ip;
        var isRtl = document.documentElement.getAttribute('dir') === 'rtl';
        var flipThreshold = Math.min(460, Math.round(boundsW * 0.55));
        var openLeft = isRtl ? clickX >= flipThreshold : clickX > boundsW - flipThreshold;
        var hasGameHostTools = simState.presetKey === 'gta5' || simState.presetKey === 'rdr2';

        /* Copy Selection & Copy for Discord */
        menu.appendChild(createCtxItem('copy', tApp('Copy Selection'), function copyCell() {
            var val = (clickedCellText || player.ip).trim();
            copyToClipboard(val, tSite('preview.toast_copied') + ': ' + val);
        }, { shortcut: 'Ctrl+C' }));

        menu.appendChild(createCtxItem('copy', tApp('Copy for Discord'), function copyDiscord() {
            var report = '**' + displayName + '** · `' + player.ip + '` · ' + player.country + ' · ' + player.isp;
            copyToClipboard(report, tSite('preview.toast_copied_discord', { name: displayName }));
        }));

        menu.appendChild(createCtxSeparator());

        /* Remove Player */
        menu.appendChild(createCtxItem('remove', tApp('Remove Player', { count: 1 }), function removePlayer() {
            simState.connected = simState.connected.filter(function keep(p) { return p.id !== player.id; });
            simState.disconnected = simState.disconnected.filter(function keep(p) { return p.id !== player.id; });
            if (simState.selectedId === player.id) {
                simState.selectedId = null;
            }
            renderPreviewTables();
            showToast(tSite('preview.toast_removed', { name: displayName }));
        }, { danger: true }));

        menu.appendChild(createCtxSeparator());

        /* Host tools (GTA V / RDR2) */
        if (hasGameHostTools && player.isHost && !isDisconnected) {
            menu.appendChild(createCtxItem('x', tApp('Clear Session Host'), function clearHost() {
                player.isHost = false;
                renderPreviewTables();
                showToast(tSite('preview.toast_host_cleared', { name: displayName }));
            }));
        }
        if (hasGameHostTools) {
            menu.appendChild(createCtxItem('bug', tApp('Host Diagnostics…'), function showHostDiag() {
                showDemoFeatureToast(tApp('Host Diagnostics…'));
            }));
        }

        /* Filtering & Diagnostics */
        menu.appendChild(createCtxItem('x', tApp('Exclude IP / Range'), function excludeIp() {
            simState.connected = simState.connected.filter(function keep(p) { return p.ip !== player.ip; });
            simState.disconnected = simState.disconnected.filter(function keep(p) { return p.ip !== player.ip; });
            renderPreviewTables();
            showToast(tSite('preview.toast_excluded', { ip: player.ip }));
        }));

        menu.appendChild(createCtxItem('globe', tApp("Filter ISP '{isp}'", { isp: player.isp }), function filterIsp() {
            simState.connected = simState.connected.filter(function keep(p) { return p.isp !== player.isp; });
            simState.disconnected = simState.disconnected.filter(function keep(p) { return p.isp !== player.isp; });
            renderPreviewTables();
            showToast(tSite('preview.toast_filtered_isp', { isp: player.isp }));
        }));

        menu.appendChild(createCtxItem('search', tApp('IP Lookup Details'), function showLookup() {
            showDemoFeatureToast(tApp('IP Lookup Details'));
        }));

        if (!isDisconnected) {
            menu.appendChild(createCtxItem('chart-line', tApp('Rate Graph'), function openRateGraph() {
                showDemoFeatureToast(tApp('Rate Graph'));
            }));
        }

        menu.appendChild(createCtxItem(
            'gauge',
            tApp(player.highRate ? 'Unblacklist from Player High Rate Monitor' : 'Blacklist in Player High Rate Monitor'),
            function showHrmDemoNotice() {
                showDemoFeatureToast(tApp('Player High Rate Monitor'));
            },
        ));

        menu.appendChild(createCtxSeparator());

        /* Submenus: Looky System, Ping, Scan Ports, UserIP, Search in... */
        if (simState.presetKey === 'gta5' && !player.isServer) {
            var lookyItems = [
                createCtxItem('globe', tApp('Open Website'), function openLookyWebsite() {
                    window.open('https://looky-gta.cc', '_blank', 'noopener,noreferrer');
                }),
            ];
            if (player.source === 'looky') {
                lookyItems.push(createCtxItem('globe', tApp('View on Website'), function openLookyProfile() {
                    showDemoFeatureToast(tApp('View on Website'));
                }));
            }
            lookyItems.push(createCtxSeparator());
            lookyItems.push(createCtxItem('user-round', tApp('Lookup'), function runLookyLookup() {
                showDemoFeatureToast(tApp('Lookup'));
            }));
            if (player.source === 'looky') {
                lookyItems.push(createCtxItem('bot', tApp('Call Crawler'), function runLookyCrawler() {
                    showDemoFeatureToast(tApp('Call Crawler'));
                }));
                lookyItems.push(createCtxItem('user-plus', tApp('Proxy Join'), function runLookyProxyJoin() {
                    showDemoFeatureToast(tApp('Proxy Join'));
                }));
                lookyItems.push(createCtxSeparator());
                lookyItems.push(createCtxItem('remove', tApp('Remove Looky Usernames…'), function removeLookyNames() {
                    showDemoFeatureToast(tApp('Remove Looky Usernames…'));
                }));
            }
            menu.appendChild(createCtxSubmenu('scan-eye', tApp('Looky System'), lookyItems, openLeft));
        }

        menu.appendChild(createCtxSubmenu('activity', tApp('Ping'), [
            createCtxItem('activity', tApp('ICMP Ping'), function runPing() {
                showDemoFeatureToast(tApp('ICMP Ping'));
            }),
            createCtxItem('globe', tApp('Web (Check-Host)…'), function runCheckHost() {
                showDemoFeatureToast(tApp('Web (Check-Host)…'));
            }),
        ], openLeft));

        menu.appendChild(createCtxItem('radar', tApp('Scan Ports…'), function runPortScan() {
            showDemoFeatureToast(tApp('Scan Ports…'));
        }));

        var userIpSubItems = [];
        if (player.source !== 'userip') {
            userIpSubItems.push(createCtxItem('user-plus', tSite('preview.ctx_add_userip'), function addUserIp() {
                showDemoFeatureToast(tApp('UserIP'));
            }));
        } else {
            userIpSubItems.push(createCtxItem('remove', tSite('preview.ctx_remove_userip'), function removeUserIp() {
                showDemoFeatureToast(tApp('UserIP'));
            }, { danger: true }));
        }
        menu.appendChild(createCtxSubmenu('database', tApp('UserIP'), userIpSubItems, openLeft));

        menu.appendChild(createCtxSubmenu('search', tApp('Search in…'), [
            createCtxItem('database', tApp('UserIP All Databases'), function searchUserIp() {
                showDemoFeatureToast(tApp('UserIP All Databases'));
            }),
            createCtxItem('file-text', tApp('UserIP Logging'), function searchUserIpLogs() {
                showDemoFeatureToast(tApp('UserIP Logging'));
            }),
            createCtxItem('folder', tApp('Sessions Logging'), function searchSessionLogs() {
                showDemoFeatureToast(tApp('Sessions Logging'));
            }),
        ], openLeft));

        menu.classList.toggle('is-compact', sizingSpec.compact);
        menu.hidden = false;

        /* Smartly size & clamp strictly inside active viewport (or rotated fullscreen stage) */
        menu.style.left = '0px';
        menu.style.top = '0px';
        menu.style.transform = '';
        menu.style.transformOrigin = '';
        var menuW = menu.offsetWidth;
        var menuH = menu.offsetHeight;
        var scaleW = menuW > 0 ? (sizingSpec.maxMenuW / menuW) : 1;
        var scaleH = menuH > 0 ? (sizingSpec.maxMenuH / menuH) : 1;
        var fitScale = Math.min(sizingSpec.baseScale, scaleW, scaleH);
        if (fitScale < 0.999) {
            menu.style.transformOrigin = 'top left';
            menu.style.transform = 'scale(' + fitScale.toFixed(4) + ')';
        } else {
            fitScale = 1;
        }
        var effectiveW = menuW * fitScale;
        var effectiveH = menuH * fitScale;
        var margin = sizingSpec.margin;
        var topInset = sizingSpec.topInset;
        var maxLeft = Math.max(margin, boundsW - effectiveW - margin);
        var maxTop = Math.max(topInset, boundsH - effectiveH - margin);
        var preferredLeft = isRtl ? (clickX - effectiveW) : clickX;
        var left = Math.max(margin, Math.min(preferredLeft, maxLeft));
        var top = Math.max(topInset, Math.min(clickY, maxTop));
        menu.style.left = left + 'px';
        menu.style.top = top + 'px';

        contextMenuLayout = {
            left: left,
            top: top,
            width: effectiveW,
            height: effectiveH,
            scale: fitScale,
            compact: sizingSpec.compact,
            margin: margin,
            topInset: topInset,
            boundsW: boundsW,
            boundsH: boundsH,
            isRtl: isRtl,
        };
    }

    function createConnectedRow(player, isDisconnected) {
        var tr = document.createElement('tr');
        var classes = [isDisconnected ? 'ss-row-disconnected' : 'ss-row-connected'];
        if (player.isServer) {
            classes.push('ss-row-server');
        } else {
            if (player.pastSession) {
                classes.push('ss-row-past');
            }
            if (player.source === 'looky') {
                classes.push('ss-row-looky');
            } else if (player.source === 'userip') {
                classes.push('ss-row-userip');
            }
        }
        if (player.id === simState.selectedId) {
            classes.push('is-selected');
        }
        tr.className = classes.join(' ');
        tr.setAttribute('data-player-id', player.id);

        tr.appendChild(buildUsernameCell(player));
        tr.appendChild(makeTextCell(formatElapsed(player.firstSeenSec || player.rejoinSec), 'mono'));
        tr.appendChild(makeTextCell(
            isDisconnected ? formatElapsed(player.rejoinSec || player.lastSeenSec) : formatElapsed(player.rejoinSec),
            'mono',
        ));
        tr.appendChild(makeTextCell(formatNumber(player.rejoins || 0), 'num'));
        tr.appendChild(makeTextCell(formatNumber(player.packets), 'num'));
        var ppsValue = isDisconnected ? 0 : (player.pps || 0);
        var bpsValue = isDisconnected ? 0 : (player.bps || 0);
        tr.appendChild(makeRateCell(formatNumber(ppsValue), ppsValue, PPS_MAX_THRESHOLD, Boolean(player.isServer)));
        tr.appendChild(makeTextCell(formatBytes(player.bytes), 'num'));
        tr.appendChild(makeRateCell(formatBytes(bpsValue), bpsValue, BPS_MAX_THRESHOLD, Boolean(player.isServer)));
        var connectedHost = getDisplayHostname(player);
        tr.appendChild(buildIpCell(player, isDisconnected));
        tr.appendChild(makeTextCell(connectedHost, 'mono col-elide', connectedHost));
        tr.appendChild(makeTextCell(player.ports, 'mono'));
        tr.appendChild(buildCountryCell(player));
        tr.appendChild(makeTextCell(player.region || '', 'col-elide', player.region || ''));
        tr.appendChild(makeTextCell(player.isp, 'col-elide', player.isp));
        tr.appendChild(makeTextCell(tApp(player.mobile ? 'Yes' : 'No')));
        tr.appendChild(makeTextCell(tApp(player.vpn ? 'Yes' : 'No'), player.vpn ? 'vpn-yes' : ''));
        tr.appendChild(makeTextCell(tApp(player.hosting ? 'Yes' : 'No')));
        tr.appendChild(makeTextCell(tApp(!isDisconnected && player.pinging ? 'Yes' : 'No')));

        tr.addEventListener('click', function onRowClick() {
            simState.selectedId = simState.selectedId === player.id ? null : player.id;
            renderPreviewTables();
        });

        tr.addEventListener('contextmenu', function onContextMenu(ev) {
            ev.preventDefault();
            ev.stopPropagation();
            if (Date.now() < touchLongPressState.suppressContextMenuUntil) {
                return;
            }
            clearTouchLongPressTimer();
            var cell = ev.target && ev.target.closest ? ev.target.closest('td') : null;
            openRowContextMenu(ev.clientX, ev.clientY, player, isDisconnected, cell ? cell.textContent : player.ip);
        });

        return tr;
    }

    function createDisconnectedRow(player) {
        var tr = document.createElement('tr');
        var classes = ['ss-row-disconnected'];
        if (player.isServer) {
            classes.push('ss-row-server');
        } else {
            if (player.pastSession) {
                classes.push('ss-row-past');
            }
            if (player.source === 'looky') {
                classes.push('ss-row-looky');
            } else if (player.source === 'userip') {
                classes.push('ss-row-userip');
            }
        }
        if (player.id === simState.selectedId) {
            classes.push('is-selected');
        }
        tr.className = classes.join(' ');
        tr.setAttribute('data-player-id', player.id);

        tr.appendChild(buildUsernameCell(player));
        tr.appendChild(makeTextCell(formatElapsed(player.firstSeenSec || player.lastSeenSec), 'mono'));
        tr.appendChild(makeTextCell(formatElapsed(player.rejoinSec || player.firstSeenSec || player.lastSeenSec), 'mono'));
        tr.appendChild(makeTextCell(formatElapsed(player.lastSeenSec), 'mono'));
        tr.appendChild(makeTextCell(formatDuration(player.totalSessionSec || player.sessionSec), 'mono'));
        tr.appendChild(makeTextCell(formatDuration(player.sessionSec), 'mono'));
        tr.appendChild(makeTextCell(formatNumber(player.rejoins || 0), 'num'));
        tr.appendChild(makeTextCell(formatNumber(player.packets), 'num'));
        tr.appendChild(makeTextCell(formatBytes(player.bytes), 'num'));
        var disconnectedHost = getDisplayHostname(player);
        tr.appendChild(buildIpCell(player, true));
        tr.appendChild(makeTextCell(disconnectedHost, 'mono col-elide', disconnectedHost));
        tr.appendChild(makeTextCell(player.ports, 'mono'));
        tr.appendChild(buildCountryCell(player));
        tr.appendChild(makeTextCell(player.region || '', 'col-elide', player.region || ''));
        tr.appendChild(makeTextCell(player.isp, 'col-elide', player.isp));
        tr.appendChild(makeTextCell(tApp(player.mobile ? 'Yes' : 'No')));
        tr.appendChild(makeTextCell(tApp(player.vpn ? 'Yes' : 'No'), player.vpn ? 'vpn-yes' : ''));
        tr.appendChild(makeTextCell(tApp(player.hosting ? 'Yes' : 'No')));
        tr.appendChild(makeTextCell(tApp('No')));

        tr.addEventListener('click', function onRowClick() {
            simState.selectedId = simState.selectedId === player.id ? null : player.id;
            renderPreviewTables();
        });

        tr.addEventListener('contextmenu', function onContextMenu(ev) {
            ev.preventDefault();
            ev.stopPropagation();
            if (Date.now() < touchLongPressState.suppressContextMenuUntil) {
                return;
            }
            clearTouchLongPressTimer();
            var cell = ev.target && ev.target.closest ? ev.target.closest('td') : null;
            openRowContextMenu(ev.clientX, ev.clientY, player, true, cell ? cell.textContent : player.ip);
        });

        return tr;
    }

    function updateSpinboxControls(kind, totalCount, rowLimit, currentPage) {
        var rowsVal = document.getElementById('ss-' + kind + '-rows-val');
        var rowsUp = document.getElementById('ss-' + kind + '-rows-up');
        var rowsDown = document.getElementById('ss-' + kind + '-rows-down');
        var pageVal = document.getElementById('ss-' + kind + '-page');
        var pageUp = document.getElementById('ss-' + kind + '-page-up');
        var pageDown = document.getElementById('ss-' + kind + '-page-down');
        var clearBtn = document.getElementById('ss-' + kind + '-clear');

        var totalPages = rowLimit > 0 ? Math.max(1, Math.ceil(totalCount / rowLimit)) : 1;
        var clampedPage = Math.max(1, Math.min(currentPage, totalPages));
        var stepIdx = ROWS_LIMIT_STEPS.indexOf(rowLimit);

        if (rowsVal) {
            rowsVal.textContent = rowLimit === 0 ? tApp('All ({count})', { count: totalCount }) : String(rowLimit);
        }
        if (rowsUp) {
            rowsUp.disabled = stepIdx >= ROWS_LIMIT_STEPS.length - 1;
        }
        if (rowsDown) {
            rowsDown.disabled = stepIdx <= 0;
        }
        if (pageVal) {
            pageVal.textContent = clampedPage + ' / ' + totalPages;
        }
        if (pageUp) {
            pageUp.disabled = clampedPage >= totalPages;
        }
        if (pageDown) {
            pageDown.disabled = clampedPage <= 1;
        }
        if (clearBtn) {
            clearBtn.disabled = totalCount === 0;
        }
        return clampedPage;
    }

    var PREVIEW_STAGE_BREAKPOINT_PX = 900;
    var PREVIEW_STAGE_CANVAS_WIDTH = 1220;

    var previewStageState = {
        inlineMode: 'fit',
        fullscreenMode: 'fit',
        fullscreen: false,
        rotateInFullscreen: true,
        rotated: false,
        scale: 1,
    };

    function isPreviewStageActive() {
        return previewStageState.fullscreen || window.innerWidth <= PREVIEW_STAGE_BREAKPOINT_PX;
    }

    function syncFullscreenOverlayPortals(shell, isFullscreen) {
        var toastRegion = document.getElementById('toast-region');
        if (!toastRegion) {
            return;
        }
        var targetHost = isFullscreen && shell ? shell : document.body;
        if (toastRegion.parentNode !== targetHost) {
            targetHost.appendChild(toastRegion);
        }
    }

    function updatePreviewStageLayout() {
        var shell = document.getElementById('ss-stage-shell');
        var bar = document.getElementById('ss-stage-bar');
        var viewport = document.getElementById('ss-stage-viewport');
        var sizer = document.getElementById('ss-stage-sizer');
        var canvas = document.getElementById('ss-stage-canvas');
        var workspace = document.querySelector('.ss-workspace');
        var panBtn = document.getElementById('ss-stage-pan-btn');
        var fitBtn = document.getElementById('ss-stage-fit-btn');
        var fsBtn = document.getElementById('ss-stage-fs-btn');
        var exitBtn = document.getElementById('ss-stage-exit-btn');
        var rotateBtn = document.getElementById('ss-stage-rotate-btn');
        if (!shell || !viewport || !sizer || !canvas) {
            return;
        }

        var active = isPreviewStageActive();
        var isFullscreen = previewStageState.fullscreen;
        var isPortrait = window.innerHeight > window.innerWidth;
        var shouldRotate = isFullscreen && isPortrait && previewStageState.rotateInFullscreen;
        var mode = isFullscreen ? previewStageState.fullscreenMode : previewStageState.inlineMode;

        var rotationChanged = previewStageState.rotated !== shouldRotate;
        previewStageState.rotated = shouldRotate;

        shell.classList.toggle('is-stage-active', active);
        shell.classList.toggle('is-fullscreen', isFullscreen);
        shell.classList.toggle('is-rotated', shouldRotate);
        shell.classList.toggle('is-fit-mode', active && mode === 'fit');
        document.documentElement.classList.toggle('ss-preview-fullscreen-open', isFullscreen);
        document.body.classList.toggle('ss-preview-fullscreen-open', isFullscreen);
        syncFullscreenOverlayPortals(shell, isFullscreen);
        if (rotationChanged) {
            hideRichTooltip();
            closeContextMenu();
        }

        if (panBtn && fitBtn) {
            var isPan = mode === 'pan';
            panBtn.classList.toggle('is-active', isPan);
            panBtn.setAttribute('aria-pressed', isPan ? 'true' : 'false');
            fitBtn.classList.toggle('is-active', !isPan);
            fitBtn.setAttribute('aria-pressed', !isPan ? 'true' : 'false');
        }
        if (fsBtn) {
            fsBtn.hidden = isFullscreen;
            fsBtn.setAttribute('aria-expanded', isFullscreen ? 'true' : 'false');
        }
        if (exitBtn) {
            exitBtn.hidden = !isFullscreen;
        }
        if (rotateBtn) {
            rotateBtn.hidden = !(isFullscreen && isPortrait);
        }

        if (!active) {
            previewStageState.scale = 1;
            sizer.style.width = '';
            sizer.style.height = '';
            canvas.style.transform = '';
            if (workspace) {
                workspace.style.height = '';
            }
            applySplitterLayout();
            return;
        }

        var liveWin = document.getElementById('ss-live-window');
        var availW = Math.max(260, viewport.clientWidth || (shouldRotate ? window.innerHeight : window.innerWidth));
        var availH = isFullscreen
            ? Math.max(200, viewport.clientHeight || ((shouldRotate ? window.innerWidth : window.innerHeight) - (bar ? bar.offsetHeight : 44)))
            : 0;

        if (mode === 'fit') {
            var scale = Math.min(1, availW / PREVIEW_STAGE_CANVAS_WIDTH);
            if (isFullscreen && workspace) {
                var chromeH = liveWin
                    ? Math.max(120, liveWin.offsetHeight - workspace.offsetHeight)
                    : 148;
                var targetWsH = Math.max(290, Math.min(540, Math.floor((availH / scale) - chromeH)));
                workspace.style.height = targetWsH + 'px';
            } else if (workspace) {
                workspace.style.height = '';
            }
            applySplitterLayout();
            var naturalH = (liveWin ? liveWin.offsetHeight : canvas.offsetHeight) || 644;
            if (isFullscreen && naturalH * scale > availH) {
                scale = Math.min(scale, availH / naturalH);
            }
            previewStageState.scale = scale;
            sizer.style.width = Math.round(PREVIEW_STAGE_CANVAS_WIDTH * scale) + 'px';
            sizer.style.height = Math.round(naturalH * scale) + 'px';
            canvas.style.transform = 'scale(' + scale.toFixed(4) + ')';
        } else {
            previewStageState.scale = 1;
            if (workspace) {
                workspace.style.height = isFullscreen ? Math.max(320, availH - 148) + 'px' : '';
            }
            applySplitterLayout();
            sizer.style.width = PREVIEW_STAGE_CANVAS_WIDTH + 'px';
            sizer.style.height = '';
            canvas.style.transform = '';
        }
    }

    function openPreviewFullscreen() {
        previewStageState.fullscreen = true;
        previewStageState.rotateInFullscreen = true;
        previewStageState.fullscreenMode = 'fit';
        hideRichTooltip();
        closeAllAppMenus();
        closeContextMenu();
        closeSearchColumnPopup();
        closeLangDropdown();
        closeThemeDropdown();
        closeMobileNavDrawer();
        updatePreviewStageLayout();
        if (typeof window.requestAnimationFrame === 'function') {
            window.requestAnimationFrame(updatePreviewStageLayout);
        }
    }

    function closePreviewFullscreen() {
        if (!previewStageState.fullscreen) {
            return;
        }
        previewStageState.fullscreen = false;
        hideRichTooltip();
        closeAllAppMenus();
        closeContextMenu();
        closeSearchColumnPopup();
        updatePreviewStageLayout();
    }

    function getSplitterBounds(workspace, connectedSection, disconnectedSection, splitterHandle) {
        var wsStyle = window.getComputedStyle(workspace);
        var padY = (parseFloat(wsStyle.paddingTop) || 0) + (parseFloat(wsStyle.paddingBottom) || 0);
        var handleOuter = splitterHandle ? (splitterHandle.offsetHeight + 6) : 12;
        var baseMin = previewStageState.fullscreen ? 86 : MIN_SECTION_HEIGHT_PX;
        var avail = Math.max(baseMin * 2, workspace.clientHeight - padY - handleOuter);
        var connBar = connectedSection ? connectedSection.querySelector('.ss-section-bar') : null;
        var discBar = disconnectedSection ? disconnectedSection.querySelector('.ss-section-bar') : null;
        var connMin = Math.max(baseMin, connBar ? Math.ceil(connBar.offsetHeight + 48) : baseMin);
        var discMin = Math.max(baseMin, discBar ? Math.ceil(discBar.offsetHeight + 48) : baseMin);
        var minH = Math.min(connMin, Math.floor(avail / 2));
        var maxH = Math.max(minH, avail - Math.min(discMin, Math.floor(avail / 2)));
        return { avail: avail, minH: minH, maxH: maxH };
    }

    function applySplitterLayout() {
        var workspace = document.querySelector('.ss-workspace');
        var connectedSection = document.getElementById('ss-connected-section');
        var disconnectedSection = document.getElementById('ss-disconnected-section');
        var splitterHandle = document.getElementById('ss-splitter-handle');
        if (!workspace || !connectedSection || !disconnectedSection) {
            return;
        }
        if (simState.merged || !simState.connectedExpanded || !simState.disconnectedExpanded) {
            connectedSection.style.flex = '1 1 0';
            disconnectedSection.style.flex = '1 1 0';
            return;
        }
        var bounds = getSplitterBounds(workspace, connectedSection, disconnectedSection, splitterHandle);
        var connH = Math.round(Math.max(bounds.minH, Math.min(bounds.maxH, bounds.avail * simState.splitterRatio)));
        connectedSection.style.flex = '0 0 ' + connH + 'px';
        disconnectedSection.style.flex = '1 1 0';
    }

    function updateSectionVisibility(filteredConnectedCount, filteredDisconnectedCount) {
        var connectedSection = document.getElementById('ss-connected-section');
        var disconnectedSection = document.getElementById('ss-disconnected-section');
        var splitterHandle = document.getElementById('ss-splitter-handle');
        var placeholder = document.getElementById('ss-minimized-placeholder');
        var connectedCollapse = document.getElementById('ss-connected-collapse');
        var disconnectedCollapse = document.getElementById('ss-disconnected-collapse');
        var connectedExpand = document.getElementById('ss-connected-expand');
        var disconnectedExpand = document.getElementById('ss-disconnected-expand');

        if (simState.merged) {
            if (connectedSection) {
                connectedSection.hidden = false;
            }
            if (disconnectedSection) {
                disconnectedSection.hidden = true;
            }
            if (splitterHandle) {
                splitterHandle.hidden = true;
            }
            if (placeholder) {
                placeholder.hidden = true;
            }
            if (connectedCollapse) {
                connectedCollapse.hidden = true;
            }
            if (disconnectedCollapse) {
                disconnectedCollapse.hidden = true;
            }
            if (connectedExpand) {
                connectedExpand.hidden = true;
            }
            if (disconnectedExpand) {
                disconnectedExpand.hidden = true;
            }
            applySplitterLayout();
            return;
        }

        if (connectedCollapse) {
            connectedCollapse.hidden = false;
        }
        if (disconnectedCollapse) {
            disconnectedCollapse.hidden = false;
        }
        if (connectedSection) {
            connectedSection.hidden = !simState.connectedExpanded;
        }
        if (disconnectedSection) {
            disconnectedSection.hidden = !simState.disconnectedExpanded;
        }
        if (splitterHandle) {
            splitterHandle.hidden = !(simState.connectedExpanded && simState.disconnectedExpanded);
        }
        if (placeholder) {
            placeholder.hidden = simState.connectedExpanded || simState.disconnectedExpanded;
        }
        if (connectedExpand) {
            connectedExpand.hidden = simState.connectedExpanded;
            connectedExpand.textContent = tApp('Show Connected Players ({count})', { count: filteredConnectedCount });
        }
        if (disconnectedExpand) {
            disconnectedExpand.hidden = simState.disconnectedExpanded;
            disconnectedExpand.textContent = tApp('Show Disconnected Players ({count})', { count: filteredDisconnectedCount });
        }
        applySplitterLayout();
    }

    function parseIpv4ForSort(ipStr) {
        var parts = String(ipStr || '').split('.');
        if (parts.length !== 4) {
            return 0;
        }
        var total = 0;
        for (var i = 0; i < 4; i += 1) {
            var n = Number(parts[i]);
            if (Number.isNaN(n)) {
                return 0;
            }
            total = (total * 256) + n;
        }
        return total;
    }

    function parsePortsForSort(portsStr) {
        var parts = String(portsStr || '').split(',');
        var nums = [];
        for (var i = 0; i < parts.length; i += 1) {
            var trimmed = parts[i].trim();
            if (/^\d+$/.test(trimmed)) {
                nums.push(Number(trimmed));
            }
        }
        return nums;
    }

    function comparePortTuples(a, b) {
        var len = Math.min(a.length, b.length);
        for (var i = 0; i < len; i += 1) {
            if (a[i] !== b[i]) {
                return a[i] - b[i];
            }
        }
        return a.length - b.length;
    }

    function getDisplayUsernameForSort(player) {
        var baseName = player.username || '';
        return (player.note && baseName ? baseName + ' (' + player.note + ')' : baseName).toLowerCase();
    }

    function comparePlayerEntries(entryA, entryB, col, dir) {
        var a = entryA.player;
        var b = entryB.player;
        var discA = entryA.disc;
        var discB = entryB.disc;
        var cmp = 0;

        if (col === 'username') {
            cmp = getDisplayUsernameForSort(a).localeCompare(getDisplayUsernameForSort(b));
        } else if (col === 'firstSeen') {
            cmp = (a.firstSeenSec || a.rejoinSec || a.lastSeenSec || 0) - (b.firstSeenSec || b.rejoinSec || b.lastSeenSec || 0);
        } else if (col === 'lastRejoin') {
            cmp = (a.rejoinSec || a.lastSeenSec || 0) - (b.rejoinSec || b.lastSeenSec || 0);
        } else if (col === 'lastSeen') {
            cmp = (a.lastSeenSec || 0) - (b.lastSeenSec || 0);
        } else if (col === 'totalSessionTime') {
            cmp = (a.totalSessionSec || a.sessionSec || 0) - (b.totalSessionSec || b.sessionSec || 0);
        } else if (col === 'sessionTime') {
            cmp = (a.sessionSec || 0) - (b.sessionSec || 0);
            if (cmp === 0) {
                cmp = parseIpv4ForSort(a.ip) - parseIpv4ForSort(b.ip);
            }
        } else if (col === 'rejoins') {
            cmp = (a.rejoins || 0) - (b.rejoins || 0);
        } else if (col === 'packets') {
            cmp = (a.packets || 0) - (b.packets || 0);
        } else if (col === 'pps') {
            cmp = (discA ? 0 : (a.pps || 0)) - (discB ? 0 : (b.pps || 0));
        } else if (col === 'bandwidth') {
            cmp = (a.bytes || 0) - (b.bytes || 0);
        } else if (col === 'bps') {
            cmp = (discA ? 0 : (a.bps || 0)) - (discB ? 0 : (b.bps || 0));
        } else if (col === 'ip') {
            cmp = parseIpv4ForSort(a.ip) - parseIpv4ForSort(b.ip);
        } else if (col === 'hostname') {
            cmp = getDisplayHostname(a).toLowerCase().localeCompare(getDisplayHostname(b).toLowerCase());
        } else if (col === 'ports') {
            cmp = comparePortTuples(parsePortsForSort(a.ports), parsePortsForSort(b.ports));
        } else if (col === 'country') {
            cmp = String(a.country || '').toLowerCase().localeCompare(String(b.country || '').toLowerCase());
        } else if (col === 'region') {
            cmp = String(a.region || '').toLowerCase().localeCompare(String(b.region || '').toLowerCase());
        } else if (col === 'isp') {
            cmp = String(a.isp || '').toLowerCase().localeCompare(String(b.isp || '').toLowerCase());
        } else if (col === 'mobile') {
            cmp = tApp(a.mobile ? 'Yes' : 'No').toLowerCase().localeCompare(tApp(b.mobile ? 'Yes' : 'No').toLowerCase());
        } else if (col === 'vpn') {
            cmp = tApp(a.vpn ? 'Yes' : 'No').toLowerCase().localeCompare(tApp(b.vpn ? 'Yes' : 'No').toLowerCase());
        } else if (col === 'hosting') {
            cmp = tApp(a.hosting ? 'Yes' : 'No').toLowerCase().localeCompare(tApp(b.hosting ? 'Yes' : 'No').toLowerCase());
        } else if (col === 'ping') {
            cmp = tApp(!discA && a.pinging ? 'Yes' : 'No').toLowerCase().localeCompare(tApp(!discB && b.pinging ? 'Yes' : 'No').toLowerCase());
        }

        if (cmp === 0) {
            cmp = parseIpv4ForSort(a.ip) - parseIpv4ForSort(b.ip);
        }
        return dir === 'desc' ? -cmp : cmp;
    }

    function updateSortHeaderIndicators() {
        document.querySelectorAll('th[data-sort-table]').forEach(function syncTh(th) {
            var tableKey = th.getAttribute('data-sort-table');
            var col = th.getAttribute('data-sort-col');
            var sortState = tableKey === 'disconnected' ? simState.disconnectedSort : simState.connectedSort;
            var isSorted = sortState.col === col;
            th.classList.toggle('is-sorted', isSorted);
            th.setAttribute('aria-sort', isSorted ? (sortState.dir === 'asc' ? 'ascending' : 'descending') : 'none');
            var useEl = th.querySelector('.ss-sort-arrow use');
            if (useEl) {
                useEl.setAttribute('href', (isSorted && sortState.dir === 'asc') ? '#icon-chevron-up' : '#icon-chevron-down');
            }
        });
    }

    /* Mirrors SessionTableView._paint_empty_state() in src/session_sniffer/guis/tables.py */
    function setTableEmptyState(kind, isEmpty, hasSearch, hasRegistryPlayers, isMerged) {
        var box = document.getElementById('ss-' + kind + '-empty');
        var titleEl = document.getElementById('ss-' + kind + '-empty-title');
        var subtitleEl = document.getElementById('ss-' + kind + '-empty-subtitle');
        if (!box) {
            return;
        }
        if (!isEmpty) {
            box.hidden = true;
            return;
        }
        var titleKey;
        var subtitleKey;
        if (hasSearch && hasRegistryPlayers) {
            if (kind === 'connected') {
                titleKey = isMerged ? 'No matching players' : 'No matching connected players';
            } else {
                titleKey = 'No matching disconnected players';
            }
            subtitleKey = 'No players match the current search filter.';
        } else if (kind === 'connected') {
            titleKey = isMerged ? 'No players' : 'No connected players';
            subtitleKey = isMerged ? 'Players will appear here.' : 'Connected players will appear here.';
        } else {
            titleKey = 'No disconnected players';
            subtitleKey = 'Disconnected players will appear here.';
        }
        if (titleEl) {
            titleEl.textContent = tApp(titleKey);
        }
        if (subtitleEl) {
            subtitleEl.textContent = tApp(subtitleKey);
        }
        box.hidden = false;
    }

    function renderPreviewTables() {
        var connectedBody = document.getElementById('ss-connected-tbody');
        var disconnectedBody = document.getElementById('ss-disconnected-tbody');
        var connectedTitle = document.getElementById('ss-connected-title');
        var disconnectedTitle = document.getElementById('ss-disconnected-title');

        if (!connectedBody || !disconnectedBody) {
            return;
        }

        var hasSearch = Boolean(simState.searchQuery && simState.searchQuery.trim());
        var filteredConnected = simState.connected.filter(matchesSearch);
        var filteredDisconnected = simState.disconnected.filter(matchesSearch);

        updateSectionVisibility(filteredConnected.length, filteredDisconnected.length);
        updateSortHeaderIndicators();

        var mergeLabel = tApp(simState.merged ? 'SPLIT' : 'MERGE');
        ['ss-merge-btn', 'ss-disconnected-merge-btn'].forEach(function syncMergeBtn(id) {
            var btn = document.getElementById(id);
            if (btn) {
                btn.setAttribute('aria-pressed', simState.merged ? 'true' : 'false');
                btn.textContent = mergeLabel;
            }
        });

        connectedBody.innerHTML = '';
        if (simState.merged) {
            var mergedTotal = filteredConnected.length + filteredDisconnected.length;
            if (connectedTitle) {
                connectedTitle.textContent = tApp('Players ({count})', { count: mergedTotal });
            }
            simState.connectedPage = updateSpinboxControls('connected', mergedTotal, simState.connectedRowLimit, simState.connectedPage);
            var mergedPairs = [];
            filteredConnected.forEach(function pushC(p) { mergedPairs.push({ player: p, disc: false }); });
            filteredDisconnected.forEach(function pushD(p) { mergedPairs.push({ player: p, disc: true }); });
            mergedPairs.sort(function sortMerged(a, b) {
                return comparePlayerEntries(a, b, simState.connectedSort.col, simState.connectedSort.dir);
            });
            var visibleMerged = simState.connectedRowLimit > 0
                ? mergedPairs.slice((simState.connectedPage - 1) * simState.connectedRowLimit, simState.connectedPage * simState.connectedRowLimit)
                : mergedPairs;
            setTableEmptyState(
                'connected',
                visibleMerged.length === 0,
                hasSearch,
                (simState.connected.length + simState.disconnected.length) > 0,
                true,
            );
            setTableEmptyState('disconnected', false, false, false, false);
            visibleMerged.forEach(function addM(pair) { connectedBody.appendChild(createConnectedRow(pair.player, pair.disc)); });
            return;
        }

        if (connectedTitle) {
            connectedTitle.textContent = tApp('Connected Players ({count})', { count: filteredConnected.length });
        }
        if (disconnectedTitle) {
            disconnectedTitle.textContent = tApp('Disconnected Players ({count})', { count: filteredDisconnected.length });
        }

        var sortedConnected = filteredConnected
            .map(function wrapC(p) { return { player: p, disc: false }; })
            .sort(function sortC(a, b) {
                return comparePlayerEntries(a, b, simState.connectedSort.col, simState.connectedSort.dir);
            })
            .map(function unwrapC(entry) { return entry.player; });

        simState.connectedPage = updateSpinboxControls('connected', sortedConnected.length, simState.connectedRowLimit, simState.connectedPage);
        var visibleConnected = simState.connectedRowLimit > 0
            ? sortedConnected.slice((simState.connectedPage - 1) * simState.connectedRowLimit, simState.connectedPage * simState.connectedRowLimit)
            : sortedConnected;
        setTableEmptyState('connected', visibleConnected.length === 0, hasSearch, simState.connected.length > 0, false);
        visibleConnected.forEach(function addC(p) { connectedBody.appendChild(createConnectedRow(p, false)); });

        disconnectedBody.innerHTML = '';
        var sortedDisconnected = filteredDisconnected
            .map(function wrapD(p) { return { player: p, disc: true }; })
            .sort(function sortD(a, b) {
                return comparePlayerEntries(a, b, simState.disconnectedSort.col, simState.disconnectedSort.dir);
            })
            .map(function unwrapD(entry) { return entry.player; });

        simState.disconnectedPage = updateSpinboxControls('disconnected', sortedDisconnected.length, simState.disconnectedRowLimit, simState.disconnectedPage);
        var visibleDisconnected = simState.disconnectedRowLimit > 0
            ? sortedDisconnected.slice((simState.disconnectedPage - 1) * simState.disconnectedRowLimit, simState.disconnectedPage * simState.disconnectedRowLimit)
            : sortedDisconnected;
        setTableEmptyState('disconnected', visibleDisconnected.length === 0, hasSearch, simState.disconnected.length > 0, false);
        visibleDisconnected.forEach(function addD(p) { disconnectedBody.appendChild(createDisconnectedRow(p)); });
    }

    function updateMetricsDisplay() {
        var uptimeEl = document.getElementById('ss-uptime-val');
        var packetsEl = document.getElementById('ss-packets-val');

        if (uptimeEl) {
            uptimeEl.textContent = formatUptime(simState.uptimeSeconds);
        }
        if (packetsEl) {
            packetsEl.textContent = formatNumber(simState.totalPackets);
        }
    }

    function tickSimulation() {
        simState.uptimeSeconds += 1;

        var deltaPackets = 0;
        simState.connected.forEach(function tickPlayer(player) {
            player.firstSeenSec = (player.firstSeenSec || player.rejoinSec) + 1;
            player.rejoinSec += 1;
            if (player.isServer) {
                player.pps = Math.floor(Math.random() * 4);
                player.packets += player.pps;
                player.bps = player.pps * 240;
                player.bytes += player.bps;
                deltaPackets += player.pps;
                return;
            }
            var jitter = player.highRate
                ? Math.floor(Math.random() * 48) - 18
                : Math.floor(Math.random() * 9) - 4;
            var minPps = player.highRate ? 95 : 5;
            var maxPps = player.highRate ? 195 : 42;
            player.pps = Math.max(minPps, Math.min(maxPps, player.pps + jitter));
            player.packets += player.pps;
            var addedBytes = player.pps * (360 + Math.floor(Math.random() * 140));
            player.bps = addedBytes;
            player.bytes += addedBytes;
            player.ping = Math.max(14, player.ping + Math.floor(Math.random() * 5) - 2);
            deltaPackets += player.pps;
        });

        simState.disconnected.forEach(function tickDisc(player) {
            player.firstSeenSec = (player.firstSeenSec || player.lastSeenSec) + 1;
            player.rejoinSec = (player.rejoinSec || player.firstSeenSec) + 1;
            player.lastSeenSec += 1;
        });

        simState.totalPackets += deltaPackets;
        updateMetricsDisplay();

        var latEl = document.getElementById('ss-status-latency');
        if (latEl) {
            latEl.textContent = tApp('{latency}ms', { latency: (0.3 + Math.random() * 0.4).toFixed(1) });
        }

        if (touchLongPressState.timer === null) {
            renderPreviewTables();
        }
    }

    function closeAllAppMenus() {
        document.querySelectorAll('.ss-menu-popup').forEach(function hide(popup) {
            popup.hidden = true;
        });
        document.querySelectorAll('.ss-menu-trigger').forEach(function reset(trigger) {
            trigger.setAttribute('aria-expanded', 'false');
        });
    }

    function closeSearchColumnPopup() {
        var btn = document.getElementById('ss-search-column');
        var popup = document.getElementById('ss-search-column-popup');
        if (btn && popup) {
            popup.hidden = true;
            btn.setAttribute('aria-expanded', 'false');
        }
    }

    function syncSearchColumnUi() {
        var label = document.getElementById('ss-search-column-label');
        var popup = document.getElementById('ss-search-column-popup');
        if (!popup) {
            return;
        }
        var activeOption = null;
        popup.querySelectorAll('.ss-search-combo-option').forEach(function syncOption(opt) {
            var isSelected = opt.getAttribute('data-search-col') === simState.searchColumn;
            opt.classList.toggle('is-selected', isSelected);
            opt.setAttribute('aria-selected', isSelected ? 'true' : 'false');
            if (isSelected) {
                activeOption = opt;
            }
        });
        if (!activeOption) {
            activeOption = popup.querySelector('.ss-search-combo-option[data-search-col="all"]');
            if (activeOption) {
                simState.searchColumn = 'all';
                activeOption.classList.add('is-selected');
                activeOption.setAttribute('aria-selected', 'true');
            }
        }
        if (label && activeOption) {
            var appKey = activeOption.getAttribute('data-i18n-app') || 'All Columns';
            label.setAttribute('data-i18n-app', appKey);
            label.textContent = tApp(appKey);
        }
    }

    function openSearchColumnPopup(focusSelected) {
        var btn = document.getElementById('ss-search-column');
        var popup = document.getElementById('ss-search-column-popup');
        if (!btn || !popup) {
            return;
        }
        closeLangDropdown();
        closeThemeDropdown();
        closeMobileNavDrawer();
        closeAllAppMenus();
        closeContextMenu();
        syncSearchColumnUi();
        popup.hidden = false;
        btn.setAttribute('aria-expanded', 'true');
        var activeOption = popup.querySelector('.ss-search-combo-option.is-selected');
        if (activeOption) {
            activeOption.scrollIntoView({ block: 'nearest' });
            if (focusSelected) {
                activeOption.focus();
            }
        }
    }

    function selectSearchColumn(colValue) {
        simState.searchColumn = colValue || 'all';
        syncSearchColumnUi();
        closeSearchColumnPopup();
        renderPreviewTables();
    }

    function toggleMergedTables() {
        simState.merged = !simState.merged;
        var searchInput = document.getElementById('ss-search-input');
        if (searchInput) {
            searchInput.placeholder = tApp(simState.merged ? 'Search players...' : 'Search connected + disconnected players...');
        }
        renderPreviewTables();
    }

    function initPreviewInteractions() {
        /* Preset buttons */
        document.querySelectorAll('[data-preset]').forEach(function wirePreset(btn) {
            btn.addEventListener('click', function onSelectPreset() {
                loadPreset(btn.getAttribute('data-preset'));
            });
        });

        /* Global search & column filter */
        var searchInput = document.getElementById('ss-search-input');
        var searchColumnBtn = document.getElementById('ss-search-column');
        var searchColumnPopup = document.getElementById('ss-search-column-popup');
        if (searchInput) {
            searchInput.addEventListener('input', function onSearch() {
                simState.searchQuery = searchInput.value;
                renderPreviewTables();
            });
        }
        if (searchColumnBtn && searchColumnPopup) {
            syncSearchColumnUi();
            var searchComboOptions = Array.prototype.slice.call(
                searchColumnPopup.querySelectorAll('.ss-search-combo-option')
            );

            searchColumnBtn.addEventListener('click', function onToggleColumnPopup(ev) {
                ev.stopPropagation();
                if (searchColumnPopup.hidden) {
                    openSearchColumnPopup(ev.detail === 0);
                } else {
                    closeSearchColumnPopup();
                }
            });

            searchColumnBtn.addEventListener('keydown', function onColumnBtnKeyDown(ev) {
                if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
                    ev.preventDefault();
                    var wasOpen = !searchColumnPopup.hidden;
                    if (!wasOpen) {
                        openSearchColumnPopup(true);
                        return;
                    }
                    var currentIdx = searchComboOptions.findIndex(function isCurrent(opt) {
                        return opt.classList.contains('is-selected');
                    });
                    if (currentIdx === -1) {
                        currentIdx = 0;
                    }
                    var delta = ev.key === 'ArrowDown' ? 1 : -1;
                    var targetIdx = (currentIdx + delta + searchComboOptions.length) % searchComboOptions.length;
                    if (searchComboOptions[targetIdx]) {
                        searchComboOptions[targetIdx].focus();
                    }
                } else if (ev.key === 'Escape') {
                    closeSearchColumnPopup();
                }
            });

            searchComboOptions.forEach(function wireColumnOption(opt, idx) {
                opt.addEventListener('click', function onPickColumn(ev) {
                    ev.stopPropagation();
                    selectSearchColumn(opt.getAttribute('data-search-col') || 'all');
                    searchColumnBtn.focus();
                });

                opt.addEventListener('keydown', function onOptionKeyDown(ev) {
                    if (ev.key === 'ArrowDown') {
                        ev.preventDefault();
                        var next = searchComboOptions[(idx + 1) % searchComboOptions.length];
                        if (next) {
                            next.focus();
                        }
                    } else if (ev.key === 'ArrowUp') {
                        ev.preventDefault();
                        var prev = searchComboOptions[(idx - 1 + searchComboOptions.length) % searchComboOptions.length];
                        if (prev) {
                            prev.focus();
                        }
                    } else if (ev.key === 'Home') {
                        ev.preventDefault();
                        if (searchComboOptions[0]) {
                            searchComboOptions[0].focus();
                        }
                    } else if (ev.key === 'End') {
                        ev.preventDefault();
                        if (searchComboOptions[searchComboOptions.length - 1]) {
                            searchComboOptions[searchComboOptions.length - 1].focus();
                        }
                    } else if (ev.key === 'Escape') {
                        ev.preventDefault();
                        closeSearchColumnPopup();
                        searchColumnBtn.focus();
                    } else if (ev.key === 'Tab') {
                        closeSearchColumnPopup();
                    }
                });
            });
        }

        /* Notification toggle buttons (left-click single, right-click toggle-all like _main_header.py) */
        var visualBtn = document.getElementById('ss-visual-notif-btn');
        var visualIcon = document.getElementById('ss-visual-notif-icon');
        var voiceBtn = document.getElementById('ss-voice-notif-btn');
        var voiceIcon = document.getElementById('ss-voice-notif-icon');

        function syncNotificationButtonsUi() {
            if (visualBtn) {
                visualBtn.classList.toggle('is-enabled', simState.visualAlerts);
                visualBtn.classList.toggle('is-muted', !simState.visualAlerts);
                visualBtn.setAttribute('aria-pressed', simState.visualAlerts ? 'true' : 'false');
                var vUse = visualIcon && visualIcon.querySelector('use');
                if (vUse) {
                    vUse.setAttribute('href', simState.visualAlerts ? '#icon-bell' : '#icon-bell-off');
                }
            }
            if (voiceBtn) {
                voiceBtn.classList.toggle('is-enabled', simState.voiceAlerts);
                voiceBtn.classList.toggle('is-muted', !simState.voiceAlerts);
                voiceBtn.setAttribute('aria-pressed', simState.voiceAlerts ? 'true' : 'false');
                var sUse = voiceIcon && voiceIcon.querySelector('use');
                if (sUse) {
                    sUse.setAttribute('href', simState.voiceAlerts ? '#icon-volume-2' : '#icon-volume-x');
                }
            }
        }

        function toggleAllNotifications(ev) {
            ev.preventDefault();
            var enableBoth = !(simState.visualAlerts || simState.voiceAlerts);
            simState.visualAlerts = enableBoth;
            simState.voiceAlerts = enableBoth;
            syncNotificationButtonsUi();
            showToast(tSite(enableBoth ? 'preview.toast_visual_on' : 'preview.toast_visual_off'));
        }

        if (visualBtn) {
            visualBtn.addEventListener('click', function toggleVisual() {
                simState.visualAlerts = !simState.visualAlerts;
                syncNotificationButtonsUi();
                showToast(tSite(simState.visualAlerts ? 'preview.toast_visual_on' : 'preview.toast_visual_off'));
            });
            visualBtn.addEventListener('contextmenu', toggleAllNotifications);
        }

        if (voiceBtn) {
            voiceBtn.addEventListener('click', function toggleVoice() {
                simState.voiceAlerts = !simState.voiceAlerts;
                syncNotificationButtonsUi();
                showToast(tSite(simState.voiceAlerts ? 'preview.toast_voice_on' : 'preview.toast_voice_off'));
            });
            voiceBtn.addEventListener('contextmenu', toggleAllNotifications);
        }

        /* Merge & Clear buttons */
        ['ss-merge-btn', 'ss-disconnected-merge-btn'].forEach(function wireMerge(id) {
            var btn = document.getElementById(id);
            if (btn) {
                btn.addEventListener('click', toggleMergedTables);
            }
        });

        var connClear = document.getElementById('ss-connected-clear');
        if (connClear) {
            connClear.addEventListener('click', function onClearConnected() {
                simState.connected = [];
                if (simState.merged) {
                    simState.disconnected = [];
                }
                simState.connectedPage = 1;
                simState.selectedId = null;
                renderPreviewTables();
                showToast(tSite('preview.toast_cleared'));
            });
        }

        var discClear = document.getElementById('ss-disconnected-clear');
        if (discClear) {
            discClear.addEventListener('click', function onClearDisconnected() {
                simState.disconnected = [];
                simState.disconnectedPage = 1;
                renderPreviewTables();
                showToast(tSite('preview.toast_cleared'));
            });
        }

        /* 1:1 QSpinBox Rows & Page controls */
        [
            { kind: 'connected', limitKey: 'connectedRowLimit', pageKey: 'connectedPage' },
            { kind: 'disconnected', limitKey: 'disconnectedRowLimit', pageKey: 'disconnectedPage' },
        ].forEach(function wireSpinboxes(cfg) {
            var rowsUp = document.getElementById('ss-' + cfg.kind + '-rows-up');
            var rowsDown = document.getElementById('ss-' + cfg.kind + '-rows-down');
            var pageUp = document.getElementById('ss-' + cfg.kind + '-page-up');
            var pageDown = document.getElementById('ss-' + cfg.kind + '-page-down');

            if (rowsUp) {
                rowsUp.addEventListener('click', function onRowsUp() {
                    var idx = ROWS_LIMIT_STEPS.indexOf(simState[cfg.limitKey]);
                    if (idx < ROWS_LIMIT_STEPS.length - 1) {
                        simState[cfg.limitKey] = ROWS_LIMIT_STEPS[idx + 1];
                        simState[cfg.pageKey] = 1;
                        renderPreviewTables();
                    }
                });
            }
            if (rowsDown) {
                rowsDown.addEventListener('click', function onRowsDown() {
                    var idx = ROWS_LIMIT_STEPS.indexOf(simState[cfg.limitKey]);
                    if (idx > 0) {
                        simState[cfg.limitKey] = ROWS_LIMIT_STEPS[idx - 1];
                        simState[cfg.pageKey] = 1;
                        renderPreviewTables();
                    }
                });
            }
            if (pageUp) {
                pageUp.addEventListener('click', function onPageUp() {
                    simState[cfg.pageKey] += 1;
                    renderPreviewTables();
                });
            }
            if (pageDown) {
                pageDown.addEventListener('click', function onPageDown() {
                    simState[cfg.pageKey] = Math.max(1, simState[cfg.pageKey] - 1);
                    renderPreviewTables();
                });
            }
        });

        /* 1:1 Qt QSplitter vertical drag resizer (mirrors MainWindow._tables_splitter) */
        var splitterHandle = document.getElementById('ss-splitter-handle');
        var workspaceEl = document.querySelector('.ss-workspace');
        var connectedSecEl = document.getElementById('ss-connected-section');
        var disconnectedSecEl = document.getElementById('ss-disconnected-section');
        if (splitterHandle && workspaceEl && connectedSecEl) {
            var dragState = null;

            function updateSplitterFromDelta(deltaY) {
                var bounds = getSplitterBounds(workspaceEl, connectedSecEl, disconnectedSecEl, splitterHandle);
                var nextH = Math.max(bounds.minH, Math.min(bounds.maxH, dragState.startHeight + deltaY));
                simState.splitterRatio = nextH / bounds.avail;
                applySplitterLayout();
            }

            window.addEventListener('resize', updatePreviewStageLayout);
            window.addEventListener('orientationchange', updatePreviewStageLayout);

            splitterHandle.addEventListener('pointerdown', function onSplitterDown(ev) {
                if (ev.button !== 0 || simState.merged || !simState.connectedExpanded || !simState.disconnectedExpanded) {
                    return;
                }
                ev.preventDefault();
                dragState = {
                    pointerId: ev.pointerId,
                    startX: ev.clientX,
                    startY: ev.clientY,
                    startHeight: connectedSecEl.offsetHeight,
                };
                splitterHandle.classList.add('is-dragging');
                document.body.classList.add('ss-is-resizing-splitter');
                if (splitterHandle.setPointerCapture) {
                    try {
                        splitterHandle.setPointerCapture(ev.pointerId);
                    } catch (_err) {
                        /* Ignore capture errors on synthetic events. */
                    }
                }
            });

            window.addEventListener('pointermove', function onSplitterMove(ev) {
                if (!dragState || ev.pointerId !== dragState.pointerId) {
                    return;
                }
                var rawDelta = previewStageState.rotated
                    ? -(ev.clientX - dragState.startX)
                    : (ev.clientY - dragState.startY);
                var scale = previewStageState.scale || 1;
                updateSplitterFromDelta(rawDelta / scale);
            });

            function finishSplitterDrag(ev) {
                if (!dragState || (ev && ev.pointerId !== dragState.pointerId)) {
                    return;
                }
                if (splitterHandle.releasePointerCapture && ev) {
                    try {
                        splitterHandle.releasePointerCapture(ev.pointerId);
                    } catch (_err) {
                        /* Ignore release errors. */
                    }
                }
                dragState = null;
                splitterHandle.classList.remove('is-dragging');
                document.body.classList.remove('ss-is-resizing-splitter');
            }

            window.addEventListener('pointerup', finishSplitterDrag);
            window.addEventListener('pointercancel', finishSplitterDrag);
            splitterHandle.addEventListener('dblclick', function onSplitterReset() {
                simState.splitterRatio = DEFAULT_SPLITTER_RATIO;
                applySplitterLayout();
            });
            splitterHandle.addEventListener('keydown', function onSplitterKey(ev) {
                if (ev.key !== 'ArrowUp' && ev.key !== 'ArrowDown') {
                    return;
                }
                if (simState.merged || !simState.connectedExpanded || !simState.disconnectedExpanded) {
                    return;
                }
                ev.preventDefault();
                var step = ev.key === 'ArrowUp' ? -24 : 24;
                dragState = {
                    pointerId: -1,
                    startX: 0,
                    startY: 0,
                    startHeight: connectedSecEl.offsetHeight,
                };
                updateSplitterFromDelta(step);
                dragState = null;
            });
        }

        /* 1:1 Minimize & Expand buttons (mirrors MainWindow._update_splitter_visibility) */
        var connCollapse = document.getElementById('ss-connected-collapse');
        var discCollapse = document.getElementById('ss-disconnected-collapse');
        var connExpand = document.getElementById('ss-connected-expand');
        var discExpand = document.getElementById('ss-disconnected-expand');

        if (connCollapse) {
            connCollapse.addEventListener('click', function onMinimizeConnected() {
                simState.connectedExpanded = false;
                renderPreviewTables();
            });
        }
        if (discCollapse) {
            discCollapse.addEventListener('click', function onMinimizeDisconnected() {
                simState.disconnectedExpanded = false;
                renderPreviewTables();
            });
        }
        if (connExpand) {
            connExpand.addEventListener('click', function onExpandConnected() {
                simState.connectedExpanded = true;
                renderPreviewTables();
            });
        }
        if (discExpand) {
            discExpand.addEventListener('click', function onExpandDisconnected() {
                simState.disconnectedExpanded = true;
                renderPreviewTables();
            });
        }

        /* 1:1 Column header sorting (mirrors SessionTableView._on_section_clicked & table_model.py) */
        function toggleColumnSort(tableKey, col) {
            var sortState = tableKey === 'disconnected' ? simState.disconnectedSort : simState.connectedSort;
            if (sortState.col === col) {
                sortState.dir = sortState.dir === 'desc' ? 'asc' : 'desc';
            } else {
                sortState.col = col;
                sortState.dir = 'desc';
            }
            if (tableKey === 'disconnected') {
                simState.disconnectedPage = 1;
            } else {
                simState.connectedPage = 1;
            }
            renderPreviewTables();
        }

        document.querySelectorAll('th[data-sort-table]').forEach(function wireSortHeader(th) {
            var tableKey = th.getAttribute('data-sort-table');
            var col = th.getAttribute('data-sort-col');
            if (!tableKey || !col) {
                return;
            }
            th.addEventListener('click', function onSortClick() {
                toggleColumnSort(tableKey, col);
            });
            th.addEventListener('keydown', function onSortKeydown(ev) {
                if (ev.key === 'Enter' || ev.key === ' ') {
                    ev.preventDefault();
                    toggleColumnSort(tableKey, col);
                }
            });
        });

        syncColumnHeaderTooltips();

        /* 1:1 Qt QMenuBar dropdowns (click to open, hover to switch while open) */
        function hasOpenAppMenu() {
            var popups = document.querySelectorAll('.ss-menu-popup');
            for (var i = 0; i < popups.length; i += 1) {
                if (!popups[i].hidden) {
                    return true;
                }
            }
            return false;
        }

        document.querySelectorAll('.ss-menu-trigger').forEach(function wireMenu(trigger) {
            trigger.addEventListener('click', function onMenuClick(ev) {
                ev.stopPropagation();
                hideRichTooltip();
                closeLangDropdown();
                closeThemeDropdown();
                closeMobileNavDrawer();
                closeContextMenu();
                closeSearchColumnPopup();
                var key = trigger.getAttribute('data-menu');
                var popup = document.querySelector('[data-menu-popup="' + key + '"]');
                if (!popup) {
                    return;
                }
                var willOpen = popup.hidden;
                closeAllAppMenus();
                popup.hidden = !willOpen;
                trigger.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
            });
            trigger.addEventListener('mouseenter', function onMenuHover() {
                if (!hasOpenAppMenu()) {
                    return;
                }
                var key = trigger.getAttribute('data-menu');
                var popup = document.querySelector('[data-menu-popup="' + key + '"]');
                if (!popup || !popup.hidden) {
                    return;
                }
                closeAllAppMenus();
                popup.hidden = false;
                trigger.setAttribute('aria-expanded', 'true');
            });
        });

        document.querySelectorAll('[data-menu-action]').forEach(function wireMenuAction(item) {
            item.addEventListener('click', function onAction() {
                var action = item.getAttribute('data-menu-action');
                closeAllAppMenus();
                if (action === 'app-feature') {
                    var appKey = item.getAttribute('data-feature-app') || '';
                    showDemoFeatureToast(tApp(appKey));
                }
            });
        });

        /* Responsive Mobile Desktop Stage controls (100% Pan / Fit View / Fullscreen Landscape) */
        document.querySelectorAll('[data-stage-mode]').forEach(function wireStageMode(btn) {
            btn.addEventListener('click', function onStageMode() {
                var nextMode = btn.getAttribute('data-stage-mode') === 'fit' ? 'fit' : 'pan';
                if (previewStageState.fullscreen) {
                    previewStageState.fullscreenMode = nextMode;
                } else {
                    previewStageState.inlineMode = nextMode;
                }
                updatePreviewStageLayout();
            });
        });

        var stageFsBtn = document.getElementById('ss-stage-fs-btn');
        if (stageFsBtn) {
            stageFsBtn.addEventListener('click', openPreviewFullscreen);
        }
        var stageExitBtn = document.getElementById('ss-stage-exit-btn');
        if (stageExitBtn) {
            stageExitBtn.addEventListener('click', closePreviewFullscreen);
        }
        var stageRotateBtn = document.getElementById('ss-stage-rotate-btn');
        if (stageRotateBtn) {
            stageRotateBtn.addEventListener('click', function onToggleRotate() {
                hideRichTooltip();
                closeContextMenu();
                previewStageState.rotateInFullscreen = !previewStageState.rotateInFullscreen;
                updatePreviewStageLayout();
            });
        }
        var stageShellEl = document.getElementById('ss-stage-shell');
        if (stageShellEl) {
            stageShellEl.addEventListener('click', function onStageToastAction(ev) {
                if (!previewStageState.fullscreen) {
                    return;
                }
                var actionBtn = ev.target && ev.target.closest ? ev.target.closest('.toast-action-btn') : null;
                if (actionBtn) {
                    closePreviewFullscreen();
                }
            }, true);
        }

        var heroPreviewCta = document.getElementById('hero-preview-cta');
        var liveWindow = document.getElementById('ss-live-window');
        var spotlightTimer = null;

        function jumpToInteractiveDemo(ev) {
            var targetSection = document.getElementById('preview');
            if (targetSection) {
                if (ev) {
                    ev.preventDefault();
                }
                targetSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
            if (!liveWindow) {
                return;
            }
            liveWindow.classList.remove('is-spotlight');
            void liveWindow.offsetWidth;
            liveWindow.classList.add('is-spotlight');
            if (spotlightTimer) {
                window.clearTimeout(spotlightTimer);
            }
            spotlightTimer = window.setTimeout(function clearSpotlight() {
                liveWindow.classList.remove('is-spotlight');
                spotlightTimer = null;
            }, 1200);
        }

        if (heroPreviewCta && liveWindow) {
            heroPreviewCta.addEventListener('click', jumpToInteractiveDemo);
        }

        /* Hero Screenshot Full-Size Lightbox */
        var heroLightbox = document.getElementById('hero-lightbox');
        var heroZoomBtn = document.getElementById('hero-showcase-zoom-btn');
        var heroLbBackdrop = document.getElementById('hero-lightbox-backdrop');
        var heroLbClose = document.getElementById('hero-lightbox-close');
        var heroLbDemo = document.getElementById('hero-lightbox-demo');
        var heroLbDownload = document.getElementById('hero-lightbox-download');

        function openHeroLightbox() {
            if (!heroLightbox) {
                return;
            }
            heroLightbox.hidden = false;
            document.body.style.overflow = 'hidden';
            if (heroLbClose) {
                heroLbClose.focus();
            }
        }

        function closeHeroLightbox() {
            if (!heroLightbox || heroLightbox.hidden) {
                return;
            }
            heroLightbox.hidden = true;
            if (!previewStageState.fullscreen) {
                document.body.style.overflow = '';
            }
            if (heroZoomBtn) {
                heroZoomBtn.focus();
            }
        }

        if (heroZoomBtn) {
            heroZoomBtn.addEventListener('click', openHeroLightbox);
        }
        if (heroLbBackdrop) {
            heroLbBackdrop.addEventListener('click', closeHeroLightbox);
        }
        if (heroLbClose) {
            heroLbClose.addEventListener('click', closeHeroLightbox);
        }
        if (heroLbDemo) {
            heroLbDemo.addEventListener('click', function onLbDemoClick(ev) {
                closeHeroLightbox();
                jumpToInteractiveDemo(ev);
            });
        }
        if (heroLbDownload) {
            heroLbDownload.addEventListener('click', function onLbDownloadClick() {
                closeHeroLightbox();
            });
        }
        document.addEventListener('keydown', function onHeroLbEscape(ev) {
            if (ev.key === 'Escape') {
                closeHeroLightbox();
            }
        });

        /* Touch long-press context menu for mobile browsers (iOS Safari does not fire contextmenu on long-press) */
        [
            { id: 'ss-connected-tbody', tableKind: 'connected' },
            { id: 'ss-disconnected-tbody', tableKind: 'disconnected' },
        ].forEach(function wireTouchLongPress(cfg) {
            var tbody = document.getElementById(cfg.id);
            if (!tbody) {
                return;
            }
            tbody.addEventListener('pointerdown', function onRowPointerDown(ev) {
                if (ev.pointerType !== 'touch' && ev.pointerType !== 'pen') {
                    return;
                }
                if (ev.isPrimary === false) {
                    clearTouchLongPressTimer();
                    return;
                }
                var tr = ev.target && ev.target.closest ? ev.target.closest('tr[data-player-id]') : null;
                if (!tr) {
                    return;
                }
                var playerId = tr.getAttribute('data-player-id');
                var cell = ev.target && ev.target.closest ? ev.target.closest('td') : null;
                var cellText = cell ? cell.textContent : '';

                clearTouchLongPressTimer();
                touchLongPressState.pointerId = ev.pointerId;
                touchLongPressState.startX = ev.clientX;
                touchLongPressState.startY = ev.clientY;
                touchLongPressState.triggered = false;

                touchLongPressState.timer = window.setTimeout(function fireLongPress() {
                    touchLongPressState.timer = null;
                    var found = findPlayerForRow(playerId, cfg.tableKind);
                    if (!found) {
                        return;
                    }
                    touchLongPressState.triggered = true;
                    touchLongPressState.suppressClickUntil = Date.now() + 700;
                    touchLongPressState.suppressContextMenuUntil = Date.now() + 700;
                    openRowContextMenu(
                        touchLongPressState.startX,
                        touchLongPressState.startY,
                        found.player,
                        found.isDisconnected,
                        cellText || found.player.ip,
                    );
                }, LONG_PRESS_DELAY_MS);
            });
        });

        window.addEventListener('pointerdown', function onAnyPointerDown() {
            if (!touchLongPressState.triggered) {
                touchLongPressState.suppressClickUntil = 0;
            }
        }, true);

        window.addEventListener('pointermove', function onLongPressMove(ev) {
            if (touchLongPressState.timer === null || ev.pointerId !== touchLongPressState.pointerId) {
                return;
            }
            var dx = ev.clientX - touchLongPressState.startX;
            var dy = ev.clientY - touchLongPressState.startY;
            if ((dx * dx) + (dy * dy) > LONG_PRESS_MOVE_TOLERANCE_PX * LONG_PRESS_MOVE_TOLERANCE_PX) {
                clearTouchLongPressTimer();
            }
        }, { passive: true });

        function onLongPressPointerEnd(ev) {
            if (touchLongPressState.pointerId !== null && ev.pointerId !== touchLongPressState.pointerId) {
                return;
            }
            clearTouchLongPressTimer();
            if (touchLongPressState.triggered) {
                touchLongPressState.triggered = false;
                touchLongPressState.suppressClickUntil = Date.now() + 450;
            }
        }

        window.addEventListener('pointerup', onLongPressPointerEnd, true);
        window.addEventListener('pointercancel', onLongPressPointerEnd, true);

        window.addEventListener('touchstart', function onMultiTouchStart(ev) {
            if (ev.touches && ev.touches.length > 1) {
                clearTouchLongPressTimer();
            }
        }, { passive: true });

        window.addEventListener('touchend', function onLongPressTouchEnd(ev) {
            if (touchLongPressState.triggered) {
                ev.preventDefault();
                touchLongPressState.triggered = false;
                touchLongPressState.suppressClickUntil = Date.now() + 450;
            }
        }, { passive: false, capture: true });

        document.addEventListener('click', function onSuppressLongPressClick(ev) {
            if (Date.now() < touchLongPressState.suppressClickUntil) {
                touchLongPressState.suppressClickUntil = 0;
                ev.preventDefault();
                ev.stopPropagation();
            }
        }, true);

        loadPreset('gta5');
        updateMetricsDisplay();
        updatePreviewStageLayout();
        if (typeof window.requestAnimationFrame === 'function') {
            window.requestAnimationFrame(updatePreviewStageLayout);
        }
        window.setInterval(tickSimulation, 1000);
    }


    Core.onOutsideDismiss(function onPreviewOutsideDismiss(ev) {
        var menubar = document.getElementById('ss-menubar');
        if (menubar && document.querySelector('.ss-menu-popup:not([hidden])') && !Core.isEventInside(ev, menubar)) {
            closeAllAppMenus();
        }
        var ctxMenu = document.getElementById('ss-context-menu');
        if (ctxMenu && !ctxMenu.hidden && !Core.isEventInside(ev, ctxMenu)) {
            closeContextMenu();
        }
        var searchComboWrap = document.getElementById('ss-search-column-wrap');
        var searchComboPopup = document.getElementById('ss-search-column-popup');
        if (searchComboPopup && !searchComboPopup.hidden && !Core.isEventInside(ev, searchComboWrap)) {
            closeSearchColumnPopup();
        }
    });

    document.addEventListener('keydown', function onPreviewKeyDown(ev) {
        if (ev.key === 'Escape') {
            closePreviewFullscreen();
            closeAllAppMenus();
            closeContextMenu();
            closeSearchColumnPopup();
        }
    });

    window.addEventListener('scroll', function onPreviewScroll() {
        clearTouchLongPressTimer();
        closeContextMenu();
    }, true);
    window.addEventListener('resize', function onPreviewResize() {
        clearTouchLongPressTimer();
        closeContextMenu();
    });

    Core.onClosePopups(function closePreviewPopups() {
        closeAllAppMenus();
        closeContextMenu();
        closeSearchColumnPopup();
    });

    Core.onThemeChange(refreshRateCellColors);

    Core.onLanguageChange(function handlePreviewLanguageChange() {
        hideRichTooltip();
        renderAppSubtitle();
        var searchInput = document.getElementById('ss-search-input');
        if (searchInput) {
            searchInput.placeholder = tApp(simState.merged ? 'Search players...' : 'Search connected + disconnected players...');
        }
        closeContextMenu();
        closeSearchColumnPopup();
        syncSearchColumnUi();
        syncPresetMenusAndStatus();
        syncColumnHeaderTooltips();
        renderPreviewTables();
        updateMetricsDisplay();
        updatePreviewStageLayout();
    });

    initPreviewInteractions();
}());
