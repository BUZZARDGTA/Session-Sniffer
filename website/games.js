/* ==========================================================================
   Session Sniffer Supported Games & Software Explorer (index.html)
   - Dual-row online game jackets marquee, Wiki table & cover gallery
   - Search, P2P architecture & platform filtering, sorting & detail modal
   ========================================================================== */

(function initSessionSnifferGames() {
    'use strict';

    var Core = window.SSCore;
    if (!Core || !document.getElementById('games-explorer')) {
        return;
    }

    var tSite = Core.tSite;
    var tApp = Core.tApp;
    var createIconSvg = Core.createIconSvg;
    var setRichTooltip = Core.setRichTooltip;
    var hideRichTooltip = Core.hideRichTooltip;

    /* ----------------------------------------------------------------------
       5B. Supported Games & Software Showcase (Online Jackets + Wiki Table)
       ---------------------------------------------------------------------- */

    var STEAM_CDN = 'https://shared.fastly.steamstatic.com/store_item_assets/steam/apps/';
    var IGDB_CDN = 'https://images.igdb.com/igdb/image/upload/t_cover_big_2x/';

    var SUPPORTED_CATALOG = [
        /* ---- 56 Officially Tested Video Games (from GitHub Wiki) ---- */
        {
            id: 'borderlands-2',
            category: 'game',
            name: 'Borderlands 2',
            platforms: ['PC'],
            p2p: 'host',
            resolver: 'no',
            noteKey: 'games.note_host_only',
            cover: STEAM_CDN + '49520/library_600x900.jpg',
        },
        {
            id: 'borderlands-3',
            category: 'game',
            name: 'Borderlands 3',
            platforms: ['PC'],
            p2p: 'host',
            resolver: 'no',
            noteKey: 'games.note_host_only',
            cover: STEAM_CDN + '397540/library_600x900.jpg',
        },
        {
            id: 'borderlands-4',
            category: 'game',
            name: 'Borderlands 4',
            platforms: ['PC'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '1285190/e68c1eeacfc21e61e5a03ae81a20694856665af4/library_600x900.jpg',
            showcaseRank: 11,
        },
        {
            id: 'borderlands-tps',
            category: 'game',
            name: 'Borderlands: The Pre-Sequel',
            platforms: ['PC'],
            p2p: 'host',
            resolver: 'no',
            noteKey: 'games.note_host_only',
            cover: STEAM_CDN + '261640/library_600x900.jpg',
        },
        {
            id: 'cod-aw',
            category: 'game',
            name: 'Call of Duty®: Advanced Warfare',
            platforms: ['PC', 'PS3'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '209650/library_600x900.jpg',
        },
        {
            id: 'cod-bo',
            category: 'game',
            name: 'Call of Duty®: Black Ops',
            platforms: ['PC', 'PS3'],
            p2p: 'partial',
            resolver: 'no',
            noteKey: 'games.note_cod_bo',
            cover: STEAM_CDN + '42700/library_600x900.jpg',
            showcaseRank: 18,
        },
        {
            id: 'cod-bocw',
            category: 'game',
            name: 'Call of Duty®: Black Ops Cold War',
            platforms: ['PC'],
            p2p: 'partial',
            resolver: 'no',
            noteKey: 'games.note_cod_bocw',
            cover: STEAM_CDN + '1985810/library_600x900.jpg',
            showcaseRank: 17,
        },
        {
            id: 'cod-bo2',
            category: 'game',
            name: 'Call of Duty®: Black Ops II',
            platforms: ['PC', 'PS3'],
            p2p: 'partial',
            resolver: 'no',
            noteKey: 'games.note_cod_bo2',
            cover: STEAM_CDN + '202970/library_600x900.jpg',
            showcaseRank: 6,
        },
        {
            id: 'cod-bo3',
            category: 'game',
            name: 'Call of Duty®: Black Ops III',
            platforms: ['PC', 'PS5', 'PS3'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '311210/library_600x900.jpg',
            showcaseRank: 5,
        },
        {
            id: 'cod-ghosts',
            category: 'game',
            name: 'Call of Duty®: Ghosts',
            platforms: ['PC', 'PS3'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '209160/library_600x900.jpg',
        },
        {
            id: 'cod-iw',
            category: 'game',
            name: 'Call of Duty®: Infinite Warfare',
            platforms: ['PC'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '292730/library_600x900.jpg',
        },
        {
            id: 'cod-mw2-2009',
            category: 'game',
            name: 'Call of Duty®: Modern Warfare® 2 (2009)',
            platforms: ['PC', 'PS3'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '10180/library_600x900.jpg',
            showcaseRank: 7,
        },
        {
            id: 'cod-mw3-2011',
            category: 'game',
            name: 'Call of Duty®: Modern Warfare® 3 (2011)',
            platforms: ['PC', 'PS3'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '115300/library_600x900.jpg',
        },
        {
            id: 'cod-vanguard',
            category: 'game',
            name: 'Call of Duty®: Vanguard',
            platforms: ['PC'],
            p2p: 'partial',
            resolver: 'no',
            noteKey: 'games.note_cod_vanguard',
            cover: STEAM_CDN + '1985820/library_600x900.jpg',
        },
        {
            id: 'cod-wwii',
            category: 'game',
            name: 'Call of Duty®: WWII',
            platforms: ['PC'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '476600/library_600x900.jpg',
        },
        {
            id: 'deep-rock-galactic',
            category: 'game',
            name: 'Deep Rock Galactic',
            platforms: ['PC'],
            p2p: 'host',
            resolver: 'no',
            noteKey: 'games.note_drg',
            cover: STEAM_CDN + '548430/library_600x900.jpg',
            showcaseRank: 12,
        },
        {
            id: 'destiny',
            category: 'game',
            name: 'Destiny',
            platforms: ['PS3'],
            p2p: 'verified',
            resolver: 'no',
            cover: IGDB_CDN + 'co1rco.jpg',
            showcaseRank: 23,
        },
        {
            id: 'dragon-ball-fighterz',
            category: 'game',
            name: 'DRAGON BALL FighterZ',
            platforms: ['PC'],
            p2p: 'full',
            resolver: 'no',
            noteKey: 'games.note_fully_p2p',
            cover: STEAM_CDN + '678950/library_600x900.jpg',
            showcaseRank: 19,
        },
        {
            id: 'dying-light',
            category: 'game',
            name: 'Dying Light',
            platforms: ['PC'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '239140/b962a5213054357b157b0fe45bf9db41b5739886/library_600x900.jpg',
        },
        {
            id: 'dying-light-2',
            category: 'game',
            name: 'Dying Light 2',
            platforms: ['PC'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '534380/5b75126ece6e937bda12bf5f802647c30d7a2801/library_600x900.jpg',
            showcaseRank: 13,
        },
        {
            id: 'elden-ring',
            category: 'game',
            name: 'ELDEN RING',
            platforms: ['PS4'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '1245620/library_600x900.jpg',
            showcaseRank: 3,
        },
        {
            id: 'elden-ring-nightreign',
            category: 'game',
            name: 'ELDEN RING NIGHTREIGN',
            platforms: ['PC', 'PS4'],
            p2p: 'full',
            resolver: 'no',
            noteKey: 'games.note_nightreign',
            cover: STEAM_CDN + '2622380/d1ee7bc631966b1a99e232a9f84af736bb298395/library_600x900.jpg',
            showcaseRank: 4,
        },
        {
            id: 'generation-zero',
            category: 'game',
            name: 'Generation Zero®',
            platforms: ['PC'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '704270/library_600x900.jpg',
        },
        {
            id: 'green-hell',
            category: 'game',
            name: 'Green Hell',
            platforms: ['PC'],
            p2p: 'full',
            resolver: 'no',
            noteKey: 'games.note_fully_p2p',
            cover: STEAM_CDN + '815370/library_600x900.jpg',
        },
        {
            id: 'gta-iv',
            category: 'game',
            name: 'Grand Theft Auto IV',
            platforms: ['PS3'],
            p2p: 'verified',
            resolver: 'ps3',
            cover: STEAM_CDN + '12210/library_600x900.jpg',
            showcaseRank: 24,
        },
        {
            id: 'gta-online',
            category: 'game',
            name: 'Grand Theft Auto Online',
            platforms: ['PC', 'Xbox Series X|S', 'Xbox One', 'PS5', 'PS4'],
            p2p: 'verified',
            resolver: 'plugins',
            toolkit: 'GTA V',
            noteKey: 'games.note_gtao',
            cover: IGDB_CDN + 'co4rq1.jpg',
            showcaseRank: 1,
        },
        {
            id: 'minecraft-bedrock',
            category: 'game',
            name: 'Minecraft: Bedrock Edition',
            platforms: ['PC', 'PS4'],
            p2p: 'partial',
            resolver: 'no',
            noteKey: 'games.note_mc_bedrock',
            cover: IGDB_CDN + 'co8fu7.jpg',
            showcaseRank: 8,
        },
        {
            id: 'minecraft-ps3',
            category: 'game',
            name: 'Minecraft: PlayStation®3 Edition',
            platforms: ['PS3'],
            p2p: 'full',
            resolver: 'ps3',
            noteKey: 'games.note_fully_p2p',
            cover: IGDB_CDN + 'co8mll.jpg',
            showcaseRank: 25,
        },
        {
            id: 'monopoly-madness',
            category: 'game',
            name: 'Monopoly Madness',
            platforms: ['PC'],
            p2p: 'host',
            resolver: 'no',
            noteKey: 'games.note_monopoly_madness',
            cover: STEAM_CDN + '2383760/library_600x900.jpg',
        },
        {
            id: 'monster-hunter-world',
            category: 'game',
            name: 'Monster Hunter: World',
            platforms: ['PC'],
            p2p: 'full',
            resolver: 'no',
            noteKey: 'games.note_fully_p2p',
            cover: STEAM_CDN + '582010/library_600x900.jpg',
            showcaseRank: 9,
        },
        {
            id: 'mortal-kombat-11',
            category: 'game',
            name: 'Mortal Kombat 11',
            platforms: ['PC', 'PS4'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '976310/library_600x900.jpg',
            showcaseRank: 16,
        },
        {
            id: 'mortal-kombat-x',
            category: 'game',
            name: 'Mortal Kombat X',
            platforms: ['PC', 'PS4'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '307780/library_600x900.jpg',
        },
        {
            id: 'naruto-storm-4',
            category: 'game',
            name: 'NARUTO SHIPPUDEN: Ultimate Ninja STORM 4',
            platforms: ['PS4'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '349040/library_600x900.jpg',
        },
        {
            id: 'naruto-storm-revolution',
            category: 'game',
            name: 'NARUTO SHIPPUDEN: Ultimate Ninja STORM Revolution',
            platforms: ['PC'],
            p2p: 'full',
            resolver: 'no',
            noteKey: 'games.note_fully_p2p',
            cover: IGDB_CDN + 'co1u96.jpg',
        },
        {
            id: 'nfs-most-wanted',
            category: 'game',
            name: 'Need for Speed™ Most Wanted',
            platforms: ['PC'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '1262560/library_600x900.jpg',
        },
        {
            id: 'new-monopoly',
            category: 'game',
            name: 'NEW MONOPOLY®',
            platforms: ['PC'],
            p2p: 'host',
            resolver: 'no',
            noteKey: 'games.note_host_only',
            cover: STEAM_CDN + '2929170/5eec9eb927fa77fa9585e9d1951764c923bc9e77/library_capsule.jpg',
        },
        {
            id: 'payday-2',
            category: 'game',
            name: 'Payday 2',
            platforms: ['PC', 'PS3'],
            p2p: 'full',
            resolver: 'ps3',
            noteKey: 'games.note_payday2',
            cover: STEAM_CDN + '218620/e7aba53917eb9c188f83f1df103bc96f657a4b53/library_capsule.jpg',
            showcaseRank: 20,
        },
        {
            id: 'playstation-party-chat',
            category: 'game',
            name: 'PlayStation Party Chat',
            platforms: ['PS5', 'PS4'],
            p2p: 'partial',
            resolver: 'no',
            noteKey: 'games.note_ps_party',
            brandA: '#0070d1',
            brandB: '#002c77',
            logo: 'https://cdn.simpleicons.org/playstation/ffffff',
            shortLabel: 'PARTY CHAT',
        },
        {
            id: 'ready-or-not',
            category: 'game',
            name: 'Ready or Not',
            platforms: ['PC'],
            p2p: 'host',
            resolver: 'no',
            noteKey: 'games.note_host_only',
            cover: STEAM_CDN + '1144200/1ebfc7f05967d7dd39a7659b31b04a6b40a77663/library_capsule.jpg',
            showcaseRank: 10,
        },
        {
            id: 'red-dead-online',
            category: 'game',
            name: 'Red Dead Online',
            platforms: ['PC', 'Xbox Series X|S', 'Xbox One', 'PS5', 'PS4'],
            p2p: 'verified',
            resolver: 'no',
            toolkit: 'RDR2',
            cover: STEAM_CDN + '1404210/library_600x900.jpg',
            showcaseRank: 2,
        },
        {
            id: 'red-dead-redemption',
            category: 'game',
            name: 'Red Dead Redemption',
            platforms: ['PS3'],
            p2p: 'verified',
            resolver: 'ps3',
            cover: STEAM_CDN + '2668510/f5cf694ddab93ed2462a9e2f5e01064e121c5663/library_600x900.jpg',
            showcaseRank: 26,
        },
        {
            id: 'risk-of-rain-2',
            category: 'game',
            name: 'Risk of Rain 2',
            platforms: ['PC'],
            p2p: 'host',
            resolver: 'no',
            noteKey: 'games.note_host_only',
            cover: STEAM_CDN + '632360/library_600x900.jpg',
            showcaseRank: 15,
        },
        {
            id: 'skate-3',
            category: 'game',
            name: 'Skate 3',
            platforms: ['PS3'],
            p2p: 'verified',
            resolver: 'no',
            cover: IGDB_CDN + 'co1o4l.jpg',
            showcaseRank: 22,
        },
        {
            id: 'sniper-elite-3',
            category: 'game',
            name: 'Sniper Elite 3',
            platforms: ['PS3'],
            p2p: 'host',
            resolver: 'ps3',
            noteKey: 'games.note_sniper_elite3',
            cover: STEAM_CDN + '238090/library_600x900.jpg',
        },
        {
            id: 'sons-of-the-forest',
            category: 'game',
            name: 'Sons Of The Forest',
            platforms: ['PC'],
            p2p: 'host',
            resolver: 'no',
            noteKey: 'games.note_host_only',
            cover: STEAM_CDN + '1326470/library_600x900.jpg',
            showcaseRank: 14,
        },
        {
            id: 'sf-30th',
            category: 'game',
            name: 'Street Fighter 30th Anniversary Collection',
            platforms: ['PC'],
            p2p: 'full',
            resolver: 'no',
            noteKey: 'games.note_fully_p2p',
            cover: STEAM_CDN + '586200/library_600x900.jpg',
        },
        {
            id: 'tekken-7',
            category: 'game',
            name: 'TEKKEN 7',
            platforms: ['PC'],
            p2p: 'full',
            resolver: 'no',
            noteKey: 'games.note_fully_p2p',
            cover: STEAM_CDN + '389730/library_600x900.jpg',
            showcaseRank: 21,
        },
        {
            id: 'the-division-2',
            category: 'game',
            name: 'The Division 2',
            platforms: ['PC'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '2221490/8517c0415397d69e5c0e818eb1f2eb0ae83806b2/library_600x900.jpg',
            showcaseRank: 27,
        },
        {
            id: 'thehunter-cotw',
            category: 'game',
            name: 'theHunter Call of the Wild™',
            platforms: ['PC'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '518790/library_600x900.jpg',
        },
        {
            id: 'thehunter-classic',
            category: 'game',
            name: 'theHunter Classic',
            platforms: ['PC'],
            p2p: 'host',
            resolver: 'no',
            noteKey: 'games.note_host_only',
            cover: STEAM_CDN + '253710/library_600x900.jpg',
        },
        {
            id: 'ghost-recon-breakpoint',
            category: 'game',
            name: "Tom Clancy's Ghost Recon® Breakpoint",
            platforms: ['PC'],
            p2p: 'partial',
            resolver: 'no',
            noteKey: 'games.note_gr_breakpoint',
            cover: STEAM_CDN + '2231380/library_600x900.jpg',
        },
        {
            id: 'ghost-recon-wildlands',
            category: 'game',
            name: "Tom Clancy's Ghost Recon® Wildlands",
            platforms: ['PC'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '460930/library_600x900.jpg',
        },
        {
            id: 'ultra-sf-iv',
            category: 'game',
            name: 'Ultra Street Fighter IV',
            platforms: ['PC'],
            p2p: 'full',
            resolver: 'no',
            noteKey: 'games.note_fully_p2p',
            cover: STEAM_CDN + '45760/library_600x900.jpg',
        },
        {
            id: 'uno',
            category: 'game',
            name: 'UNO',
            platforms: ['PC'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '470220/8315ac8b7e91e0501b473cff7cf88b1b67906489/library_capsule.jpg',
        },
        {
            id: 'warframe',
            category: 'game',
            name: 'Warframe',
            platforms: ['PC'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '230410/0572533cfd26a64e831f83ef3f940e1b8012b1e8/library_capsule.jpg',
            showcaseRank: 28,
        },
        {
            id: 'watch-dogs-2',
            category: 'game',
            name: 'Watch Dogs® 2',
            platforms: ['PC'],
            p2p: 'verified',
            resolver: 'no',
            cover: STEAM_CDN + '447040/library_600x900.jpg',
        },

        /* ---- 12 Officially Tested Softwares (from GitHub Wiki) ---- */
        {
            id: 'sw-torrents',
            category: 'software',
            name: 'Any torrenting softwares',
            nameKey: 'games.sw_torrents',
            platforms: ['Any'],
            p2p: 'verified',
            resolver: 'no',
            brandA: '#7c3aed',
            brandB: '#2e1065',
            logo: 'https://cdn.simpleicons.org/bittorrent/ffffff',
            shortLabel: 'P2P TORRENT',
        },
        {
            id: 'sw-anydesk',
            category: 'software',
            name: 'AnyDesk',
            platforms: ['PC'],
            p2p: 'verified',
            resolver: 'no',
            brandA: '#ef443b',
            brandB: '#7f1d1d',
            logo: 'https://cdn.simpleicons.org/anydesk/ffffff',
            shortLabel: 'AnyDesk',
        },
        {
            id: 'sw-azar',
            category: 'software',
            name: 'Azar',
            platforms: ['Android', 'iOS'],
            p2p: 'verified',
            resolver: 'no',
            brandA: '#00d98b',
            brandB: '#065f46',
            logo: 'https://is1-ssl.mzstatic.com/image/thumb/Purple221/v4/bd/cf/ec/bdcfec1e-fb0b-da9d-cfdb-faf83f6edb74/AppIcon-0-0-1x_U007epad-0-1-0-85-220.png/512x512bb.jpg',
            logoFullbleed: true,
            shortLabel: 'Azar',
        },
        {
            id: 'sw-chatspin',
            category: 'software',
            name: 'Chatspin',
            platforms: ['Android', 'iOS'],
            p2p: 'verified',
            resolver: 'no',
            brandA: '#f59e0b',
            brandB: '#92400e',
            logo: 'https://chatspin.com/apple-touch-icon.png',
            logoFullbleed: true,
            shortLabel: 'Chatspin',
        },
        {
            id: 'sw-instagram',
            category: 'software',
            name: 'Instagram',
            platforms: ['Android', 'iOS'],
            p2p: 'partial',
            resolver: 'no',
            noteKey: 'games.note_social_call',
            brandA: '#e1306c',
            brandB: '#5851db',
            logo: 'https://cdn.simpleicons.org/instagram/ffffff',
            shortLabel: 'Instagram',
        },
        {
            id: 'sw-messenger',
            category: 'software',
            name: 'Messenger',
            platforms: ['Android', 'iOS', 'PC (Microsoft Store)'],
            p2p: 'verified',
            resolver: 'no',
            brandA: '#00b2ff',
            brandB: '#6d28d9',
            logo: 'https://cdn.simpleicons.org/messenger/ffffff',
            shortLabel: 'Messenger',
        },
        {
            id: 'sw-ometv',
            category: 'software',
            name: 'OmeTV',
            platforms: ['Android', 'iOS'],
            p2p: 'verified',
            resolver: 'no',
            brandA: '#ea580c',
            brandB: '#166534',
            logo: 'https://ome.tv/apple-touch-icon.png',
            logoFullbleed: true,
            shortLabel: 'OmeTV',
        },
        {
            id: 'sw-parsec',
            category: 'software',
            name: 'Parsec',
            platforms: ['PC'],
            p2p: 'verified',
            resolver: 'no',
            brandA: '#e11d48',
            brandB: '#1d4ed8',
            logo: 'https://www.google.com/s2/favicons?domain=parsec.app&sz=128',
            logoLightBg: true,
            shortLabel: 'Parsec',
        },
        {
            id: 'sw-rustdesk',
            category: 'software',
            name: 'RustDesk',
            platforms: ['PC'],
            p2p: 'verified',
            resolver: 'no',
            brandA: '#2563eb',
            brandB: '#1e1b4b',
            logo: 'https://cdn.simpleicons.org/rustdesk/ffffff',
            shortLabel: 'RustDesk',
        },
        {
            id: 'sw-snapchat',
            category: 'software',
            name: 'Snapchat',
            platforms: ['Android', 'iOS'],
            p2p: 'partial',
            resolver: 'no',
            noteKey: 'games.note_social_call',
            brandA: '#eab308',
            brandB: '#854d0e',
            logo: 'https://cdn.simpleicons.org/snapchat/111111',
            logoLightBg: true,
            shortLabel: 'Snapchat',
        },
        {
            id: 'sw-teamviewer',
            category: 'software',
            name: 'TeamViewer',
            platforms: ['PC'],
            p2p: 'verified',
            resolver: 'no',
            brandA: '#0284c7',
            brandB: '#0c4a6e',
            logo: 'https://cdn.simpleicons.org/teamviewer/ffffff',
            shortLabel: 'TeamViewer',
        },
        {
            id: 'sw-whatsapp',
            category: 'software',
            name: 'WhatsApp',
            platforms: ['PC'],
            p2p: 'partial',
            resolver: 'no',
            noteKey: 'games.note_whatsapp',
            brandA: '#22c55e',
            brandB: '#14532d',
            logo: 'https://cdn.simpleicons.org/whatsapp/ffffff',
            shortLabel: 'WhatsApp',
        },
    ];

    var GAMES_ONLY_LIST = SUPPORTED_CATALOG.filter(function isGameItem(item) {
        return item.category === 'game';
    });
    var SOFTWARE_ONLY_LIST = SUPPORTED_CATALOG.filter(function isSoftwareItem(item) {
        return item.category === 'software';
    });

    var P2P_META = {
        full: {
            labelKey: 'games.p2p_full',
            descKey: 'games.p2p_full_desc',
            icon: 'network',
            order: 0,
        },
        host: {
            labelKey: 'games.p2p_host',
            descKey: 'games.p2p_host_desc',
            icon: 'crown',
            order: 1,
        },
        partial: {
            labelKey: 'games.p2p_partial',
            descKey: 'games.p2p_partial_desc',
            icon: 'radio-tower',
            order: 2,
        },
        verified: {
            labelKey: 'games.p2p_verified',
            descKey: 'games.p2p_verified_desc',
            icon: 'check',
            order: 3,
        },
    };

    var PLATFORM_FILTERS = [
        { key: 'all', labelKey: 'games.filter_platform_all', cats: ['game', 'software', 'all'] },
        { key: 'PC', label: 'PC', cats: ['game', 'software', 'all'] },
        { key: 'PS5', label: 'PS5', cats: ['game', 'all'] },
        { key: 'PS4', label: 'PS4', cats: ['game', 'all'] },
        { key: 'PS3', label: 'PS3', cats: ['game', 'all'] },
        { key: 'Xbox', label: 'Xbox', cats: ['game', 'all'] },
        { key: 'Android', label: 'Android', cats: ['software', 'all'] },
        { key: 'iOS', label: 'iOS', cats: ['software', 'all'] },
    ];

    var INITIAL_COVERS_LIMIT = 18;

    var gamesState = {
        category: 'game',
        view: 'table',
        p2pFilter: 'all',
        platformFilter: 'all',
        searchQuery: '',
        sortField: 'name',
        sortDir: 'asc',
        gridExpanded: false,
        modalOpen: false,
        modalList: [],
        modalIndex: 0,
        lastFocusedBeforeModal: null,
    };

    var marqueeState = {
        shell: null,
        viewport: null,
        rows: [
            { el: null, itemCount: 0, loopWidth: 0, offset: 0, durationSec: 105, dir: 1 },
            { el: null, itemCount: 0, loopWidth: 0, offset: 0, durationSec: 115, dir: -1 },
        ],
        rafId: 0,
        wakeTimerId: 0,
        lastFrameTime: 0,
        autoFactor: 1,
        wheelPending: 0,
        inertiaVel: 0,
        isHovered: false,
        isFocused: false,
        isPointerDown: false,
        isVisible: true,
        reducedMotion: false,
        autoResumeAt: 0,
        pausedUi: false,
        suppressClickUntil: 0,
        drag: {
            active: false,
            pointerId: null,
            pointerType: '',
            startX: 0,
            startY: 0,
            lastX: 0,
            axisLocked: null,
            hasDragged: false,
            captured: false,
            samples: [],
        },
    };

    function getCatalogItemName(item) {
        return item.nameKey ? tSite(item.nameKey) : item.name;
    }

    function getCatalogItemNote(item) {
        return item.noteKey ? tSite(item.noteKey) : '';
    }

    function platformMatchesFilter(platforms, filterKey) {
        if (filterKey === 'all') {
            return true;
        }
        return platforms.some(function checkPlat(p) {
            if (p === 'Any') {
                return true;
            }
            if (filterKey === 'PC') {
                return p === 'PC' || p.indexOf('PC ') === 0;
            }
            if (filterKey === 'Xbox') {
                return p.indexOf('Xbox') !== -1;
            }
            return p === filterKey;
        });
    }

    function getPlatformChipClass(platform) {
        if (platform === 'Any') {
            return 'platform-chip--any';
        }
        if (platform.indexOf('PS') === 0) {
            return 'platform-chip--ps';
        }
        if (platform.indexOf('Xbox') === 0) {
            return 'platform-chip--xbox';
        }
        if (platform === 'Android') {
            return 'platform-chip--android';
        }
        if (platform === 'iOS') {
            return 'platform-chip--ios';
        }
        return 'platform-chip--pc';
    }

    function formatPlatformLabel(platform) {
        return platform === 'Any' ? tSite('games.platform_any') : platform;
    }

    function getPlatformTipInfo(platform) {
        if (platform === 'all') {
            return {
                title: tSite('games.filter_platform_all'),
                body: tSite('games.tip_platforms_col'),
                variant: 'neutral',
            };
        }
        if (platform === 'Any') {
            return {
                title: tSite('games.platform_any'),
                body: tSite('games.tip_plat_any'),
                variant: 'partial',
            };
        }
        if (platform === 'PC' || platform.indexOf('PC ') === 0) {
            return {
                title: platform,
                body: tSite('games.tip_plat_pc'),
                variant: 'neutral',
            };
        }
        if (platform === 'Android' || platform === 'iOS') {
            return {
                title: platform,
                body: tSite('games.tip_plat_mobile'),
                variant: 'full',
            };
        }
        return {
            title: platform,
            body: tSite('games.tip_plat_console'),
            variant: 'partial',
        };
    }


    function buildBrandedPosterArt(item) {
        var wrap = document.createElement('div');
        wrap.className = 'jacket-poster-art';
        var brandA = item.brandA || '#3b82f6';
        var brandB = item.brandB || '#1e293b';
        wrap.style.setProperty('--brand-a', brandA);
        wrap.style.setProperty('--brand-b', brandB);

        var emblem = document.createElement('div');
        emblem.className = 'jacket-poster-emblem'
            + (item.logoFullbleed ? ' jacket-poster-emblem--fullbleed' : '')
            + (item.logoLightBg ? ' jacket-poster-emblem--light-bg' : '');

        if (item.logo) {
            var logoImg = document.createElement('img');
            logoImg.src = item.logo;
            logoImg.alt = getCatalogItemName(item);
            logoImg.loading = 'lazy';
            logoImg.decoding = 'async';
            logoImg.draggable = false;
            logoImg.referrerPolicy = 'no-referrer';
            logoImg.addEventListener('error', function onLogoFallback() {
                emblem.innerHTML = '';
                emblem.appendChild(createIconSvg(item.category === 'software' ? 'monitor-smartphone' : 'gamepad-2', 'icon-sm'));
            });
            emblem.appendChild(logoImg);
        } else {
            emblem.appendChild(createIconSvg(item.category === 'software' ? 'monitor-smartphone' : 'gamepad-2', 'icon-sm'));
        }

        var label = document.createElement('span');
        label.className = 'jacket-poster-label';
        label.textContent = item.shortLabel || getCatalogItemName(item);

        wrap.appendChild(emblem);
        wrap.appendChild(label);
        return wrap;
    }

    function attachCoverArtwork(container, item) {
        if (!item.cover) {
            container.appendChild(buildBrandedPosterArt(item));
            return;
        }
        var img = document.createElement('img');
        img.src = item.cover;
        img.alt = getCatalogItemName(item);
        img.loading = 'lazy';
        img.decoding = 'async';
        img.draggable = false;
        img.referrerPolicy = 'no-referrer';
        img.addEventListener('error', function onCoverErr() {
            if (img.parentNode === container) {
                container.replaceChild(buildBrandedPosterArt(item), img);
            }
        });
        container.appendChild(img);
    }

    function createP2pBadge(p2pKey) {
        var meta = P2P_META[p2pKey] || P2P_META.verified;
        var span = document.createElement('span');
        span.className = 'p2p-badge p2p-badge--' + p2pKey;
        var label = tSite(meta.labelKey);
        setRichTooltip(span, label, tSite(meta.descKey), p2pKey);
        span.appendChild(createIconSvg(meta.icon, 'icon-xs'));
        var txt = document.createElement('span');
        txt.textContent = label;
        span.appendChild(txt);
        return span;
    }

    function createPlatformChips(platforms) {
        var wrap = document.createElement('div');
        wrap.className = 'platform-chips';
        platforms.forEach(function addChip(p) {
            var chip = document.createElement('span');
            chip.className = 'platform-chip ' + getPlatformChipClass(p);
            chip.setAttribute('dir', 'ltr');
            chip.textContent = formatPlatformLabel(p);
            var tipInfo = getPlatformTipInfo(p);
            setRichTooltip(chip, tipInfo.title, tipInfo.body, tipInfo.variant);
            wrap.appendChild(chip);
        });
        return wrap;
    }

    function createResolverIndicator(item, interactive) {
        if (item.resolver === 'ps3') {
            var yesBadge = document.createElement('span');
            yesBadge.className = 'games-resolver-badge games-resolver-badge--ps3';
            var yesLabel = tSite('games.resolver_ps3');
            setRichTooltip(yesBadge, yesLabel, tSite('games.modal_resolver_ps3_desc'), 'full');
            yesBadge.appendChild(createIconSvg('check', 'icon-xs'));
            var yesTxt = document.createElement('span');
            yesTxt.textContent = yesLabel;
            yesBadge.appendChild(yesTxt);
            return yesBadge;
        }
        if (item.resolver === 'plugins') {
            var plugEl = document.createElement(interactive ? 'a' : 'span');
            plugEl.className = 'games-resolver-badge games-resolver-badge--plugins';
            var plugLabel = tSite('games.resolver_plugins');
            setRichTooltip(plugEl, plugLabel, tSite('games.modal_resolver_plugins_desc'), 'resolver');
            if (interactive) {
                plugEl.href = '#username-resolving';
                plugEl.addEventListener('click', function onJumpResolver(ev) {
                    ev.stopPropagation();
                });
            }
            plugEl.appendChild(createIconSvg('scan-eye', 'icon-xs'));
            var plugTxt = document.createElement('span');
            plugTxt.textContent = plugLabel;
            plugEl.appendChild(plugTxt);
            return plugEl;
        }
        var noSpan = document.createElement('span');
        noSpan.className = 'games-resolver-no';
        var noLabel = tSite('games.resolver_no');
        noSpan.textContent = noLabel;
        setRichTooltip(
            noSpan,
            tSite('games.col_resolver') + ' — ' + noLabel,
            tSite('games.modal_resolver_none_desc'),
            'verified'
        );
        return noSpan;
    }

    function getCategoryPool() {
        if (gamesState.category === 'game') {
            return GAMES_ONLY_LIST;
        }
        if (gamesState.category === 'software') {
            return SOFTWARE_ONLY_LIST;
        }
        return SUPPORTED_CATALOG;
    }

    function getFilteredCatalog() {
        var pool = getCategoryPool();
        var q = gamesState.searchQuery.trim().toLowerCase();

        var filtered = pool.filter(function matchEntry(item) {
            if (gamesState.p2pFilter === 'resolver') {
                if (item.resolver === 'no') {
                    return false;
                }
            } else if (gamesState.p2pFilter !== 'all' && item.p2p !== gamesState.p2pFilter) {
                return false;
            }

            if (!platformMatchesFilter(item.platforms, gamesState.platformFilter)) {
                return false;
            }

            if (!q) {
                return true;
            }

            var displayName = getCatalogItemName(item).toLowerCase();
            var rawName = item.name.toLowerCase();
            var noteText = getCatalogItemNote(item).toLowerCase();
            var p2pLabel = tSite((P2P_META[item.p2p] || P2P_META.verified).labelKey).toLowerCase();
            var platText = item.platforms.join(' ').toLowerCase();
            var toolkitText = item.toolkit ? item.toolkit.toLowerCase() : '';

            return (
                displayName.indexOf(q) !== -1
                || rawName.indexOf(q) !== -1
                || noteText.indexOf(q) !== -1
                || p2pLabel.indexOf(q) !== -1
                || platText.indexOf(q) !== -1
                || toolkitText.indexOf(q) !== -1
            );
        });

        var dir = gamesState.sortDir === 'desc' ? -1 : 1;
        return filtered.slice().sort(function sortEntries(a, b) {
            var field = gamesState.sortField;
            var cmp = 0;
            if (field === 'p2p') {
                cmp = ((P2P_META[a.p2p] || P2P_META.verified).order) - ((P2P_META[b.p2p] || P2P_META.verified).order);
            } else if (field === 'platforms') {
                cmp = b.platforms.length - a.platforms.length;
                if (cmp === 0) {
                    cmp = a.platforms.join(', ').localeCompare(b.platforms.join(', '));
                }
            } else if (field === 'resolver') {
                var rank = { ps3: 0, plugins: 1, no: 2 };
                cmp = (rank[a.resolver] !== undefined ? rank[a.resolver] : 2) - (rank[b.resolver] !== undefined ? rank[b.resolver] : 2);
            }
            if (cmp === 0) {
                cmp = getCatalogItemName(a).localeCompare(getCatalogItemName(b));
            }
            return cmp * dir;
        });
    }

    function buildMarqueeWall() {
        var row1 = document.getElementById('games-marquee-row-1');
        var row2 = document.getElementById('games-marquee-row-2');
        if (!row1 || !row2) {
            return;
        }

        /* Put iconic hits near the front while still showcasing all 56 tested games */
        var ordered = GAMES_ONLY_LIST.slice().sort(function sortShowcase(a, b) {
            var ra = typeof a.showcaseRank === 'number' ? a.showcaseRank : 999;
            var rb = typeof b.showcaseRank === 'number' ? b.showcaseRank : 999;
            if (ra !== rb) {
                return ra - rb;
            }
            return a.name.localeCompare(b.name);
        });

        var firstHalf = [];
        var secondHalf = [];
        ordered.forEach(function splitRows(item, idx) {
            if (idx % 2 === 0) {
                firstHalf.push(item);
            } else {
                secondHalf.push(item);
            }
        });

        function populateRow(trackEl, list) {
            trackEl.innerHTML = '';
            /* Duplicate sequence once for seamless 0% -> -50% infinite loop */
            var doubled = list.concat(list);
            doubled.forEach(function addTile(item, dupIdx) {
                var btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'marquee-jacket marquee-jacket--' + item.p2p;
                btn.setAttribute('data-marquee-id', item.id);
                btn.setAttribute('aria-label', getCatalogItemName(item));
                if (dupIdx >= list.length) {
                    btn.setAttribute('tabindex', '-1');
                    btn.setAttribute('aria-hidden', 'true');
                }

                attachCoverArtwork(btn, item);

                var dot = document.createElement('span');
                dot.className = 'marquee-jacket-dot marquee-jacket-dot--' + item.p2p;
                dot.setAttribute('aria-hidden', 'true');
                btn.appendChild(dot);

                if (item.toolkit) {
                    var tk = document.createElement('span');
                    tk.className = 'marquee-jacket-toolkit';
                    tk.setAttribute('aria-hidden', 'true');
                    tk.appendChild(createIconSvg('crown', 'icon-xs'));
                    btn.appendChild(tk);
                }

                var scrim = document.createElement('div');
                scrim.className = 'marquee-jacket-scrim';
                var nameSpan = document.createElement('span');
                nameSpan.className = 'marquee-jacket-name';
                nameSpan.textContent = getCatalogItemName(item);
                scrim.appendChild(nameSpan);
                btn.appendChild(scrim);

                btn.addEventListener('click', function onClickShowcase() {
                    openGameDetailModal(item, ordered);
                });

                trackEl.appendChild(btn);
            });
        }

        populateRow(row1, firstHalf);
        populateRow(row2, secondHalf);

        marqueeState.rows[0].el = row1;
        marqueeState.rows[0].itemCount = firstHalf.length;
        marqueeState.rows[1].el = row2;
        marqueeState.rows[1].itemCount = secondHalf.length;
    }

    function wrapMarqueeOffset(offset, loopWidth) {
        if (loopWidth <= 0) {
            return 0;
        }
        var mod = offset % loopWidth;
        return mod < 0 ? mod + loopWidth : mod;
    }

    function applyMarqueeRowTransform(row) {
        if (!row.el) {
            return;
        }
        row.el.style.transform = 'translate3d(' + (-row.offset).toFixed(2) + 'px, 0, 0)';
    }

    function measureMarqueeRows() {
        for (var i = 0; i < marqueeState.rows.length; i += 1) {
            var row = marqueeState.rows[i];
            if (!row.el || row.itemCount <= 0 || row.el.children.length <= row.itemCount) {
                continue;
            }
            var first = row.el.children[0];
            var dup = row.el.children[row.itemCount];
            var nextWidth = dup.offsetLeft - first.offsetLeft;
            if (nextWidth > 0 && nextWidth !== row.loopWidth) {
                if (row.loopWidth > 0) {
                    row.offset = wrapMarqueeOffset((row.offset / row.loopWidth) * nextWidth, nextWidth);
                } else {
                    row.offset = wrapMarqueeOffset(row.offset, nextWidth);
                }
                row.loopWidth = nextWidth;
                applyMarqueeRowTransform(row);
            }
        }
    }

    function shiftMarqueeManual(deltaPx) {
        if (!deltaPx) {
            return;
        }
        if (marqueeState.rows[0].loopWidth <= 0 || marqueeState.rows[1].loopWidth <= 0) {
            measureMarqueeRows();
        }
        for (var i = 0; i < marqueeState.rows.length; i += 1) {
            var row = marqueeState.rows[i];
            if (row.loopWidth > 0) {
                row.offset = wrapMarqueeOffset(row.offset + deltaPx, row.loopWidth);
                applyMarqueeRowTransform(row);
            }
        }
    }

    function syncMarqueePausedUi(isPaused) {
        if (marqueeState.pausedUi === isPaused) {
            return;
        }
        marqueeState.pausedUi = isPaused;
        if (marqueeState.shell) {
            marqueeState.shell.classList.toggle('is-paused', isPaused);
        }
    }

    function clearMarqueeWakeTimer() {
        if (marqueeState.wakeTimerId) {
            window.clearTimeout(marqueeState.wakeTimerId);
            marqueeState.wakeTimerId = 0;
        }
    }

    function scheduleMarqueeWake(delayMs) {
        clearMarqueeWakeTimer();
        if (delayMs > 0) {
            marqueeState.wakeTimerId = window.setTimeout(function onWakeMarquee() {
                marqueeState.wakeTimerId = 0;
                ensureMarqueeRunning();
            }, Math.ceil(delayMs) + 16);
        }
    }

    function stopMarqueeLoop() {
        if (marqueeState.rafId) {
            window.cancelAnimationFrame(marqueeState.rafId);
            marqueeState.rafId = 0;
        }
        marqueeState.lastFrameTime = 0;
    }

    function isElementFocusVisible(el) {
        if (!el || typeof el.matches !== 'function') {
            return false;
        }
        try {
            return el.matches(':focus-visible');
        } catch (_err) {
            return false;
        }
    }

    function stepMarquee(now) {
        marqueeState.rafId = 0;

        if (document.hidden || !marqueeState.isVisible) {
            marqueeState.lastFrameTime = 0;
            return;
        }

        var dt = marqueeState.lastFrameTime ? Math.min((now - marqueeState.lastFrameTime) / 1000, 0.05) : 0.016;
        marqueeState.lastFrameTime = now;

        var isUserMoving = (
            marqueeState.isPointerDown
            || Math.abs(marqueeState.wheelPending) > 0.4
            || Math.abs(marqueeState.inertiaVel) > 6
        );
        var hasHardPause = (
            marqueeState.reducedMotion
            || gamesState.modalOpen
            || marqueeState.isHovered
            || marqueeState.isFocused
            || marqueeState.isPointerDown
        );
        var wantAutoPause = hasHardPause || isUserMoving || now < marqueeState.autoResumeAt;

        syncMarqueePausedUi(wantAutoPause);

        var targetAuto = wantAutoPause ? 0 : 1;
        if (marqueeState.autoFactor !== targetAuto) {
            var blendRate = targetAuto === 0 ? 18 : 4.2;
            marqueeState.autoFactor += (targetAuto - marqueeState.autoFactor) * (1 - Math.exp(-blendRate * dt));
            if (Math.abs(targetAuto - marqueeState.autoFactor) < 0.004) {
                marqueeState.autoFactor = targetAuto;
            }
        }

        var manualDelta = 0;
        if (Math.abs(marqueeState.wheelPending) > 0.05) {
            var wheelStep = marqueeState.wheelPending * (1 - Math.exp(-15 * dt));
            marqueeState.wheelPending -= wheelStep;
            manualDelta += wheelStep;
        } else {
            marqueeState.wheelPending = 0;
        }

        if (!marqueeState.isPointerDown && Math.abs(marqueeState.inertiaVel) > 6) {
            manualDelta += marqueeState.inertiaVel * dt;
            marqueeState.inertiaVel *= Math.exp(-4.6 * dt);
            if (Math.abs(marqueeState.inertiaVel) > 25) {
                marqueeState.autoResumeAt = Math.max(marqueeState.autoResumeAt, now + 1100);
            }
        } else if (!marqueeState.isPointerDown) {
            marqueeState.inertiaVel = 0;
        }

        if (marqueeState.rows[0].loopWidth <= 0 || marqueeState.rows[1].loopWidth <= 0) {
            measureMarqueeRows();
        }

        for (var i = 0; i < marqueeState.rows.length; i += 1) {
            var row = marqueeState.rows[i];
            if (row.loopWidth <= 0) {
                continue;
            }
            var autoVel = (row.loopWidth / row.durationSec) * row.dir * marqueeState.autoFactor;
            var totalDelta = autoVel * dt + manualDelta;
            if (totalDelta !== 0) {
                row.offset = wrapMarqueeOffset(row.offset + totalDelta, row.loopWidth);
                applyMarqueeRowTransform(row);
            }
        }

        var needsNextFrame = (
            !wantAutoPause
            || marqueeState.autoFactor > 0
            || Math.abs(marqueeState.wheelPending) > 0.05
            || Math.abs(marqueeState.inertiaVel) > 6
        );
        if (needsNextFrame) {
            marqueeState.rafId = window.requestAnimationFrame(stepMarquee);
        } else {
            marqueeState.lastFrameTime = 0;
            if (!hasHardPause && now < marqueeState.autoResumeAt) {
                scheduleMarqueeWake(marqueeState.autoResumeAt - now);
            }
        }
    }

    function ensureMarqueeRunning() {
        clearMarqueeWakeTimer();
        if (!marqueeState.viewport || document.hidden || !marqueeState.isVisible) {
            return;
        }
        if (!marqueeState.rafId) {
            marqueeState.lastFrameTime = 0;
            marqueeState.rafId = window.requestAnimationFrame(stepMarquee);
        }
    }

    function onMarqueeModalToggle(isOpen) {
        if (isOpen) {
            marqueeState.isHovered = false;
            marqueeState.wheelPending = 0;
            marqueeState.inertiaVel = 0;
            syncMarqueePausedUi(true);
            ensureMarqueeRunning();
        } else {
            marqueeState.autoResumeAt = performance.now() + 900;
            ensureMarqueeRunning();
        }
    }

    function initInteractiveMarquee() {
        var shell = document.getElementById('games-marquee-shell');
        var viewport = document.getElementById('games-marquee-viewport');
        if (!shell || !viewport) {
            return;
        }
        marqueeState.shell = shell;
        marqueeState.viewport = viewport;

        var reducedMotionMq = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
        marqueeState.reducedMotion = !!(reducedMotionMq && reducedMotionMq.matches);
        if (marqueeState.reducedMotion) {
            marqueeState.autoFactor = 0;
            syncMarqueePausedUi(true);
        }
        if (reducedMotionMq) {
            var onReducedMotionChange = function onReducedMotionChange(ev) {
                marqueeState.reducedMotion = !!ev.matches;
                ensureMarqueeRunning();
            };
            if (typeof reducedMotionMq.addEventListener === 'function') {
                reducedMotionMq.addEventListener('change', onReducedMotionChange);
            } else if (typeof reducedMotionMq.addListener === 'function') {
                reducedMotionMq.addListener(onReducedMotionChange);
            }
        }

        measureMarqueeRows();

        if (typeof window.ResizeObserver === 'function') {
            var resizeObserver = new window.ResizeObserver(function onMarqueeResize() {
                measureMarqueeRows();
            });
            resizeObserver.observe(viewport);
        } else {
            window.addEventListener('resize', measureMarqueeRows);
        }

        if (typeof window.IntersectionObserver === 'function') {
            var io = new window.IntersectionObserver(function onMarqueeIntersect(entries) {
                if (!entries || !entries.length) {
                    return;
                }
                marqueeState.isVisible = entries[0].isIntersecting;
                if (marqueeState.isVisible) {
                    ensureMarqueeRunning();
                } else {
                    stopMarqueeLoop();
                    clearMarqueeWakeTimer();
                }
            }, { threshold: 0.01 });
            io.observe(viewport);
        }

        document.addEventListener('visibilitychange', function onDocVisChange() {
            if (document.hidden) {
                stopMarqueeLoop();
                clearMarqueeWakeTimer();
            } else {
                ensureMarqueeRunning();
            }
        });

        /* Auto-pause on desktop mouse hover; ignore emulated touch hover so touch always auto-resumes */
        viewport.addEventListener('pointerenter', function onMarqueePointerEnter(ev) {
            if (ev.pointerType !== 'mouse') {
                return;
            }
            marqueeState.isHovered = true;
            ensureMarqueeRunning();
        });

        viewport.addEventListener('pointerleave', function onMarqueePointerLeave(ev) {
            if (ev.pointerType !== 'mouse') {
                return;
            }
            marqueeState.isHovered = false;
            marqueeState.autoResumeAt = Math.max(marqueeState.autoResumeAt, performance.now() + 450);
            ensureMarqueeRunning();
        });

        /* Mouse wheel & trackpad horizontal/vertical scrolling with smooth kinetic easing */
        viewport.addEventListener('wheel', function onMarqueeWheel(ev) {
            if (ev.ctrlKey || ev.metaKey || gamesState.modalOpen) {
                return;
            }
            var dx = ev.deltaX || 0;
            var dy = ev.deltaY || 0;
            if (dx === 0 && dy === 0) {
                return;
            }
            var raw = Math.abs(dx) >= Math.abs(dy) ? dx : dy;
            var unit = 1;
            if (ev.deltaMode === 1) {
                unit = 28;
            } else if (ev.deltaMode === 2) {
                unit = Math.max(viewport.clientWidth * 0.85, 320);
            }
            var scaled = raw * unit * 1.25;
            var clamped = Math.max(-420, Math.min(420, scaled));
            if (clamped === 0) {
                return;
            }

            ev.preventDefault();
            hideRichTooltip();
            marqueeState.inertiaVel = 0;
            marqueeState.wheelPending = Math.max(-1600, Math.min(1600, marqueeState.wheelPending + clamped));
            marqueeState.autoResumeAt = Math.max(marqueeState.autoResumeAt, performance.now() + 2000);
            ensureMarqueeRunning();
        }, { passive: false });

        /* Touch finger swipe & mouse drag with axis locking and native-feeling fling inertia */
        var drag = marqueeState.drag;

        viewport.addEventListener('pointerdown', function onMarqueePointerDown(ev) {
            if (gamesState.modalOpen) {
                return;
            }
            if (ev.pointerType === 'mouse' && ev.button !== 0) {
                return;
            }
            if (drag.active) {
                return;
            }
            var now = performance.now();
            drag.active = true;
            drag.pointerId = ev.pointerId;
            drag.pointerType = ev.pointerType || 'mouse';
            drag.startX = ev.clientX;
            drag.startY = ev.clientY;
            drag.lastX = ev.clientX;
            drag.axisLocked = null;
            drag.hasDragged = false;
            drag.captured = false;
            drag.samples = [{ x: ev.clientX, t: now }];

            marqueeState.isPointerDown = true;
            marqueeState.inertiaVel = 0;
            marqueeState.wheelPending = 0;
            ensureMarqueeRunning();
        });

        viewport.addEventListener('pointermove', function onMarqueeHoverSelfHeal(ev) {
            if (ev.pointerType === 'mouse' && !marqueeState.isHovered && !gamesState.modalOpen) {
                marqueeState.isHovered = true;
                ensureMarqueeRunning();
            }
        });

        window.addEventListener('pointermove', function onMarqueePointerMove(ev) {
            if (!drag.active || ev.pointerId !== drag.pointerId) {
                return;
            }
            if (drag.axisLocked === 'y') {
                return;
            }

            var now = performance.now();
            var totalDx = ev.clientX - drag.startX;
            var totalDy = ev.clientY - drag.startY;

            if (drag.axisLocked === null) {
                if (drag.pointerType === 'mouse') {
                    if (Math.abs(totalDx) < 5) {
                        return;
                    }
                    drag.axisLocked = 'x';
                } else {
                    if (Math.abs(totalDx) < 6 && Math.abs(totalDy) < 6) {
                        return;
                    }
                    if (Math.abs(totalDy) > Math.abs(totalDx) * 1.15) {
                        drag.axisLocked = 'y';
                        drag.active = false;
                        marqueeState.isPointerDown = false;
                        marqueeState.autoResumeAt = Math.max(marqueeState.autoResumeAt, now + 1000);
                        ensureMarqueeRunning();
                        return;
                    }
                    drag.axisLocked = 'x';
                }

                drag.hasDragged = true;
                drag.lastX = ev.clientX;
                drag.samples = [{ x: ev.clientX, t: now }];
                hideRichTooltip();
                viewport.classList.add('is-dragging');
                try {
                    viewport.setPointerCapture(ev.pointerId);
                    drag.captured = true;
                } catch (_err) {
                    drag.captured = false;
                }
            }

            var stepDx = ev.clientX - drag.lastX;
            drag.lastX = ev.clientX;
            if (stepDx !== 0) {
                shiftMarqueeManual(-stepDx);
            }
            drag.samples.push({ x: ev.clientX, t: now });
            while (drag.samples.length > 2 && now - drag.samples[0].t > 100) {
                drag.samples.shift();
            }
        });

        /* Guard horizontal touchmove so mobile browsers don't hijack swipes while keeping vertical scroll native */
        viewport.addEventListener('touchmove', function onMarqueeTouchMove(ev) {
            if (!ev.cancelable || !drag.active || drag.pointerType !== 'touch' || !ev.touches || ev.touches.length !== 1) {
                return;
            }
            if (drag.axisLocked === 'x') {
                ev.preventDefault();
                return;
            }
            if (drag.axisLocked === null) {
                var touch = ev.touches[0];
                var tdx = touch.clientX - drag.startX;
                var tdy = touch.clientY - drag.startY;
                if (Math.abs(tdx) > 6 && Math.abs(tdx) >= Math.abs(tdy)) {
                    ev.preventDefault();
                }
            }
        }, { passive: false });

        function finishMarqueeDrag(ev, cancelled) {
            if (!drag.active) {
                return;
            }
            if (ev && ev.pointerId !== undefined && ev.pointerId !== drag.pointerId) {
                return;
            }

            var wasDragged = drag.hasDragged;
            var wasTouch = drag.pointerType !== 'mouse';
            var samples = drag.samples;
            var pid = drag.pointerId;
            var wasCaptured = drag.captured;

            drag.active = false;
            drag.pointerId = null;
            drag.axisLocked = null;
            drag.hasDragged = false;
            drag.captured = false;
            drag.samples = [];

            marqueeState.isPointerDown = false;
            viewport.classList.remove('is-dragging');
            if (wasCaptured && pid !== null) {
                try {
                    viewport.releasePointerCapture(pid);
                } catch (_err) {
                    /* Pointer capture already released. */
                }
            }
            if (!wasTouch && ev && typeof ev.clientX === 'number' && typeof ev.clientY === 'number') {
                var vpBounds = viewport.getBoundingClientRect();
                if (
                    ev.clientX < vpBounds.left
                    || ev.clientX > vpBounds.right
                    || ev.clientY < vpBounds.top
                    || ev.clientY > vpBounds.bottom
                ) {
                    marqueeState.isHovered = false;
                }
            }

            var now = performance.now();
            if (wasDragged) {
                marqueeState.suppressClickUntil = now + 400;
                if (!cancelled && samples.length >= 2) {
                    var lastSample = samples[samples.length - 1];
                    if (now - lastSample.t < 95) {
                        while (samples.length > 2 && lastSample.t - samples[0].t > 110) {
                            samples.shift();
                        }
                        var spanSec = (lastSample.t - samples[0].t) / 1000;
                        if (spanSec > 0.008) {
                            var rawVel = -(lastSample.x - samples[0].x) / spanSec;
                            if (Math.abs(rawVel) > 55) {
                                marqueeState.inertiaVel = Math.max(-3000, Math.min(3000, rawVel));
                            }
                        }
                    }
                }
            }

            marqueeState.autoResumeAt = Math.max(marqueeState.autoResumeAt, now + (wasTouch ? 2200 : 1600));
            ensureMarqueeRunning();
        }

        window.addEventListener('pointerup', function onMarqueePointerUp(ev) {
            finishMarqueeDrag(ev, false);
        });
        window.addEventListener('pointercancel', function onMarqueePointerCancel(ev) {
            finishMarqueeDrag(ev, true);
        });
        window.addEventListener('blur', function onMarqueeWindowBlur() {
            if (drag.active) {
                finishMarqueeDrag(null, true);
            }
        });

        /* Suppress accidental cover click immediately after a drag gesture */
        viewport.addEventListener('click', function onMarqueeClickCapture(ev) {
            if (performance.now() < marqueeState.suppressClickUntil) {
                ev.preventDefault();
                ev.stopPropagation();
            }
        }, true);

        viewport.addEventListener('dragstart', function onMarqueeDragStart(ev) {
            ev.preventDefault();
        });

        /* Auto-pause on keyboard focus and support Left/Right arrow scrolling */
        viewport.addEventListener('focusin', function onMarqueeFocusIn(ev) {
            if (!isElementFocusVisible(ev.target)) {
                return;
            }
            marqueeState.isFocused = true;
            var vpRect = viewport.getBoundingClientRect();
            var targetRect = ev.target.getBoundingClientRect();
            if (targetRect.left < vpRect.left + 24) {
                marqueeState.wheelPending += targetRect.left - (vpRect.left + 48);
            } else if (targetRect.right > vpRect.right - 24) {
                marqueeState.wheelPending += targetRect.right - (vpRect.right - 48);
            }
            ensureMarqueeRunning();
        });

        viewport.addEventListener('focusout', function onMarqueeFocusOut(ev) {
            if (!viewport.contains(ev.relatedTarget)) {
                marqueeState.isFocused = false;
                marqueeState.autoResumeAt = Math.max(marqueeState.autoResumeAt, performance.now() + 600);
                ensureMarqueeRunning();
            }
        });

        viewport.addEventListener('keydown', function onMarqueeKeyDown(ev) {
            if (gamesState.modalOpen) {
                return;
            }
            if (ev.key === 'ArrowLeft' || ev.key === 'ArrowRight') {
                ev.preventDefault();
                hideRichTooltip();
                marqueeState.inertiaVel = 0;
                var step = ev.key === 'ArrowRight' ? 250 : -250;
                marqueeState.wheelPending = Math.max(-1600, Math.min(1600, marqueeState.wheelPending + step));
                marqueeState.autoResumeAt = Math.max(marqueeState.autoResumeAt, performance.now() + 2000);
                ensureMarqueeRunning();
            }
        });

        ensureMarqueeRunning();
    }

    function updateGamesStaticCopy() {
        var leadEl = document.getElementById('games-section-lead');
        if (leadEl) {
            leadEl.textContent = tSite('games.subtitle', {
                games: GAMES_ONLY_LIST.length,
                apps: SOFTWARE_ONLY_LIST.length,
            });
        }

        var statGames = document.getElementById('games-stat-games');
        if (statGames) {
            statGames.textContent = String(GAMES_ONLY_LIST.length);
        }

        var statApps = document.getElementById('games-stat-apps');
        if (statApps) {
            statApps.textContent = String(SOFTWARE_ONLY_LIST.length);
        }

        var catGameCount = document.getElementById('games-cat-count-game');
        var catSwCount = document.getElementById('games-cat-count-software');
        var catAllCount = document.getElementById('games-cat-count-all');
        if (catGameCount) {
            catGameCount.textContent = String(GAMES_ONLY_LIST.length);
        }
        if (catSwCount) {
            catSwCount.textContent = String(SOFTWARE_ONLY_LIST.length);
        }
        if (catAllCount) {
            catAllCount.textContent = String(SUPPORTED_CATALOG.length);
        }

        updateGamesTooltips();
    }

    function updateGamesTooltips() {
        var fullCount = GAMES_ONLY_LIST.filter(function isFull(i) { return i.p2p === 'full'; }).length;
        var hostCount = GAMES_ONLY_LIST.filter(function isHost(i) { return i.p2p === 'host'; }).length;
        var partialCount = GAMES_ONLY_LIST.filter(function isPart(i) { return i.p2p === 'partial'; }).length;

        setRichTooltip(
            document.getElementById('games-eyebrow-pill'),
            tSite('games.stat_universal_label'),
            tSite('games.stat_universal_sub'),
            'partial'
        );
        setRichTooltip(
            document.getElementById('games-summary-games'),
            tSite('games.stat_games_label'),
            tSite('games.stat_games_sub', {
                full: fullCount,
                host: hostCount,
                partial: partialCount,
            }),
            'full'
        );
        setRichTooltip(
            document.getElementById('games-summary-apps'),
            tSite('games.stat_apps_label'),
            tSite('games.stat_apps_sub'),
            'partial'
        );
        setRichTooltip(
            document.getElementById('games-summary-platforms'),
            tSite('games.stat_platforms_label'),
            'PC · PS5 · PS4 · PS3 · Xbox · Android · iOS',
            'neutral'
        );
        setRichTooltip(
            document.getElementById('games-th-p2p'),
            tSite('games.col_p2p'),
            tSite('games.tip_p2p_col'),
            'partial'
        );
        setRichTooltip(
            document.getElementById('games-th-platforms'),
            tSite('games.col_platforms'),
            tSite('games.tip_platforms_col'),
            'neutral'
        );
        setRichTooltip(
            document.getElementById('games-th-resolver'),
            tSite('games.col_resolver'),
            tSite('games.tip_resolver_col'),
            'resolver'
        );

        var byId = {};
        GAMES_ONLY_LIST.forEach(function mapGame(g) {
            byId[g.id] = g;
        });
        document.querySelectorAll('.marquee-jacket[data-marquee-id]').forEach(function syncMarqueeTip(btn) {
            var item = byId[btn.getAttribute('data-marquee-id')];
            if (!item) {
                return;
            }
            var p2pMeta = P2P_META[item.p2p] || P2P_META.verified;
            setRichTooltip(
                btn,
                getCatalogItemName(item) + ' · ' + tSite(p2pMeta.labelKey),
                tSite(p2pMeta.descKey),
                item.p2p
            );
        });
    }

    function renderGamesFilters() {
        var p2pBar = document.getElementById('games-p2p-filters');
        var platBar = document.getElementById('games-platform-filters');
        var pool = getCategoryPool();

        if (p2pBar) {
            p2pBar.innerHTML = '';
            var platformPool = pool.filter(function byPlat(item) {
                return platformMatchesFilter(item.platforms, gamesState.platformFilter);
            });

            var p2pOptions = [
                { key: 'all', labelKey: 'games.filter_p2p_all', descKey: 'games.tip_p2p_all', dot: null, variant: 'neutral' },
                { key: 'full', labelKey: 'games.p2p_full', descKey: 'games.p2p_full_desc', dot: 'full', variant: 'full' },
                { key: 'host', labelKey: 'games.p2p_host', descKey: 'games.p2p_host_desc', dot: 'host', variant: 'host' },
                { key: 'partial', labelKey: 'games.p2p_partial', descKey: 'games.p2p_partial_desc', dot: 'partial', variant: 'partial' },
                { key: 'verified', labelKey: 'games.p2p_verified', descKey: 'games.p2p_verified_desc', dot: 'verified', variant: 'verified' },
                { key: 'resolver', labelKey: 'games.filter_resolver', descKey: 'games.tip_resolver_col', dot: 'resolver', variant: 'resolver' },
            ];

            p2pOptions.forEach(function addP2pPill(opt) {
                var count = platformPool.filter(function countMatch(item) {
                    if (opt.key === 'all') {
                        return true;
                    }
                    if (opt.key === 'resolver') {
                        return item.resolver !== 'no';
                    }
                    return item.p2p === opt.key;
                }).length;

                if (opt.key !== 'all' && count === 0 && gamesState.p2pFilter !== opt.key) {
                    return;
                }

                var isActive = gamesState.p2pFilter === opt.key;
                var btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'games-filter-pill' + (isActive ? ' is-active' : '');
                btn.setAttribute('aria-pressed', isActive ? 'true' : 'false');
                var labelText = tSite(opt.labelKey);
                setRichTooltip(btn, labelText, tSite(opt.descKey), opt.variant);

                if (opt.dot) {
                    var dot = document.createElement('span');
                    dot.className = 'games-filter-dot games-filter-dot--' + opt.dot;
                    dot.setAttribute('aria-hidden', 'true');
                    btn.appendChild(dot);
                }

                var lbl = document.createElement('span');
                lbl.textContent = labelText;
                btn.appendChild(lbl);

                var cnt = document.createElement('span');
                cnt.className = 'games-filter-count';
                cnt.textContent = String(count);
                btn.appendChild(cnt);

                btn.addEventListener('click', function onSelectP2p() {
                    gamesState.p2pFilter = opt.key;
                    renderGamesExplorer();
                });

                p2pBar.appendChild(btn);
            });
        }

        if (platBar) {
            platBar.innerHTML = '';
            PLATFORM_FILTERS.forEach(function addPlatPill(opt) {
                if (opt.cats.indexOf(gamesState.category) === -1) {
                    return;
                }
                var isActive = gamesState.platformFilter === opt.key;
                var btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'games-filter-pill games-filter-pill--platform' + (isActive ? ' is-active' : '');
                btn.setAttribute('aria-pressed', isActive ? 'true' : 'false');

                var tipInfo = getPlatformTipInfo(opt.key);
                setRichTooltip(btn, tipInfo.title, tipInfo.body, tipInfo.variant);

                var lbl = document.createElement('span');
                lbl.textContent = opt.labelKey ? tSite(opt.labelKey) : opt.label;
                btn.appendChild(lbl);

                btn.addEventListener('click', function onSelectPlat() {
                    gamesState.platformFilter = opt.key;
                    renderGamesExplorer();
                });

                platBar.appendChild(btn);
            });
        }
    }

    function updateGamesSortHeaders() {
        document.querySelectorAll('#games-compat-table thead th[data-games-sort]').forEach(function syncTh(th) {
            var field = th.getAttribute('data-games-sort');
            var isSorted = field === gamesState.sortField;
            th.classList.toggle('is-sorted', isSorted);
            th.setAttribute('aria-sort', isSorted ? (gamesState.sortDir === 'asc' ? 'ascending' : 'descending') : 'none');
            var arrowUse = th.querySelector('.games-sort-arrow use');
            if (arrowUse) {
                arrowUse.setAttribute('href', gamesState.sortDir === 'desc' ? '#icon-chevron-down' : '#icon-chevron-up');
            }
        });
    }

    function renderGamesTable(items) {
        var tbody = document.getElementById('games-table-tbody');
        if (!tbody) {
            return;
        }
        tbody.innerHTML = '';

        if (items.length === 0) {
            var emptyTr = document.createElement('tr');
            var emptyTd = document.createElement('td');
            emptyTd.colSpan = 5;
            emptyTd.className = 'games-empty-cell';
            emptyTd.textContent = tSite('games.empty_filter');
            emptyTr.appendChild(emptyTd);
            tbody.appendChild(emptyTr);
            return;
        }

        items.forEach(function renderRow(item) {
            var tr = document.createElement('tr');
            if (item.toolkit) {
                tr.className = 'is-featured-row';
            }

            /* Column 1: Cover Thumbnail + Title (+ Toolkit badge) */
            var tdTitle = document.createElement('td');
            var titleWrap = document.createElement('div');
            titleWrap.className = 'games-cell-title';

            var thumb = document.createElement('div');
            thumb.className = 'games-thumb' + (item.category === 'software' ? ' games-thumb--software' : '');
            attachCoverArtwork(thumb, item);

            var meta = document.createElement('div');
            meta.className = 'games-title-meta';

            var nameEl = document.createElement('span');
            nameEl.className = 'games-title-name';
            nameEl.textContent = getCatalogItemName(item);
            meta.appendChild(nameEl);

            if (item.toolkit) {
                var tk = document.createElement('span');
                tk.className = 'games-toolkit-tag';
                var tkLabel = tSite('games.badge_toolkit', { game: item.toolkit });
                setRichTooltip(tk, tkLabel, tSite('games.modal_toolkit_note', { game: item.toolkit }), 'host');
                tk.appendChild(createIconSvg('crown', 'icon-xs'));
                var tkText = document.createElement('span');
                tkText.textContent = tkLabel;
                tk.appendChild(tkText);
                meta.appendChild(tk);
            }

            titleWrap.appendChild(thumb);
            titleWrap.appendChild(meta);
            tdTitle.appendChild(titleWrap);

            /* Column 2: P2P Behavior */
            var tdP2p = document.createElement('td');
            tdP2p.appendChild(createP2pBadge(item.p2p));

            /* Column 3: Tested Platforms */
            var tdPlat = document.createElement('td');
            tdPlat.appendChild(createPlatformChips(item.platforms));

            /* Column 4: Username Resolving */
            var tdRes = document.createElement('td');
            tdRes.appendChild(createResolverIndicator(item, true));

            /* Column 5: Additional Notes */
            var tdNotes = document.createElement('td');
            tdNotes.className = 'games-cell-notes';
            var noteText = getCatalogItemNote(item);
            if (noteText) {
                noteText.split('\n').forEach(function addNoteLine(line) {
                    var div = document.createElement('div');
                    div.className = 'games-note-line';
                    div.textContent = line;
                    tdNotes.appendChild(div);
                });
            } else {
                var dash = document.createElement('span');
                dash.className = 'games-note-empty';
                dash.textContent = '—';
                tdNotes.appendChild(dash);
            }

            tr.appendChild(tdTitle);
            tr.appendChild(tdP2p);
            tr.appendChild(tdPlat);
            tr.appendChild(tdRes);
            tr.appendChild(tdNotes);

            tr.addEventListener('click', function onRowClick() {
                openGameDetailModal(item, items);
            });

            tbody.appendChild(tr);
        });
    }

    function renderGamesCoverGrid(items) {
        var grid = document.getElementById('games-cover-grid');
        var moreWrap = document.getElementById('games-grid-more-wrap');
        var moreLabel = document.getElementById('games-grid-more-label');
        var moreIconUse = document.querySelector('#games-grid-more-icon use');
        if (!grid) {
            return;
        }
        grid.innerHTML = '';

        if (items.length === 0) {
            var empty = document.createElement('div');
            empty.className = 'games-grid-empty';
            empty.textContent = tSite('games.empty_filter');
            grid.appendChild(empty);
            if (moreWrap) {
                moreWrap.hidden = true;
            }
            return;
        }

        var hasActiveFilter = (
            gamesState.p2pFilter !== 'all'
            || gamesState.platformFilter !== 'all'
            || gamesState.searchQuery.trim() !== ''
        );
        var shouldCap = !hasActiveFilter && !gamesState.gridExpanded && items.length > INITIAL_COVERS_LIMIT;
        var visibleItems = shouldCap ? items.slice(0, INITIAL_COVERS_LIMIT) : items;

        visibleItems.forEach(function renderCard(item) {
            var card = document.createElement('button');
            card.type = 'button';
            card.className = 'game-jacket-card game-jacket-card--' + item.p2p;
            card.setAttribute('aria-label', getCatalogItemName(item));

            var media = document.createElement('div');
            media.className = 'game-jacket-media';
            attachCoverArtwork(media, item);

            var sheen = document.createElement('span');
            sheen.className = 'game-jacket-sheen';
            sheen.setAttribute('aria-hidden', 'true');
            media.appendChild(sheen);

            var topBar = document.createElement('div');
            topBar.className = 'game-jacket-top';

            var p2pMetaCard = P2P_META[item.p2p] || P2P_META.verified;
            var p2pChip = document.createElement('span');
            p2pChip.className = 'game-jacket-p2p game-jacket-p2p--' + item.p2p;
            var p2pCardLabel = tSite(p2pMetaCard.labelKey);
            p2pChip.textContent = p2pCardLabel;
            setRichTooltip(p2pChip, p2pCardLabel, tSite(p2pMetaCard.descKey), item.p2p);
            topBar.appendChild(p2pChip);

            if (item.toolkit || item.resolver !== 'no') {
                var iconsWrap = document.createElement('div');
                iconsWrap.className = 'game-jacket-icons';

                if (item.toolkit) {
                    var tkPill = document.createElement('span');
                    tkPill.className = 'game-jacket-icon-pill game-jacket-icon-pill--toolkit';
                    setRichTooltip(
                        tkPill,
                        tSite('games.badge_toolkit', { game: item.toolkit }),
                        tSite('games.modal_toolkit_note', { game: item.toolkit }),
                        'host'
                    );
                    tkPill.appendChild(createIconSvg('crown', 'icon-xs'));
                    iconsWrap.appendChild(tkPill);
                }
                if (item.resolver === 'ps3') {
                    var resPill = document.createElement('span');
                    resPill.className = 'game-jacket-icon-pill game-jacket-icon-pill--resolver';
                    setRichTooltip(
                        resPill,
                        tSite('games.resolver_ps3'),
                        tSite('games.modal_resolver_ps3_desc'),
                        'full'
                    );
                    resPill.appendChild(createIconSvg('user-round-check', 'icon-xs'));
                    iconsWrap.appendChild(resPill);
                } else if (item.resolver === 'plugins') {
                    var plugPill = document.createElement('span');
                    plugPill.className = 'game-jacket-icon-pill game-jacket-icon-pill--plugins';
                    setRichTooltip(
                        plugPill,
                        tSite('games.resolver_plugins'),
                        tSite('games.modal_resolver_plugins_desc'),
                        'resolver'
                    );
                    plugPill.appendChild(createIconSvg('scan-eye', 'icon-xs'));
                    iconsWrap.appendChild(plugPill);
                }
                topBar.appendChild(iconsWrap);
            }

            media.appendChild(topBar);

            var overlay = document.createElement('div');
            overlay.className = 'game-jacket-overlay';

            var titleEl = document.createElement('h4');
            titleEl.className = 'game-jacket-title';
            titleEl.textContent = getCatalogItemName(item);
            overlay.appendChild(titleEl);

            var bottomRow = document.createElement('div');
            bottomRow.className = 'game-jacket-bottom-row';

            var platsWrap = document.createElement('div');
            platsWrap.className = 'game-jacket-platforms';
            item.platforms.slice(0, 3).forEach(function addMicroPlat(p) {
                var chip = document.createElement('span');
                chip.className = 'game-jacket-plat';
                chip.setAttribute('dir', 'ltr');
                chip.textContent = p === 'Xbox Series X|S' ? 'Xbox X|S' : (p === 'PC (Microsoft Store)' ? 'PC' : formatPlatformLabel(p));
                var platTip = getPlatformTipInfo(p);
                setRichTooltip(chip, platTip.title, platTip.body, platTip.variant);
                platsWrap.appendChild(chip);
            });
            if (item.platforms.length > 3) {
                var morePlat = document.createElement('span');
                morePlat.className = 'game-jacket-plat';
                morePlat.setAttribute('dir', 'ltr');
                morePlat.textContent = '+' + (item.platforms.length - 3);
                platsWrap.appendChild(morePlat);
            }
            bottomRow.appendChild(platsWrap);

            if (item.noteKey) {
                var noteDot = document.createElement('span');
                noteDot.className = 'game-jacket-note-dot';
                setRichTooltip(noteDot, tSite('games.modal_notes_heading'), getCatalogItemNote(item), 'partial');
                noteDot.appendChild(createIconSvg('info', 'icon-xs'));
                bottomRow.appendChild(noteDot);
            }

            overlay.appendChild(bottomRow);
            media.appendChild(overlay);
            card.appendChild(media);

            card.addEventListener('click', function onOpenCard() {
                openGameDetailModal(item, items);
            });

            grid.appendChild(card);
        });

        if (moreWrap && moreLabel) {
            if (!hasActiveFilter && items.length > INITIAL_COVERS_LIMIT) {
                moreWrap.hidden = false;
                moreLabel.textContent = gamesState.gridExpanded
                    ? tSite('games.show_less_covers')
                    : tSite('games.show_all_covers', { count: items.length });
                if (moreIconUse) {
                    moreIconUse.setAttribute('href', gamesState.gridExpanded ? '#icon-chevron-up' : '#icon-chevron-down');
                }
            } else {
                moreWrap.hidden = true;
            }
        }
    }

    function syncGamesTabsUi() {
        document.querySelectorAll('#games-category-tabs [data-games-cat]').forEach(function syncCat(btn) {
            var active = btn.getAttribute('data-games-cat') === gamesState.category;
            btn.classList.toggle('is-active', active);
            btn.setAttribute('aria-selected', active ? 'true' : 'false');
        });
        document.querySelectorAll('#games-view-tabs [data-games-view]').forEach(function syncView(btn) {
            var active = btn.getAttribute('data-games-view') === gamesState.view;
            btn.classList.toggle('is-active', active);
            btn.setAttribute('aria-pressed', active ? 'true' : 'false');
        });

        var tableView = document.getElementById('games-table-view');
        var gridView = document.getElementById('games-grid-view');
        if (tableView) {
            tableView.hidden = gamesState.view !== 'table';
        }
        if (gridView) {
            gridView.hidden = gamesState.view !== 'jackets';
        }
    }

    function renderGamesExplorer() {
        syncGamesTabsUi();
        renderGamesFilters();
        updateGamesSortHeaders();

        var pool = getCategoryPool();
        var filtered = getFilteredCatalog();

        var countEl = document.getElementById('games-results-count');
        if (countEl) {
            countEl.textContent = tSite('games.showing_count', {
                shown: filtered.length,
                total: pool.length,
            });
        }

        var resetBtn = document.getElementById('games-reset-filters-btn');
        if (resetBtn) {
            var hasFilters = (
                gamesState.p2pFilter !== 'all'
                || gamesState.platformFilter !== 'all'
                || gamesState.searchQuery.trim() !== ''
            );
            resetBtn.hidden = !hasFilters;
        }

        if (gamesState.view === 'table') {
            renderGamesTable(filtered);
        } else {
            renderGamesCoverGrid(filtered);
        }
        hideRichTooltip();
    }

    function renderGameDetailModal() {
        var item = gamesState.modalList[gamesState.modalIndex];
        if (!item) {
            return;
        }

        var ambientEl = document.getElementById('game-modal-ambient');
        if (ambientEl) {
            if (item.cover) {
                ambientEl.style.backgroundImage = 'url("' + item.cover + '")';
            } else {
                ambientEl.style.backgroundImage = 'radial-gradient(circle at 30% 30%, ' + (item.brandA || '#3b82f6') + ', ' + (item.brandB || '#0f172a') + ')';
            }
        }

        var topBadges = document.getElementById('game-modal-top-badges');
        if (topBadges) {
            topBadges.innerHTML = '';
            var catBadge = document.createElement('span');
            catBadge.className = 'badge badge-muted';
            catBadge.textContent = tSite(item.category === 'software' ? 'games.category_software' : 'games.category_game');
            topBadges.appendChild(catBadge);

            if (item.toolkit) {
                var tkBadge = document.createElement('span');
                tkBadge.className = 'games-toolkit-tag';
                var modalTkLabel = tSite('games.badge_toolkit', { game: item.toolkit });
                setRichTooltip(tkBadge, modalTkLabel, tSite('games.modal_toolkit_note', { game: item.toolkit }), 'host');
                tkBadge.appendChild(createIconSvg('crown', 'icon-xs'));
                var tkTxt = document.createElement('span');
                tkTxt.textContent = modalTkLabel;
                tkBadge.appendChild(tkTxt);
                topBadges.appendChild(tkBadge);
            }
        }

        var coverCol = document.getElementById('game-modal-cover-col');
        if (coverCol) {
            coverCol.innerHTML = '';
            attachCoverArtwork(coverCol, item);
        }

        var titleEl = document.getElementById('game-modal-title');
        if (titleEl) {
            titleEl.textContent = getCatalogItemName(item);
        }

        var p2pMeta = P2P_META[item.p2p] || P2P_META.verified;
        var p2pBadgeWrap = document.getElementById('game-modal-p2p-badge-wrap');
        if (p2pBadgeWrap) {
            p2pBadgeWrap.innerHTML = '';
            p2pBadgeWrap.appendChild(createP2pBadge(item.p2p));
        }
        var p2pDesc = document.getElementById('game-modal-p2p-desc');
        if (p2pDesc) {
            p2pDesc.textContent = tSite(p2pMeta.descKey);
        }

        var toolkitCard = document.getElementById('game-modal-toolkit-card');
        var toolkitDesc = document.getElementById('game-modal-toolkit-desc');
        if (toolkitCard && toolkitDesc) {
            if (item.toolkit) {
                toolkitCard.hidden = false;
                toolkitDesc.textContent = tSite('games.modal_toolkit_note', { game: item.toolkit });
            } else {
                toolkitCard.hidden = true;
            }
        }

        var platWrap = document.getElementById('game-modal-platforms');
        if (platWrap) {
            platWrap.innerHTML = '';
            platWrap.appendChild(createPlatformChips(item.platforms));
        }

        var resBadgeWrap = document.getElementById('game-modal-resolver-badge');
        var resDesc = document.getElementById('game-modal-resolver-desc');
        var resLink = document.getElementById('game-modal-resolver-link');
        if (resBadgeWrap) {
            resBadgeWrap.innerHTML = '';
            if (item.resolver === 'no') {
                var noBadge = document.createElement('span');
                noBadge.className = 'games-resolver-badge games-resolver-badge--none';
                noBadge.appendChild(createIconSvg('x', 'icon-xs'));
                var noBadgeTxt = document.createElement('span');
                noBadgeTxt.textContent = tSite('games.modal_resolver_none_desc');
                noBadge.appendChild(noBadgeTxt);
                resBadgeWrap.appendChild(noBadge);
            } else {
                resBadgeWrap.appendChild(createResolverIndicator(item, false));
            }
        }
        if (resDesc) {
            if (item.resolver === 'ps3') {
                resDesc.hidden = false;
                resDesc.textContent = tSite('games.modal_resolver_ps3_desc');
            } else if (item.resolver === 'plugins') {
                resDesc.hidden = false;
                resDesc.textContent = tSite('games.modal_resolver_plugins_desc');
            } else {
                resDesc.hidden = true;
                resDesc.textContent = '';
            }
        }
        if (resLink) {
            resLink.hidden = item.resolver === 'no';
        }

        var notesCard = document.getElementById('game-modal-notes-card');
        var notesBody = document.getElementById('game-modal-notes-body');
        var noteText = getCatalogItemNote(item);
        if (notesCard && notesBody) {
            notesBody.innerHTML = '';
            if (noteText) {
                notesCard.hidden = false;
                noteText.split('\n').forEach(function addModalNote(line) {
                    var p = document.createElement('div');
                    p.textContent = line;
                    notesBody.appendChild(p);
                });
            } else {
                notesCard.hidden = true;
            }
        }

        var prevBtn = document.getElementById('game-modal-prev');
        var nextBtn = document.getElementById('game-modal-next');
        var closeBtn = document.getElementById('game-modal-close');
        if (prevBtn) {
            prevBtn.disabled = gamesState.modalList.length <= 1;
            prevBtn.setAttribute('aria-label', tSite('games.modal_prev'));
        }
        if (nextBtn) {
            nextBtn.disabled = gamesState.modalList.length <= 1;
            nextBtn.setAttribute('aria-label', tSite('games.modal_next'));
        }
        if (closeBtn) {
            closeBtn.setAttribute('aria-label', tSite('games.modal_close'));
        }
    }

    function openGameDetailModal(item, contextList) {
        var modal = document.getElementById('game-detail-modal');
        if (!modal) {
            return;
        }
        hideRichTooltip();
        var list = Array.isArray(contextList) && contextList.length > 0 ? contextList : SUPPORTED_CATALOG;
        var idx = list.indexOf(item);
        gamesState.modalList = list;
        gamesState.modalIndex = idx >= 0 ? idx : 0;
        gamesState.lastFocusedBeforeModal = document.activeElement;
        gamesState.modalOpen = true;
        onMarqueeModalToggle(true);
        renderGameDetailModal();
        modal.hidden = false;
        var closeBtn = document.getElementById('game-modal-close');
        if (closeBtn) {
            closeBtn.focus();
        }
    }

    function closeGameDetailModal() {
        if (!gamesState.modalOpen) {
            return;
        }
        var modal = document.getElementById('game-detail-modal');
        if (modal) {
            modal.hidden = true;
        }
        gamesState.modalOpen = false;
        if (gamesState.lastFocusedBeforeModal && typeof gamesState.lastFocusedBeforeModal.focus === 'function') {
            gamesState.lastFocusedBeforeModal.focus();
        }
        gamesState.lastFocusedBeforeModal = null;
        onMarqueeModalToggle(false);
    }

    function stepGameDetailModal(delta) {
        if (!gamesState.modalList.length) {
            return;
        }
        var len = gamesState.modalList.length;
        gamesState.modalIndex = (gamesState.modalIndex + delta + len) % len;
        renderGameDetailModal();
    }

    function renderGamesSection() {
        updateGamesStaticCopy();
        renderGamesExplorer();
        if (gamesState.modalOpen) {
            renderGameDetailModal();
        }
    }

    function initGamesSection() {
        buildMarqueeWall();
        initInteractiveMarquee();

        document.querySelectorAll('.games-summary-pill[data-summary-cat]').forEach(function bindSummaryPill(btn) {
            btn.addEventListener('click', function onSummaryJump() {
                var targetCat = btn.getAttribute('data-summary-cat') || 'game';
                gamesState.category = targetCat;
                gamesState.p2pFilter = 'all';
                gamesState.platformFilter = 'all';
                gamesState.gridExpanded = false;
                renderGamesExplorer();
                var explorer = document.getElementById('games-explorer');
                if (explorer && typeof explorer.scrollIntoView === 'function') {
                    explorer.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        });

        var browseBtn = document.getElementById('games-showcase-browse-btn');
        if (browseBtn) {
            browseBtn.addEventListener('click', function onBrowseGallery() {
                gamesState.category = 'game';
                gamesState.view = 'jackets';
                gamesState.p2pFilter = 'all';
                gamesState.platformFilter = 'all';
                gamesState.gridExpanded = false;
                renderGamesExplorer();
                var explorer = document.getElementById('games-explorer');
                if (explorer && typeof explorer.scrollIntoView === 'function') {
                    explorer.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        }

        document.querySelectorAll('#games-category-tabs [data-games-cat]').forEach(function bindCat(btn) {
            btn.addEventListener('click', function onClickCat() {
                var nextCat = btn.getAttribute('data-games-cat') || 'game';
                if (nextCat === gamesState.category) {
                    return;
                }
                gamesState.category = nextCat;
                gamesState.platformFilter = 'all';
                gamesState.p2pFilter = 'all';
                gamesState.gridExpanded = false;
                renderGamesExplorer();
            });
        });

        document.querySelectorAll('#games-view-tabs [data-games-view]').forEach(function bindView(btn) {
            btn.addEventListener('click', function onClickView() {
                var nextView = btn.getAttribute('data-games-view') || 'table';
                if (nextView === gamesState.view) {
                    return;
                }
                gamesState.view = nextView;
                renderGamesExplorer();
            });
        });

        var searchInput = document.getElementById('games-search-input');
        if (searchInput) {
            searchInput.addEventListener('input', function onSearchGames() {
                gamesState.searchQuery = searchInput.value;
                renderGamesExplorer();
            });
        }

        var resetBtn = document.getElementById('games-reset-filters-btn');
        if (resetBtn) {
            resetBtn.addEventListener('click', function onResetGames() {
                gamesState.p2pFilter = 'all';
                gamesState.platformFilter = 'all';
                gamesState.searchQuery = '';
                if (searchInput) {
                    searchInput.value = '';
                }
                renderGamesExplorer();
            });
        }

        var moreBtn = document.getElementById('games-grid-more-btn');
        if (moreBtn) {
            moreBtn.addEventListener('click', function onToggleMoreCovers() {
                gamesState.gridExpanded = !gamesState.gridExpanded;
                renderGamesExplorer();
            });
        }

        document.querySelectorAll('#games-compat-table thead th[data-games-sort]').forEach(function bindSort(th) {
            function toggleSort() {
                var field = th.getAttribute('data-games-sort') || 'name';
                if (gamesState.sortField === field) {
                    gamesState.sortDir = gamesState.sortDir === 'asc' ? 'desc' : 'asc';
                } else {
                    gamesState.sortField = field;
                    gamesState.sortDir = 'asc';
                }
                renderGamesExplorer();
            }
            th.addEventListener('click', toggleSort);
            th.addEventListener('keydown', function onSortKey(ev) {
                if (ev.key === 'Enter' || ev.key === ' ') {
                    ev.preventDefault();
                    toggleSort();
                }
            });
        });

        var modalBackdrop = document.getElementById('game-modal-backdrop');
        var modalClose = document.getElementById('game-modal-close');
        var modalPrev = document.getElementById('game-modal-prev');
        var modalNext = document.getElementById('game-modal-next');
        var modalResLink = document.getElementById('game-modal-resolver-link');
        if (modalBackdrop) {
            modalBackdrop.addEventListener('click', closeGameDetailModal);
        }
        if (modalClose) {
            modalClose.addEventListener('click', closeGameDetailModal);
        }
        if (modalPrev) {
            modalPrev.addEventListener('click', function onPrevGame() {
                stepGameDetailModal(-1);
            });
        }
        if (modalNext) {
            modalNext.addEventListener('click', function onNextGame() {
                stepGameDetailModal(1);
            });
        }
        if (modalResLink) {
            modalResLink.addEventListener('click', function onJumpFromModal() {
                closeGameDetailModal();
            });
        }

        renderGamesSection();
    }


    document.addEventListener('keydown', function onGamesKeyDown(ev) {
        if (ev.key === 'Escape') {
            closeGameDetailModal();
        } else if (gamesState.modalOpen && (ev.key === 'ArrowLeft' || ev.key === 'ArrowRight')) {
            ev.preventDefault();
            var isRtlModal = document.documentElement.getAttribute('dir') === 'rtl';
            var stepModal = ev.key === 'ArrowRight' ? 1 : -1;
            if (isRtlModal) {
                stepModal = -stepModal;
            }
            stepGameDetailModal(stepModal);
        }
    });

    Core.onLanguageChange(renderGamesSection);

    initGamesSection();
}());
