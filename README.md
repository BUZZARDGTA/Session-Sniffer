<div align="center">

# Session Sniffer

**Real-time P2P session monitor, player tracker, and network analysis suite for PC, PlayStation, Xbox, and mobile.**

[![Latest Release](https://img.shields.io/github/v/release/BUZZARDGTA/Session-Sniffer?style=for-the-badge&logo=github&label=Release&color=007ACC)](https://github.com/BUZZARDGTA/Session-Sniffer/releases/latest)
[![Total Downloads](https://img.shields.io/github/downloads/BUZZARDGTA/Session-Sniffer/total?style=for-the-badge&logo=github&label=Downloads&color=2ea44f)](https://github.com/BUZZARDGTA/Session-Sniffer/releases)
[![Platforms](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-4c1?style=for-the-badge)](https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Installation)
[![Languages](https://img.shields.io/badge/Languages-33%20(RTL%20Ready)-8A2BE2?style=for-the-badge)](#-key-features)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg?style=for-the-badge)](https://github.com/BUZZARDGTA/Session-Sniffer/blob/main/COPYING)
[![Discord](https://img.shields.io/badge/Discord-Join%20Community-%235865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/hMZ7MsPX7G)

[**Download**](#-download) • [**Key Features**](#-key-features) • [**Supported Games**](#-officially-tested-and-supported-p2p-video-games) • [**Username Resolving**](#-about-usernames-decryptionresolving) • [**Wiki**](https://github.com/BUZZARDGTA/Session-Sniffer/wiki)

<br>

![Session Sniffer](https://github.com/user-attachments/assets/529c8a1d-8302-4e54-b324-ce215e002390)

</div>

---

## 📝 Description

**Session Sniffer** is a powerful, free, and open-source packet sniffer (also known as an IP sniffer/puller) designed specifically for Peer-to-Peer (P2P) video games and applications on **PC**, **consoles** (PlayStation and Xbox), and **mobile devices**. It helps you monitor live session activity in real time, including:
- Players currently connected in your session (with geolocation, ISP/ASN, VPN/Hosting flags, ports, and live traffic rates).
- Players joining, leaving, or rejoining your session, plus full past-session history.
- Proactive alerts and automated protection against specific players, networks, or regions.

---

## 📥 Download

Grab the latest standalone executable for **Windows**, **Linux**, or **macOS**—no Python installation required—or run directly from source. Built-in update checks (`Stable` and `Pre-release` channels) keep your installation up to date automatically.

<div align="center">

[![Download Latest Release (Windows)](https://img.shields.io/badge/Download%20for%20Windows%20(x64)-%23007ACC?style=for-the-badge&logo=github&logoColor=white)](https://github.com/BUZZARDGTA/Session-Sniffer/releases/latest/download/Session_Sniffer.exe)
[![Download Latest Release (Linux)](https://img.shields.io/badge/Download%20for%20Linux%20(x64)-%23FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://github.com/BUZZARDGTA/Session-Sniffer/releases/latest/download/Session_Sniffer)
[![Download Latest Release (macOS)](https://img.shields.io/badge/Download%20for%20macOS%20(Apple%20Silicon)-%23000000?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/BUZZARDGTA/Session-Sniffer/releases/latest/download/Session_Sniffer_macOS)

</div>

- 📦 **First-time setup?** Follow the step-by-step [**Installation Guide**](https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Installation) for Windows, Linux, and macOS.
- 🐍 **Prefer running or compiling from source?** Check out [**Running from Source**](https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Running-from-Source) and [**Building from Source**](https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Building-from-Source).

---

## 🔑 Key Features

- **Free & Open Source**: Completely free to use under GPLv3, unlike paid closed-source alternatives.
- **Cross-Platform**: Native standalone builds for Windows, Linux, and macOS.
- **No Mods Required**: Operates 100% externally with zero game memory injection or risk of banning.
- **Process & Executable Sniffing**: Restrict packet capture to any PC process by PID or executable name, automatically tracking across restarts and game editions.
- **Console & Mobile Scanning**: Monitor PlayStation, Xbox, and mobile traffic via ARP spoofing or the built-in Wi-Fi Hotspot & Connection Sharing Manager.
- **Server & Protocol Filtering**: Toggle filters for 30+ cloud/game server providers, custom IP/CIDR & ISP/ASN blocklists, noisy protocols, and custom BPF filters.
- **UserIP Databases & Alt Grouping**: Track players across color-coded JSON lists with single IPs/ranges/CIDR, notes, alt-account grouping, conflict resolution, and automatic ZIP backups.
- **Detections, Combo Rules & Protection**: Custom visual popups, voice alerts, multi-condition `AND`/`OR` combo rules, and automatic process-suspension protection.
- **GTA V & RDR2 Toolkit**: Session Host detection, Solo Public Session, Player Resolver (High Rate Monitor & Player Identifier), proximity spike radar (`Adaptive Geiger`), relay detection, and Looky System integration.
- **Session Logging, Live Graphs & Network Tools**: Save and search session history in the Logs Manager, view 10+ real-time analytics graphs, and probe targets with the built-in Ping & Port Scanner tools.
- **Web Dashboard & Discord Integration**: Embedded WebSocket web server for browser/mobile viewing, live Discord Webhook table mirroring, and Discord Rich Presence (RPC).
- **Themes, Global Hotkeys & 33 Languages**: Live Theme Manager (OS sync + 6 built-in presets + custom palettes), in-game global hotkeys, and instant localization in 33 languages (including RTL).

---

## 🎮 Officially Tested and Supported P2P Video Games

Confirmed across **Grand Theft Auto Online**, **Red Dead Online**, **Call of Duty**, **ELDEN RING**, **Borderlands**, **Minecraft**, **Payday 2**, **AnyDesk**, **OmeTV**, and many more on PC, PlayStation, Xbox, and mobile:

<details>
<summary><b>🕹️ View all 56 Officially Tested Video Games</b> <i>(click to expand)</i></summary>
<br>

| Supported Video Games                             | Tested Platforms                         |  Username Resolving  | Additional Note(s)                                                                                                                                                |
| :-----------------------------------------------: | :--------------------------------------: | :------------------: | :---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Borderlands 2                                     | PC                                       |          No          | Only the host is connected through P2P                                                                                                                            |
| Borderlands 3                                     | PC                                       |          No          | Only the host is connected through P2P                                                                                                                            |
| Borderlands 4                                     | PC                                       |          No          |                                                                                                                                                                   |
| Borderlands: The Pre-Sequel                       | PC                                       |          No          | Only the host is connected through P2P                                                                                                                            |
| Call of Duty®: Advanced Warfare                   | PC, PS3                                  |          No          |                                                                                                                                                                   |
| Call of Duty®: Black Ops                          | PC, PS3                                  |          No          | On PC, only non-ranked servers & without VAC are P2P.<br>On PC, the Zombies game mode is always P2P.                                                              |
| Call of Duty®: Black Ops Cold War                 | PC                                       |          No          | On PC, only private matches and COD groups are P2P but only if they are on the same platform as you.<br>On PC, the Zombies game mode may rarely show P2P players. |
| Call of Duty®: Black Ops II                       | PC, PS3                                  |          No          | On PC, the Zombies game mode is always P2P.                                                                                                                       |
| Call of Duty®: Black Ops III                      | PC, PS5, PS3                             |          No          |                                                                                                                                                                   |
| Call of Duty®: Ghosts                             | PC, PS3                                  |          No          |                                                                                                                                                                   |
| Call of Duty®: Infinite Warfare                   | PC                                       |          No          |                                                                                                                                                                   |
| Call of Duty®: Modern Warfare® 2 (2009)           | PC, PS3                                  |          No          |                                                                                                                                                                   |
| Call of Duty®: Modern Warfare® 3 (2011)           | PC, PS3                                  |          No          |                                                                                                                                                                   |
| Call of Duty®: Vanguard                           | PC                                       |          No          | On PC, only private matches and COD groups are P2P but only if they are on the same platform as you.                                                              |
| Call of Duty®: WWII                               | PC                                       |          No          |                                                                                                                                                                   |
| Deep Rock Galactic                                | PC                                       |          No          | Only the host is connected through P2P; exact mechanics unclear                                                                                                   |
| Destiny                                           | PS3                                      |          No          |                                                                                                                                                                   |
| DRAGON BALL FighterZ                              | PC                                       |          No          | Fully P2P                                                                                                                                                         |
| Dying Light                                       | PC                                       |          No          |                                                                                                                                                                   |
| Dying Light 2                                     | PC                                       |          No          |                                                                                                                                                                   |
| ELDEN RING                                        | PS4                                      |          No          |                                                                                                                                                                   |
| ELDEN RING NIGHTREIGN                             | PC, PS4                                  |          No          | On PC, the game is fully P2P.                                                                                                                                     |
| Generation Zero®                                  | PC                                       |          No          |                                                                                                                                                                   |
| Green Hell                                        | PC                                       |          No          | Fully P2P                                                                                                                                                         |
| Grand Theft Auto IV                               | PS3                                      |         Yes          |                                                                                                                                                                   |
| Grand Theft Auto Online                           | PC, Xbox Series X\|S, Xbox One, PS5, PS4 |          No          | See [About Usernames Decryption/Resolving](#-about-usernames-decryptionresolving) for PC username resolution options                                              |
| Minecraft: Bedrock Edition                        | PC, PS4                                  |          No          | Only P2P via friends' worlds — you must invite friends or join their hosted world.                                                                                |
| Minecraft: PlayStation®3 Edition                  | PS3                                      |         Yes          | Fully P2P                                                                                                                                                         |
| Monopoly Madness                                  | PC                                       |          No          | Likely host-only P2P (dead game; couldn't get 2 players in the same lobby).                                                                                       |
| Monster Hunter: World                             | PC                                       |          No          | Fully P2P                                                                                                                                                         |
| Mortal Kombat 11                                  | PC, PS4                                  |          No          |                                                                                                                                                                   |
| Mortal Kombat X                                   | PC                                       |          No          |                                                                                                                                                                   |
| NARUTO SHIPPUDEN: Ultimate Ninja STORM 4          | PS4                                      |          No          |                                                                                                                                                                   |
| NARUTO SHIPPUDEN: Ultimate Ninja STORM Revolution | PC                                       |          No          | Fully P2P                                                                                                                                                         |
| Need for Speed™ Most Wanted                       | PC                                       |          No          |                                                                                                                                                                   |
| NEW MONOPOLY®                                     | PC                                       |          No          | Only the host is connected through P2P                                                                                                                            |
| Payday 2                                          | PC, PS3                                  |         Yes          | On PS3, the game is fully P2P.                                                                                                                                    |
| PlayStation Party Chat                            | PS5, PS4                                 |          No          | Partially P2P; May tunnel via Amazon servers (no IP) if connection is poor or set to Server Only                                                                  |
| Ready or Not                                      | PC                                       |          No          | Only the host is connected through P2P                                                                                                                            |
| Red Dead Online                                   | PC, Xbox Series X\|S, Xbox One, PS5, PS4 |          No          |                                                                                                                                                                   |
| Red Dead Redemption                               | PS3                                      |         Yes          |                                                                                                                                                                   |
| Risk of Rain 2                                    | PC                                       |          No          | Only the host is connected through P2P                                                                                                                            |
| Skate 3                                           | PS3                                      |          No          |                                                                                                                                                                   |
| Sniper Elite 3                                    | PS3                                      |         Yes          | Only the host is connected through P2P, and only when a player creates a match (standard servers are hosted). If you are the host, you can see everyone's IP.     |
| Sons Of The Forest                                | PC                                       |          No          | Fully P2P; Only the host is connected through P2P                                                                                                                 |
| Street Fighter 30th Anniversary Collection        | PC                                       |          No          | Fully P2P                                                                                                                                                         |
| TEKKEN 7                                          | PC                                       |          No          | Fully P2P                                                                                                                                                         |
| The Division 2                                    | PC                                       |          No          |                                                                                                                                                                   |
| theHunter Call of the Wild™                       | PC                                       |          No          |                                                                                                                                                                   |
| theHunter Classic                                 | PC                                       |          No          | Only the host is connected through P2P                                                                                                                            |
| Tom Clancy's Ghost Recon® Breakpoint              | PC                                       |          No          | The P2P connection appears initially, then it goes on the Amazon AWS servers.                                                                                     |
| Tom Clancy's Ghost Recon® Wildlands               | PC                                       |          No          |                                                                                                                                                                   |
| Ultra Street Fighter IV                           | PC                                       |          No          | Fully P2P                                                                                                                                                         |
| UNO                                               | PC                                       |          No          |                                                                                                                                                                   |
| Warframe                                          | PC                                       |          No          |                                                                                                                                                                   |
| Watch Dogs® 2                                     | PC                                       |          No          |                                                                                                                                                                   |

</details>

<details>
<summary><b>💻 View all 12 Officially Tested Applications & Softwares</b> <i>(click to expand)</i></summary>
<br>

| Supported Softwares      | Tested Platforms                   |  Username Resolving  | Additional Note(s)                                                                                                                                                                                           |
| :----------------------: | :--------------------------------: | :------------------: | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Any torrenting softwares | Any                                |          No          |                                                                                                                                                                                                              |
| AnyDesk                  | PC                                 |          No          |                                                                                                                                                                                                              |
| Azar                     | Android, iOS                       |          No          |                                                                                                                                                                                                              |
| Chatspin                 | Android, iOS                       |          No          |                                                                                                                                                                                                              |
| Instagram                | Android, iOS                       |          No          | Sometimes the IP does not leak, or ARP spoofing drops packets. Restarting the app or initiating a call with the camera enabled can help. The IP is typically only exposed at the very beginning of the call. |
| Messenger                | Android, iOS, PC (Microsoft Store) |          No          |                                                                                                                                                                                                              |
| OmeTV                    | Android, iOS                       |          No          |                                                                                                                                                                                                              |
| Parsec                   | PC                                 |          No          |                                                                                                                                                                                                              |
| RustDesk                 | PC                                 |          No          |                                                                                                                                                                                                              |
| Snapchat                 | Android, iOS                       |          No          | Sometimes the IP does not leak, or ARP spoofing drops packets. Restarting the app or initiating a call with the camera enabled can help. The IP is typically only exposed at the very beginning of the call. |
| TeamViewer               | PC                                 |          No          |                                                                                                                                                                                                              |
| WhatsApp                 | PC                                 |          No          | Calls usually route through a server; exact circumstances for P2P connections are unclear.                                                                                                                   |

</details>

> _Note_: Session Sniffer works with **any** Peer-to-Peer (P2P) game or application—the tables above list titles that have been officially tested and confirmed.

---

## 🔐 About Usernames Decryption/Resolving

Session Sniffer supports resolving and displaying player usernames through several methods:

- **PlayStation 3 (PS3)**: Direct packet payload extraction via the built-in **PS3 Name Resolver** setting. Note: This works only on supported PS3 games that broadcast unencrypted PlayStation usernames in packet payloads (see the **Username Resolving** column in the [Officially Tested and Supported P2P Video Games](#-officially-tested-and-supported-p2p-video-games) table for supported titles).
- **GTA Online (PC) Mod Menus**: Authoritative real-time username, host, and session-local relay logging via official Lua plugins (always prioritized first as the source of truth):
  - [Session Sniffer Cherax Lua Plugin](https://github.com/BUZZARDGTA/Session_Sniffer-plugin-Cherax-Lua)
  - [Session Sniffer Lexis Lua Plugin](https://github.com/BUZZARDGTA/Session_Sniffer-plugin-Lexis-Lua)
  - [Session Sniffer Stand Lua Plugin](https://github.com/BUZZARDGTA/Session_Sniffer-plugin-Stand-Lua)
- **GTA Online (PC) Looky System**: Cloud-based username resolving, UserIP database batch refreshes, session Crawler bot requests, and Proxy Join via [**Looky System**](https://looky-gta.cc/) (see [Looky System Configuration](https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#looky-system-configuration)).
- **UserIP JSON Databases**: Custom assignment and automatic PC username feeding across single IPs, IP ranges, and CIDR blocks with per-entry notes and alt-account grouping via the built-in **UserIP Manager** (see [UserIP JSON Databases Configuration](https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#userip-json-databases-configuration)).

> _Note_: On current-gen consoles (PS4/PS5, Xbox One/Series X|S), peer-to-peer network packets no longer expose unencrypted player usernames as this functionality has been patched on those platforms. Packet-based automatic username extraction is therefore only possible on supported legacy console titles.

---

## ⚙️ Requirements

- **Operating System**:
  - **Windows**: [Windows](https://www.microsoft.com/windows) 10 or 11 (x64)
  - **Linux**: [Ubuntu](https://ubuntu.com) 22.04+ / Debian-based (x64)
  - **macOS**: [macOS](https://www.apple.com/macos) 14+ Sonoma or later (Apple Silicon ARM64)
- **Packet Capture Driver / Library**:
  - **Windows**: [Npcap](https://npcap.com/) *(prompted automatically on first launch if missing)*
  - **Linux**: `libpcap` (`sudo apt install libpcap-dev`) and capture capabilities granted to the binary (`sudo setcap cap_net_raw,cap_net_admin,cap_sys_ptrace=eip Session_Sniffer`) or Python interpreter
  - **macOS**: Built-in `libpcap` with capture permissions granted to `/dev/bpf*` (e.g. `sudo chmod 666 /dev/bpf*` or Wireshark's `ChmodBPF` package)
- **Geolocation Databases**: [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) *(downloaded and updated automatically on startup)*

---

## 📖 Documentation & Wiki

Explore the [**Project Wiki**](https://github.com/BUZZARDGTA/Session-Sniffer/wiki) for complete guides and reference documentation:

- [**Installation Guide**](https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Installation) — Quick setup for Windows, Linux, and macOS
- [**Configuration Guide**](https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide) — Complete reference for every setting, console/mobile scanning, Looky System, and UserIP JSON databases
- [**Tips and Tricks**](https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Tips-and-Tricks) — Best practices, hidden shortcuts, and workflow optimizations
- [**Troubleshooting**](https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Troubleshooting) — Solutions for common setup and capture issues
- [**Running from Source**](https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Running-from-Source) & [**Building from Source**](https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Building-from-Source) — Developer environment and PyInstaller build instructions

---

## 🌟 Connect with Us!

We'd love to have **you** in our community!  
Join us on Discord to chat, get support, share themes or rules, and stay updated on the latest releases!

[![Join Our Discord](https://img.shields.io/badge/Join%20Our%20Discord-%235865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/hMZ7MsPX7G)

---

## 💖 Support My Work

Session Sniffer is 100% free and open source. If you find it useful, consider donating to support continued development!

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/buzzardgta)

---

## 🛠️ Contact Support

Need help? You can reach out via:
- [GitHub Issues](https://github.com/BUZZARDGTA/Session-Sniffer/issues)
- [GitHub Discussions](https://github.com/BUZZARDGTA/Session-Sniffer/discussions)
- [Discord Server](https://discord.gg/hMZ7MsPX7G)

Or privately:
- **Discord**: waitingforharukatoaddme
- **Telegram**: [@waitingforharukatoaddme](https://t.me/waitingforharukatoaddme)
