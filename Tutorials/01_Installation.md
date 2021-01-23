# Installation von RIOT

RIOT kann entweder direkt unter Linux installiert werden (VM oder physical machine) oder unter Windows mit Docker.

## Linux Installation

### Voraussetzungen

 - Git: Über Package-Manager Installieren (Bei Debian/Ubuntu: `sudo apt-get install git`)
 - Build Essentials: Tools wie gcc und make (Bei Debian/Ubuntu: `sudo apt-get install build-essential`)
 - Je nach Linux Distribution weitere Abhängigkeiten (siehe: <https://github.com/RIOT-OS/RIOT/wiki/Family:-native#dependencies>)
 - Zum "On-Chip debuggen" falls RIOT auf entsprechender Hardware ausgeführt wird noch OpenOCD (siehe: <https://github.com/RIOT-OS/RIOT/wiki/OpenOCD>)
 - GNU ARM Embedded Toolchain:
 - `sudo apt-get install gcc-arm-none-eabi`

### RIOT unter Linux installieren

 - Riot herunterladen: `git clone https://github.com/RIOT-OS/RIOT.git`
 - Version auschecken: git checkout <version> (Stand Dezember 2020: `git checkout 2020.10`)

[Teil 2: Programaufbau](02_Programaufbau.md) -->