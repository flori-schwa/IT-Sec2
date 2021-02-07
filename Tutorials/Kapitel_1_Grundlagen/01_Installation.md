# Installation von RIOT

RIOT kann entweder direkt unter Linux installiert werden (VM oder physical machine) oder unter Windows mit Docker.
Außerdem kann RIOT unter WSL (Windows Subsystem for Linux) installiert werden.

## Linux Installation

### Voraussetzungen

 - Git: Über Package-Manager Installieren (Bei Debian/Ubuntu: `sudo apt-get install git`)
 - Build Essentials: Tools wie gcc und make (Bei Debian/Ubuntu: `sudo apt-get install build-essential`)
 - Je nach Linux Distribution weitere Abhängigkeiten (siehe: <https://github.com/RIOT-OS/RIOT/wiki/Family:-native#dependencies>)
 - Zum "On-Chip debuggen" falls RIOT auf entsprechender Hardware ausgeführt wird noch OpenOCD (siehe: <https://github.com/RIOT-OS/RIOT/wiki/OpenOCD>)
 - GNU ARM Embedded Toolchain:
 - `sudo apt-get install gcc-arm-none-eabi`

Auf Ubuntu noch folgende Packages Installieren:
 - `sudo apt-get install gcc-multilib g++-multilib`

### RIOT unter Linux installieren

 - Riot herunterladen: `git clone https://github.com/RIOT-OS/RIOT.git`
 - Version auschecken: git checkout <version> (Stand Dezember 2020: `git checkout 2020.10`)

[Zurück zum Index](../../README.md)

[Weiter zu Teil 2: Programmaufbau](02_Programaufbau.md)