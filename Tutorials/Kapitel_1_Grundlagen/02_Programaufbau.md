# RIOT-Programaufbau

Ein RIOT Programm benötigt 2 Komponenten: Eine Makefile und ein Programm.

## Makefile

```makefile
# Name der Anwendung
APPLICATION = commands-tutorial

# Wenn beim Aufruf von "make", kein Board angegeben wurde, verwende
# "native"
BOARD ?= native

# Hinzufügen der benötigten Module shell und shell_commands
USEMODULE += shell
USEMODULE += shell_commands

# Pfad zur RIOT installation, in diesem Fall befindet sich RIOT im
# User Home verzeichnis
RIOTBASE ?= ${HOME}/RIOT

include $(RIOTBASE)/Makefile.include
```

Im Laufe des Tutorials werden wir die Makefile erweitern, aber dies ist alles was man für ein Minimales RIOT-Programm benötigt.

## Hello World Program

```c
#include <stdio.h>

int main(void)
{
    puts("Hello World!");
    return 0;
}
```

Das Programm lässt sich mit `make all term` starten, als Ausgabe erhalten wir

```
RIOT native interrupts/signals initialized.
LED_RED_OFF
LED_GREEN_ON
RIOT native board initialized.
RIOT native hardware initialization complete.

main(): This is RIOT! (Version: 2020.10)
Hello World!
```

<-- [Teil 1: Installation](01_Installation.md) -- [Teil 3: Shell und Commands](03_ShellCommands.md) -->