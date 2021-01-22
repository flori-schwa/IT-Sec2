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

### Fehlerbehebung

Sollte es beim ausführen von make all term  folgenden Fehler geben:

```
/usr/include/stdio.h:27:10: fatal error: bits/libc-header-start.h: No such file or directory
27 | #include <bits/libc-header-start.h>
   |          ^~~~~~~~~~~~~~~~~~~~~~~~~~
```

Dann versucht der Compiler die System "stdio.h" Datei aus "/usr/include" zu verwenden.
Wir wollen jedoch die "stdio.h" Datei von RIOT verwenden.
In meinem Fall konnte dieser Fehler durch installieren des `gcc-multilib` Packets behoben werden:
 - `sudo apt-get install gcc-multilib`

<-- [Teil 1: Installation](https://github.com/flori-schwa/IT-Sec2/blob/master/Tutorials/01_Installation.md) -- [Teil 3: Shell und Commands](https://github.com/flori-schwa/IT-Sec2/blob/master/Tutorials/03_ShellCommands.md) -->