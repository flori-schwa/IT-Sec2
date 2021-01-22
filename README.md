Zu RIOT OS
==========

RIOT ist ein Echtzeitbetriebssystem zur Anwendung im Bereich IoT. Kryptographie ist in der IoT wichtig, da sensitive Informationen (wie z.B. ob jemand zuhause) unbedingt nur von berechtigten Personen einsehbar sein. In diesem Guide (Stand: Dezember 2020) wird eine kurze Einführung zu RIOT und anschließend zur Anwendung von Kryptographischen Verfahren gegeben.

Installation von RIOT
=====================

RIOT kann entweder direkt unter Linux installiert werden (VM oder physical machine) oder unter Windows mit Docker.

Linux Installation
------------------

### Voraussetzungen

-   Git: Über Package-Manager Installieren\
    (Bei Debian/Ubuntu: sudo apt-get install git)

-   Build Essentials: Tools wie gcc und make\
    (Bei Debian/Ubuntu: sudo apt-get install build-essential)

-   Je nach Linux Distribution weitere Abhängigkeiten (siehe: <https://github.com/RIOT-OS/RIOT/wiki/Family:-native#dependencies>)

-   Zum "On-Chip debuggen" falls RIOT auf entsprechender Hardware ausgeführt wird noch OpenOCD (siehe: <https://github.com/RIOT-OS/RIOT/wiki/OpenOCD>)

-   GNU ARM Embedded Toolchain:

-   sudo apt-get install gcc-arm-none-eabi

### RIOT Installation

-   Riot herunterladen: git clone <https://github.com/RIOT-OS/RIOT.git>

-   Version auschecken: git checkout <version>\
    (Stand Dezember 2020: git checkout 2020.10)

RIOT-Program Aufbau
===================

Einfachste Makefile
-------------------

```
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

Hello World Program
-------------------

```
#include <stdio.h>

int main(void)
{
    puts("Hello World!");
    return 0;
}
```

Das Programm lässt sich mit make all term starten, als Ausgabe erhalten wir

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
  	   |      	   ^~~~~~~~~~~~~~~~~~~~~~~~~~
```

Dann versucht der Compiler die System "stdio.h" Datei aus "/usr/include" zu verwenden. Wir wollen jedoch die "stdio.h" Datei von RIOT verwenden. In meinem Fall konnte dieser Fehler durch installieren des "gcc-multilib" Packets  behoben werden:

-   sudo apt-get install gcc-multilib

Tutorials
=========

RIOT Shell und Command Handler
------------------------------

Um in der RIOT Shell Befehle auszuführen müssen im Projekt die Module "shell" und "shell_commands" hinzugefügt werden. Dazu wird die Makefile angepasst:


```
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

### Die Command Struktur

In der "shell.h" Datei wird die shell_command_t Struktur definiert, diese wird benötigt um Commands in der RIOT shell zu registrieren:

```
/**
 * @brief       	A single command in the list of the supported commands.
 * @details     	The list of commands is NULL terminated,
 *              	i.e. the last element must be ``{ NULL, NULL, NULL }``.
 */
typedef struct shell_command_t {
	const char *name; /**< Name of the function */
	const char *desc; /**< Description to print in the "help" command. */
	shell_command_handler_t handler; /**< The callback function. */
} shell_command_t;
```

Ein shell_command_handler_t ist dabei ein Function-Pointer zu einer Funktion, die ein int zurückgibt und Zwei Argumente annimmt:

-   int argc Die Anzahl der Argumente

-   char** argv Die Liste der Argumente, argv[0] ist dabei der Name des aufgerufenen Befehls, argv[argc] ist NULL

Ein Shell Callback Handler gibt 0 zurück bei erfolgreicher bearbeitung des Befehls

### Beispiel eines Shell Callback Handler

```
int test_command_handler(int argc, char** argv) {
	printf("Test command: ");

	for (int i = 0; i < argc; i++) {
    	    printf("%s ", argv[i]);
	}

	printf("\n");
	return 0;
}
```

Der obige command handler schreibt die Angegeben Argumente auf die Konsole, mit der "Test Command: " Präfix.

### Registrierung von Befehlen und Starten der Shell

Um den obigen Befehl zu registrieren allozieren wir zunächst ein Array, welches 2 Commands enthält:

-   Unseren Test command

-   Einen command, dessen member alle auf NULL gesetzt sind, um die Liste zu terminieren.

```
shell_command_t commands[] = {
	{ "test", "RIOT Shell test command", test_command_handler },
	{ NULL, NULL, NULL }
};
```

Nachdem wir dieses Array alloziert haben, müssen wir nur noch den Line Buffer allozieren und die Shell starten:

```
char line_buf[SHELL_DEFAULT_BUFSIZE];
shell_run(commands, line_buf, SHELL_DEFAULT_BUFSIZE);
```

Hier die vollständige main.c Datei:

```
#include "shell.h"
#include "shell_commands.h"

#include <stdio.h>

int test_command_handler(int argc, char** argv) {
	printf("Test command: ");

	for (int i = 0; i < argc; i++) {
    	    printf("%s ", argv[i]);
	}

	printf("\n");
	return 0;
}

int main(void)
{
	shell_command_t commands[] = {
    	    { "test", "RIOT Shell test command", test_command_handler },
    	    { NULL, NULL, NULL }
	};

	char line_buf[SHELL_DEFAULT_BUFSIZE];
	shell_run(commands, line_buf, SHELL_DEFAULT_BUFSIZE);

	return 0;
}
```

Das Programm lässt sich über make all term starten, durch Eingabe von help kann man nun alle vorhandenen Befehle auflisten:

```
Command          	Description
---------------------------------------
test             	RIOT Shell test command
reboot           	Reboot the node
version          	Prints current RIOT_VERSION
pm               	interact with layered PM subsystem
```

Nach der Eingabe des Befehls test test1 test2 test3 test4 sollte nun folgende Ausgabe zu sehen sein:

```
Test command: test test1 test2 test3 test4
```

Kryptographie
=============

In den folgenden Tutorials wollen wir nun RIOT verwenden um Daten zu verschlüsseln, zuerst mit AES (im ECB sowie im CBC modus) und danach mithilfe der Relic Library.

AES-ECB
-------

### Anpassung der Makefile

In dem hier besprochenen Programm werden wir die Module shell,  shell_commands,  crypto_aes  sowie od  verwenden

Fertige Makefile

```
# Name der Anwendung
APPLICATION = aes_ecb_example

# Standardboard
BOARD ?= native

USEMODULE += shell   		 # RIOT Shell Modul
USEMODULE += shell_commands	 # RIOT Shell Commands
USEMODULE += crypto_aes   	 # Verschlüsselung mithilfe von AES
USEMODULE += od			 # Object Dump
USEMODULE += od_string   	 # Object Dump String representation

# Pfad zur RIOT installation
RIOTBASE ?= ${HOME}/RIOT

include $(RIOTBASE)/Makefile.include
```

### Die Header-Dateien "crpyto/ciphers.h" sowie "crypto/aes.h"

In dem Programm werden wir die Header Dateien "crypto/ciphers.h" sowie "crypto/aes.h" verwenden.

Die ciphers.h Headerdatei beinhält essentielle Strukturen und Funktionen um mit RIOT Daten zu verschlüsseln. Die wichtigste Struktur dabei ist die cipher_t Struktur:

```
/**
 * @brief basic struct for using block ciphers
 *    	contains the cipher interface and the context
 */
typedef struct {
      /**< BlockCipher-Interface for the Cipher-Algorithms */
	const cipher_interface_t *interface;
      /**< The encryption context (buffer) for the algorithm */
	cipher_context_t context;
} cipher_t;
```

Wir werden die Member dieser Struktur nicht selber verwenden, aber "interface" ist ein pointer auf eine cipher_interface_t Struktur, welche Informationen über die Blockgröße, Maximale Schlüsselgröße und Function Pointer zu den Init/Encrypt sowie Decrypt Funktionen des Algorithmus enthält.

Die cipher_context_t ist ein buffer, der von den Algorithmen intern verwendet wird.

Wir werden aus der ciphers.h Headerdatei außerdem noch die Funktionen cipher_init,  cipher_encrypt  sowie cipher_decrypt verwenden:

```
/**
 * @brief Initialize new cipher state
 *
 * @param cipher     cipher struct to init (already allocated memory)
 * @param cipher_id  cipher algorithm id
 * @param key    	   encryption key to use
 * @param key_size   length of the encryption key
 *
 * @return  CIPHER_INIT_SUCCESS if the initialization was successful.
 * @return  CIPHER_ERR_BAD_CONTEXT_SIZE if CIPHER_MAX_CONTEXT_SIZE has  
 *          not been defined (which means that the cipher has not been 
 *          included in the build)
 * @return  The command may return CIPHER_ERR_INVALID_KEY_SIZE if the
 *      	key size is not valid.
 */
int cipher_init(cipher_t *cipher, cipher_id_t cipher_id,
               const uint8_t *key, uint8_t key_size);
/**
 * @brief Encrypt data of BLOCK_SIZE length
 * *
 *
 * @param cipher 	Already initialized cipher struct
 * @param input  	pointer to input data to encrypt
 * @param output 	pointer to allocated memory for encrypted data.
 *                It has to be of size BLOCK_SIZE
 *
 * @return       	The result of the encrypt operation of the underlying
 *               	cipher, which is always 1 in case of success
 * @return       	A negative value for an error
 */
int cipher_encrypt(const cipher_t *cipher, const uint8_t *input,
               	uint8_t *output);


/**
 * @brief Decrypt data of BLOCK_SIZE length
 * *
 *
 * @param cipher 	Already initialized cipher struct
 * @param input  	pointer to input data (of size BLOCKS_SIZE) to decrypt
 * @param output 	pointer to allocated memory for decrypted data.
 *                It has to be of size BLOCK_SIZE
 *
 * @return       	The result of the decrypt operation of the underlying
 *               	cipher, which is always 1 in case of success
 * @return       	A negative value for an error
 */
int cipher_decrypt(const cipher_t *cipher, const uint8_t *input,
               	uint8_t *output);
```

### cipher_init

Die cipher_init Funktion nimmt einen Pointer zu einer cipher_t Struktur, die Struktur darf uninitialisierter Speicher sein, die Funktion initialisiert diesen Speicher dann mit dem richtigen Kontext und Buffer. Das zweite Argument ist ein Pointer zu einer cipher_interface_t Struktur. Außerdem nimmt die Funktion den Schlüssel zur verschlüsselung an, sowie dessen größe.

Die Funktion gibt bei erfolgreicher Initialisiation CIPHER_INIT_SUCCESS zurück, ansonsten einer der Fehlercodes CIPHER_ERR_BAD_CONTEXT_SIZE oder CIPHER_ERR_INVALID_KEY_SIZE

Beispiel:

### cipher_encrypt

Die cipher_encrypt Funktion verschlüsselt einen Datenblock der im cipher_interface_t gespeicherten Block size und nimmt als Argument einen Pointer zu einer initialisierten cipher_t Struktur, einen Pointer zu dem Klartextbuffer sowie einen Pointer zum Ciphertextbuffer. Die Klartext und Ciphertextbuffer sollten einen Block des verwendeten Algorithmus enthalten (Bei AES also mindestens 16 Bytes).

Die Funktion gibt bei erfolgreichem Verschlüsseln 1 zurück

### cipher_decrypt

Die cipher_decrypt Funktion entschlüsselt einen Datenblock der für den Algorithmus geltenden Block size und nimmt als Argument eine Pointer zu einer initialisierten cipher_t Struktur einen Pointer zu dem Ciphertext, der entschlüsselt werden soll sowie einen Pointer zu einem Buffer, in dem der entschlüsselte Klartext geschrieben werden soll.

Die Funktion gibt bei erfolgreichem Entschlüsseln 1 zurück

### Programm zur Verschlüsselung einer Kurzen (bis zu 15 Zeichen) Nachricht

```
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "crypto/ciphers.h"
#include "crypto/aes.h"
#include "od.h"

int main(void)
{
	// Schlüssel für den AES Algorithmus
	uint8_t key[AES_KEY_SIZE] = {
    	0x64, 0x52, 0x67, 0x55,
    	0x6B, 0x58, 0x70, 0x32,
    	0x73, 0x35, 0x75, 0x38,
    	0x78, 0x2F, 0x41, 0x3F};

	cipher_t cipher;
	int err;

	// Initialisierung der cipher_t Struktur
	if ((err = cipher_init(&cipher, CIPHER_AES_128, key, AES_KEY_SIZE)) != CIPHER_INIT_SUCCESS)
	{
    	     printf("Failed to initialize cipher_t: %d\n", err);
    	     exit(err);
	}

	uint8_t input[AES_BLOCK_SIZE] = {0};  // Initialisiere den Eingabebuffer mit Nullen
	uint8_t output[AES_BLOCK_SIZE] = {0}; // Initialisiere den Ausgabebuffer mit Nullen

	sprintf((char *)input, "Testnachricht"); // Schreibe die Nachricht in den Eingabebuffer

	// Verschlüsseln der Eingabe
	if ((err = cipher_encrypt(&cipher, input, output)) != 1)
	{
    	     printf("Failed to encrypt data: %d\n", err);
    	     exit(err);
	}


       // Ausgabe des Buffers in Hexadecimal sowie der Druckbaren Zeichen in ASCII
	printf("Klartext: \t");
	od_hex_dump_ext(input, AES_BLOCK_SIZE, 0, 0);
	printf("Ciphertext: \t");
	od_hex_dump_ext(output, AES_BLOCK_SIZE, 0, 0);

	// Entschlüsseln der Verschlüsselten Eingabe,
       // durch das vertauschen von input und output,
       // wird der Verschlüsselte Text in den Inputbuffer wieder geschrieben,
       // welcher sich dadurch nicht ändern sollte.
	if ((err = cipher_decrypt(&cipher, output, input)) != 1)
	{
    	     printf("Failed to decrypt data: %d\n", err);
    	     exit(err);
	}

	printf("Entschlüsselt: \t");
	od_hex_dump_ext(input, AES_BLOCK_SIZE, 0, 0);

	exit(0);
}
```

Als Ausgabe erhalten wir:

```
Klartext:      54 65 73 74 6E 61 63 68 72 69 63 68 74 00 00 00  
Testnachricht...
Ciphertext:    BC 4E DC 18 20 A9 EB 57 59 0F 76 C0 DC 9D 5A B9
.N.. ..WY.v...Z.
Entschlüsselt: 54 65 73 74 6E 61 63 68 72 69 63 68 74 00 00 00  
Testnachricht...
```

Relic
-----