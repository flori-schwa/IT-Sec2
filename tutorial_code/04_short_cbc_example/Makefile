# Name der Anwendung
APPLICATION = aes_cbc_example

# Standardboard
BOARD ?= native

USEMODULE += shell_commands  # RIOT Shell Commands
USEMODULE += shell           # RIOT Shell Modul
USEMODULE += crypto_aes_128      # Verschlüsselung mithilfe von AES
USEMODULE += od              # Object Dump
USEMODULE += od_string       # Object Dump String representation
USEMODULE += cipher_modes # Um AES-CBC zu verwenden
USEMODULE += random       # Um einen zufälligen IV zu generieren  

# Pfad zur RIOT installation
RIOTBASE ?= ${HOME}/RIOT

include $(RIOTBASE)/Makefile.include