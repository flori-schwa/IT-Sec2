# name of your application
APPLICATION = benchmark

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= ${CURDIR}/../.base

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

export RELIC_CONFIG_FLAGS=-DARCH=NONE -DALLOC=DYNAMIC -DQUIET=off -DWORD=32 -DFP_PRIME=255 -DWITH="BN;MD;DV;FP;EP;CP;BC;EC" -DSEED=RIOTRND

USEPKG += relic

USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += crypto_aes_128
USEMODULE += cipher_modes
USEMODULE += random
USEMODULE += xtimer             # zeitbezogene Funktionen wie Timer
USEMODULE += printf_float       # Float Konsolenausgaben

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
