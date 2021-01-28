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

USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += crypto_aes

# USEMODULE += crypto_aes_precalculated
# USEMODULE += crypto_aes_unroll

USEMODULE += random
USEMODULE += xtimer

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
