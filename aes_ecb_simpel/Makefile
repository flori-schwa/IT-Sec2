# name of your application
APPLICATION = aes_ecb_simpel

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= ${CURDIR}/../.base

USEMODULE += shell			# RIOT Shell Modul
USEMODULE += shell_commands # RIOT Shell Commands
USEMODULE += crypto_aes		# Verschlüsselung mithilfe von AES
USEMODULE += od				# Object Dump

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
