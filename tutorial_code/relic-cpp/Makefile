# name of your application
APPLICATION = relic-cpp

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

USEMODULE += od
USEMODULE += od_string
USEMODULE += shell
USEMODULE += shell_commands

# Features required
FEATURES_REQUIRED += cpp # basic C++ support
FEATURES_REQUIRED += libstdcpp # libstdc++ support (for #include <cstdio>)

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

CXXEXFLAGS +=

include $(RIOTBASE)/Makefile.include
