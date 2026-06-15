# pq-sign — post-quantum detached file signing
#
# Requires: liboqs (ML-DSA / SLH-DSA) and OpenSSL >= 3.2 (Argon2id KDF).
# Both are located via pkg-config. If liboqs is installed in a custom
# prefix, point pkg-config at it, e.g.:
#
#   make PKG_CONFIG_PATH=$HOME/work/.local/lib/pkgconfig
#
# and at run time set LD_LIBRARY_PATH to the same prefix's lib dir.

CC      ?= cc
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin

# Export so the pkg-config invocations below see a PKG_CONFIG_PATH passed
# on the make command line (e.g. for a local liboqs prefix).
export PKG_CONFIG_PATH

PKG_CONFIG ?= pkg-config
DEPS        = liboqs openssl libargon2

CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-qual \
           -Wstrict-prototypes -D_FORTIFY_SOURCE=2 -fstack-protector-strong
CFLAGS  += -Iinclude $(shell $(PKG_CONFIG) --cflags $(DEPS))
LDFLAGS += $(shell $(PKG_CONFIG) --libs $(DEPS))

SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)
BIN = pq-sign

.PHONY: all clean install uninstall check

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

src/%.o: src/%.c include/pqsign.h
	$(CC) $(CFLAGS) -c -o $@ $<

check: all
	./tests/run.sh

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)

clean:
	rm -f $(OBJ) $(BIN)
