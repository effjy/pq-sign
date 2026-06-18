# pq-sign — post-quantum detached file signing
#
# Requires: liboqs (ML-DSA / SLH-DSA), OpenSSL >= 3.0 (SHA-256/AES-GCM/RNG),
# and libargon2 (the Argon2id KDF). All three are located via pkg-config. If
# liboqs is installed in a custom prefix, point pkg-config at it, e.g.:
#
#   make PKG_CONFIG_PATH=$HOME/work/.local/lib/pkgconfig
#
# and at run time set LD_LIBRARY_PATH to the same prefix's lib dir.
#
# Targets:
#   make           build the pq-sign CLI (and the GTK3 GUI if GTK3 is found)
#   make gui       build just the pq-sign-gui GTK3 front-end
#   make install   install CLI + GUI + icon + .desktop (use sudo for /usr/local)
#   make check     build, run the KAT suite and the end-to-end smoke tests
#   make asan      rebuild + check under AddressSanitizer / UBSan
#   make fuzz      build the libFuzzer parser targets (needs clang)

CC      ?= cc
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share
APPDIR  ?= $(DATADIR)/applications
ICONDIR ?= $(DATADIR)/icons/hicolor/scalable/apps

# Export so the pkg-config invocations below see a PKG_CONFIG_PATH passed
# on the make command line (e.g. for a local liboqs prefix).
export PKG_CONFIG_PATH

PKG_CONFIG ?= pkg-config
DEPS        = liboqs openssl libargon2
PKG_CFLAGS  = $(shell $(PKG_CONFIG) --cflags $(DEPS))
PKG_LIBS    = $(shell $(PKG_CONFIG) --libs $(DEPS))

# EXTRA_CFLAGS / EXTRA_LDFLAGS are injection points (used by the asan target).
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-qual \
           -Wstrict-prototypes -D_FORTIFY_SOURCE=2 -fstack-protector-strong
CFLAGS  += -Iinclude $(PKG_CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS)
LDLIBS  += $(PKG_LIBS)

# Library translation units (everything the CLI is built from except main).
LIB_SRC = src/util.c src/sigfile.c src/keyfile.c
LIB_OBJ = $(LIB_SRC:.c=.o)
OBJ     = $(LIB_OBJ) src/main.o
BIN     = pq-sign

HDRS    = include/pqsign.h include/keyfile_internal.h

KAT     = tests/kat/kat

# Optional GTK3 front-end. It is built and installed only when GTK3 is found
# via pkg-config, so the core CLI still builds on a headless machine.
HAVE_GTK   := $(shell $(PKG_CONFIG) --exists gtk+-3.0 && echo yes)
GUI_BIN     = pq-sign-gui
GUI_CFLAGS  = $(shell $(PKG_CONFIG) --cflags gtk+-3.0)
GUI_LIBS    = $(shell $(PKG_CONFIG) --libs gtk+-3.0)

ifeq ($(HAVE_GTK),yes)
ALL_TARGETS = $(BIN) $(GUI_BIN)
else
ALL_TARGETS = $(BIN)
endif

.PHONY: all clean install uninstall check kat asan fuzz gui

all: $(ALL_TARGETS)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS) $(LDLIBS)

# The GUI reuses the library objects and links GTK3 on top of the core deps.
gui: $(GUI_BIN)

$(GUI_BIN): src/gui.o $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ src/gui.o $(LIB_OBJ) $(LDFLAGS) $(LDLIBS) $(GUI_LIBS)

# Explicit rule (overrides the generic one) so gui.o gets the GTK cflags.
src/gui.o: src/gui.c $(HDRS)
	$(CC) $(CFLAGS) $(GUI_CFLAGS) -c -o $@ src/gui.c

src/%.o: src/%.c $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

# --- tests ----------------------------------------------------------------

$(KAT): tests/kat/kat.c $(LIB_OBJ) $(HDRS)
	$(CC) $(CFLAGS) -o $@ tests/kat/kat.c $(LIB_OBJ) $(LDFLAGS) $(LDLIBS)

kat: $(KAT)
	$(KAT)

check: all kat
	./tests/run.sh

# Rebuild everything with the sanitizers and run the full test suite.
asan:
	$(MAKE) clean
	$(MAKE) EXTRA_CFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer" \
	        EXTRA_LDFLAGS="-fsanitize=address,undefined" check

# libFuzzer targets for the two untrusted-input parsers. Sources are compiled
# fresh (not reused .o) so they carry the fuzzer + sanitizer instrumentation.
FUZZ_CC      ?= clang
FUZZ_CFLAGS  ?= -g -O1 -std=c11 -Iinclude $(PKG_CFLAGS) \
                -fsanitize=fuzzer,address,undefined
FUZZ_TARGETS  = fuzz_sigfile fuzz_keyarmor

fuzz: $(FUZZ_TARGETS)

fuzz_sigfile: tests/fuzz/fuzz_sigfile.c $(LIB_SRC) $(HDRS)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ tests/fuzz/fuzz_sigfile.c $(LIB_SRC) $(PKG_LIBS)

fuzz_keyarmor: tests/fuzz/fuzz_keyarmor.c $(LIB_SRC) $(HDRS)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ tests/fuzz/fuzz_keyarmor.c $(LIB_SRC) $(PKG_LIBS)

# --- install / clean ------------------------------------------------------

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
ifeq ($(HAVE_GTK),yes)
	install -m 0755 $(GUI_BIN) $(DESTDIR)$(BINDIR)/$(GUI_BIN)
	install -d $(DESTDIR)$(ICONDIR)
	install -m 0644 data/pq-sign.svg $(DESTDIR)$(ICONDIR)/pq-sign.svg
	install -d $(DESTDIR)$(APPDIR)
	install -m 0644 data/pq-sign.desktop $(DESTDIR)$(APPDIR)/pq-sign.desktop
	-gtk-update-icon-cache -f -t $(DESTDIR)$(DATADIR)/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true
endif

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)
	rm -f $(DESTDIR)$(BINDIR)/$(GUI_BIN)
	rm -f $(DESTDIR)$(ICONDIR)/pq-sign.svg
	rm -f $(DESTDIR)$(APPDIR)/pq-sign.desktop
	-gtk-update-icon-cache -f -t $(DESTDIR)$(DATADIR)/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true

clean:
	rm -f $(OBJ) src/gui.o $(GUI_BIN) $(BIN) $(KAT) $(FUZZ_TARGETS)
