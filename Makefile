# Makefile — pure C99, no libs; keygen emits headers
CC      ?= clang
CSTD    ?= c99
WARN    := -Wall -Wextra -Wpedantic -Wshadow -Wcast-qual \
           -Wmissing-prototypes -Wstrict-prototypes -Wconversion \
           -Wsign-conversion -Wpointer-arith -Wno-unused-parameter -Werror
DEFS    := -D_POSIX_C_SOURCE=200809L
OPT     := -O2
DBG     :=
SAN     :=
ifeq ($(debug),1)
  OPT := -O0
  DBG := -g3 -fno-omit-frame-pointer
endif
ifeq ($(asan),1)
  SAN := -fsanitize=address,undefined
endif

CFLAGS  := -std=$(CSTD) $(OPT) $(WARN) $(DBG) $(DEFS) $(SAN) -Iinclude -MMD -MP
LDFLAGS := $(SAN)

BIN := bin
BLD := build

SRCS_COMMON := src/net.c src/crypto.c src/sha256.c src/aes.c src/bn.c
CLIENT_SRCS := src/main_client.c src/ap.c src/cp1.c src/cp2.c $(SRCS_COMMON)
SERVER_SRCS := src/main_server.c src/ap.c $(SRCS_COMMON)

COMMON_OBJS := $(patsubst %.c,$(BLD)/%.o,$(SRCS_COMMON))
CLIENT_OBJS := $(patsubst %.c,$(BLD)/%.o,$(CLIENT_SRCS))
SERVER_OBJS := $(patsubst %.c,$(BLD)/%.o,$(SERVER_SRCS))

TEST_SRCS := $(wildcard tests/t_*.c)
TEST_OBJS := $(patsubst %.c,$(BLD)/%.o,$(TEST_SRCS))
TEST_BIN  := $(BIN)/t_all

# Quiet unless V=1
Q :=
ifeq ($(V),)
  Q := @
endif

.PHONY: all help client server clean distclean test headers keygen run-server run-client \
        strip size format format-check compdb

all: $(BIN)/client $(BIN)/server

help:
	@echo "Targets: all client server test keygen headers run-server run-client"
	@echo "         format format-check strip size clean distclean compdb"
	@echo "Toggles: debug=1  asan=1  V=1"
	@echo "Run:     make run-server PORT=9000 | make run-client HOST=127.0.0.1 PORT=9000 FILE=README"

$(BIN) $(BLD) keys:
	$(Q)mkdir -p $@

# Keygen emits keys/server_keys.h using your BN/RSA code
keygen: $(BIN)/keygen | keys
	@echo "  GEN keys/server_keys.h"
	$(Q)$(BIN)/keygen > keys/server_keys.h
	@echo "  -> wrote keys/server_keys.h"

headers: | keys
	@touch keys/server_keys.h

$(BIN)/keygen: src/keygen.c src/bn.c include/bn.h include/crypto.h | $(BIN) $(BLD)
	@echo "  CC  $@"
	$(Q)$(CC) $(CFLAGS) -o $@ src/keygen.c src/bn.c

$(BLD)/%.o: %.c | $(BLD)
	@echo "  CC  $<"
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

$(BIN)/client: $(CLIENT_OBJS) | $(BIN) keys/ca_pub.h keys/server_keys.h
	@echo "  LD  $@"
	$(Q)$(CC) $(CLIENT_OBJS) -o $@ $(LDFLAGS)

$(BIN)/server: $(SERVER_OBJS) | $(BIN) keys/server_keys.h
	@echo "  LD  $@"
	$(Q)$(CC) $(SERVER_OBJS) -o $@ $(LDFLAGS)

# ---- tests (link only common objs, not client/server mains/glue) ----
test: $(TEST_BIN)
	@if [ -x "$(TEST_BIN)" ]; then echo "  RUN $(TEST_BIN)"; $(TEST_BIN); \
	else echo "no tests (add tests/t_*.c)"; fi

$(TEST_BIN): $(TEST_OBJS) $(COMMON_OBJS) | $(BIN)
ifneq ($(strip $(TEST_SRCS)),)
	@echo "  LD  $@"
	$(Q)$(CC) $(TEST_OBJS) $(COMMON_OBJS) -o $@ $(LDFLAGS)
else
	$(Q)printf '#!/bin/sh\necho \"no tests\"\n' > $@ && chmod +x $@
endif

# ---- convenience ----
HOST ?= 127.0.0.1
PORT ?= 9000
FILE ?= README
run-server: $(BIN)/server
	@echo "RUN server :$(PORT)"
	$(Q)$(BIN)/server $(PORT)
run-client: $(BIN)/client
	@echo "RUN client $(HOST):$(PORT) $(FILE)"
	$(Q)$(BIN)/client $(HOST) $(PORT) $(FILE)

strip: $(BIN)/client $(BIN)/server
	@echo "  STRIP"
	$(Q)strip $^

size: $(BIN)/client $(BIN)/server
	@size $^

format:
	@command -v clang-format >/dev/null || { echo "clang-format not found"; exit 1; }
	@echo "  FMT (src include tests keys misc)"
	$(Q)find src include tests keys misc -type f \( -name '*.c' -o -name '*.h' \) \
		! -path 'build/*' ! -path 'bin/*' -print0 | xargs -0 clang-format -i

format-check:
	@command -v clang-format >/dev/null || { echo "clang-format not found"; exit 1; }
	@echo "  FMT-CHECK"
	$(Q)find src include tests keys misc -type f \( -name '*.c' -o -name '*.h' \) \
	  -print0 | xargs -0 clang-format -n --Werror

# compile_commands.json for clangd (best-effort)
compdb:
	@echo '[' > compile_commands.json
	@for f in $(CLIENT_SRCS) $(SERVER_SRCS) $(TEST_SRCS); do \
	  printf '{ "directory": "%s", "command": "%s -c %s %s -Iinclude -o /dev/null", "file": "%s" },\n' \
	    "$$PWD" "$(CC) $(CFLAGS)" "$$f" "" "$$f"; \
	done >> compile_commands.json
	@sed -i '$$ s/},/}]/' compile_commands.json 2>/dev/null || true
	@echo "  GEN compile_commands.json"

clean:
	@echo "CLEAN"
	$(Q)rm -rf $(BLD)
distclean: clean
	$(Q)rm -rf $(BIN) compile_commands.json

-include $(CLIENT_OBJS:.o=.d) $(SERVER_OBJS:.o=.d) $(TEST_OBJS:.o=.d)

