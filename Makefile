CC ?= cc
CPPFLAGS += -Iinclude
CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra -Wpedantic -Wshadow
CRYPTO_LIBS := $(shell pkg-config --libs openssl 2>/dev/null || echo -lcrypto)
NFQUEUE_LIBS := $(shell pkg-config --libs libnetfilter_queue 2>/dev/null || echo -lnetfilter_queue)
BIN := build/secure-inline

.PHONY: all clean test
all: $(BIN)

build:
	mkdir -p build

$(BIN): src/main.c src/handshake.c src/packet.c src/crypto.c include/secure_inline.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(shell pkg-config --cflags libnetfilter_queue openssl 2>/dev/null) \
		src/main.c src/handshake.c src/packet.c src/crypto.c -o $@ $(NFQUEUE_LIBS) $(CRYPTO_LIBS)

build/test_packet: tests/test_packet.c src/packet.c src/crypto.c include/secure_inline.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_packet.c src/packet.c src/crypto.c -o $@ $(CRYPTO_LIBS)

build/test_handshake: tests/test_handshake.c src/handshake.c src/crypto.c include/secure_inline.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_handshake.c src/handshake.c src/crypto.c -o $@ $(CRYPTO_LIBS)

test: build/test_packet build/test_handshake
	./build/test_packet
	./build/test_handshake

clean:
	rm -rf build
