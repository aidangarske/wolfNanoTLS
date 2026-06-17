# wolfNano — plain Makefile (no ./configure)
# Default backend: src (selected wolfcrypt sources from the pinned submodule).

WOLFSSL  := wolfssl
WC       := $(WOLFSSL)/wolfcrypt/src
BUILD    := build

# Pass MALLOC=1 to relax the true-no-allocator bar during bring-up.
ifeq ($(MALLOC),1)
  MALLOC_FLAG := -DWOLFNANO_ALLOW_MALLOC
endif

CFLAGS_COMMON := -Os -Wall -Wextra -Wdeclaration-after-statement \
                 -DWOLFSSL_USER_SETTINGS -I. -I$(WOLFSSL) $(MALLOC_FLAG)

# Crypto floor (provider backend = src). Math file is target-specific (below).
FLOOR_SRC := \
  $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
  $(WC)/random.c $(WC)/wolfmath.c $(WC)/logging.c $(WC)/coding.c \
  $(WC)/sha256.c $(WC)/sha512.c $(WC)/hmac.c $(WC)/kdf.c $(WC)/aes.c \
  $(WC)/asn.c $(WC)/ecc.c $(WC)/curve25519.c $(WC)/fe_operations.c \
  $(WC)/ed25519.c $(WC)/ge_operations.c

TEST_SRC := tests/floor_test.c tests/wn_host_seed.c

SHELL_INC := -Iinclude/wolfnano -Isrc/shell_slim

# Full client crypto + shell for the live interop handshake.
CONN_SRC := $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
  $(WC)/logging.c $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c $(WC)/hmac.c \
  $(WC)/kdf.c $(WC)/aes.c $(WC)/curve25519.c $(WC)/fe_operations.c \
  src/shell_slim/wn_msg.c src/shell_slim/wn_keyschedule.c \
  src/shell_slim/wn_transcript.c src/shell_slim/wn_record.c \
  src/shell_slim/wn_keyshare.c src/shell_slim/wn_serverhello.c \
  src/shell_slim/wn_connect.c tests/wn_host_seed.c
KS_SRC := $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
  $(WC)/logging.c $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c \
  $(WC)/hmac.c $(WC)/kdf.c \
  src/shell_slim/wn_keyschedule.c tests/wn_host_seed.c

TS_SRC := $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
  $(WC)/logging.c $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c \
  src/shell_slim/wn_transcript.c tests/wn_host_seed.c

REC_SRC := $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
  $(WC)/logging.c $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c $(WC)/aes.c \
  src/shell_slim/wn_record.c tests/wn_host_seed.c

KSH_SRC := $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
  $(WC)/logging.c $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c \
  $(WC)/curve25519.c $(WC)/fe_operations.c \
  src/shell_slim/wn_keyshare.c tests/wn_host_seed.c

SHELL_SRC := src/shell_slim/wn_keyshare.c src/shell_slim/wn_keyschedule.c \
  src/shell_slim/wn_transcript.c src/shell_slim/wn_record.c
HS_SRC := $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
  $(WC)/logging.c $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c $(WC)/hmac.c \
  $(WC)/kdf.c $(WC)/aes.c $(WC)/curve25519.c $(WC)/fe_operations.c \
  $(SHELL_SRC) tests/wn_host_seed.c

# wolfSSL's own crypto test, compiled with the wolfNano config so #ifdef trims
# it to exactly the floor algorithms.
WCT_SRC := $(FLOOR_SRC) $(WC)/sp_int.c wolfssl/wolfcrypt/test/test.c \
  tests/wn_host_seed.c

.PHONY: host kstest tstest rectest ksharetest hstest wctest msgtest chtest shtest test clean
test: host kstest tstest rectest ksharetest hstest wctest msgtest chtest shtest ## build + run all local self-tests

host: ## build + run the crypto floor self-test locally (PORTABLE_C)
	@mkdir -p $(BUILD)
	cc $(CFLAGS_COMMON) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(FLOOR_SRC) $(WC)/sp_int.c $(TEST_SRC) -o $(BUILD)/floor_test_host
	@echo "---- run ----"
	@./$(BUILD)/floor_test_host

kstest: ## build + run the TLS 1.3 key-schedule KATs (PORTABLE_C)
	@mkdir -p $(BUILD)
	cc $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(KS_SRC) tests/keyschedule_test.c -o $(BUILD)/keyschedule_test
	@echo "---- run ----"
	@./$(BUILD)/keyschedule_test

tstest: ## build + run the transcript-hash tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	cc $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(TS_SRC) tests/transcript_test.c -o $(BUILD)/transcript_test
	@echo "---- run ----"
	@./$(BUILD)/transcript_test

rectest: ## build + run the record-protection tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	cc $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(REC_SRC) tests/record_test.c -o $(BUILD)/record_test
	@echo "---- run ----"
	@./$(BUILD)/record_test

ksharetest: ## build + run the X25519 key-share tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	cc $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(KSH_SRC) tests/keyshare_test.c -o $(BUILD)/keyshare_test
	@echo "---- run ----"
	@./$(BUILD)/keyshare_test

hstest: ## build + run the end-to-end crypto handshake (PORTABLE_C)
	@mkdir -p $(BUILD)
	cc $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(HS_SRC) tests/handshake_crypto_test.c -o $(BUILD)/handshake_crypto_test
	@echo "---- run ----"
	@./$(BUILD)/handshake_crypto_test

wctest: ## run wolfSSL's wolfcrypt test against the floor (config-trimmed)
	@mkdir -p $(BUILD)
	cc $(CFLAGS_COMMON) -DNO_MAIN_DRIVER -DWOLFNANO_TARGET_PORTABLE_C \
	   $(WCT_SRC) tests/wolfcrypt_test_main.c -o $(BUILD)/wctest
	@echo "---- run ----"
	@./$(BUILD)/wctest | tail -3

msgtest: ## build + run the wire encode/decode primitive tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	cc $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   src/shell_slim/wn_msg.c tests/msg_test.c -o $(BUILD)/msg_test
	@echo "---- run ----"
	@./$(BUILD)/msg_test

chtest: ## build + run the ClientHello encoder test (PORTABLE_C)
	@mkdir -p $(BUILD)
	cc $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   src/shell_slim/wn_msg.c src/shell_slim/wn_clienthello.c \
	   tests/clienthello_test.c -o $(BUILD)/clienthello_test
	@echo "---- run ----"
	@./$(BUILD)/clienthello_test

shtest: ## build + run the ServerHello parser test (PORTABLE_C)
	@mkdir -p $(BUILD)
	cc $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   src/shell_slim/wn_msg.c src/shell_slim/wn_serverhello.c \
	   tests/serverhello_test.c -o $(BUILD)/serverhello_test
	@echo "---- run ----"
	@./$(BUILD)/serverhello_test

interop: ## live TLS 1.3 PSK handshake vs OpenSSL and wolfSSL
	@mkdir -p $(BUILD)
	cc $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CONN_SRC) tests/interop_psk_test.c -o $(BUILD)/interop_psk_client
	@echo "== vs OpenSSL =="; sh tests/interop_psk.sh
	@echo "== vs wolfSSL =="; sh tests/interop_wolfssl.sh

clean:
	rm -rf $(BUILD) *.o
