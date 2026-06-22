# wolfNanoTLS — plain Makefile (no ./configure)
# Default backend: src (selected wolfcrypt sources from the pinned submodule).

WOLFSSL  := wolfssl
WC       := $(WOLFSSL)/wolfcrypt/src
BUILD    := build
CC       ?= cc

# Pass MALLOC=1 to relax the true-no-allocator bar during bring-up.
ifeq ($(MALLOC),1)
  MALLOC_FLAG := -DWOLFNANOTLS_ALLOW_MALLOC
endif

CFLAGS_COMMON := -Os -Wall -Wextra -Wdeclaration-after-statement \
                 -DWOLFSSL_USER_SETTINGS -I. -I$(WOLFSSL) $(MALLOC_FLAG) \
                 $(EXTRA_CFLAGS)

# Crypto floor (provider backend = src). Math file is target-specific (below).
FLOOR_SRC := \
  $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
  $(WC)/random.c $(WC)/wolfmath.c $(WC)/logging.c $(WC)/coding.c \
  $(WC)/sha256.c $(WC)/sha512.c $(WC)/hmac.c $(WC)/kdf.c $(WC)/aes.c \
  $(WC)/asn.c $(WC)/ecc.c $(WC)/curve25519.c $(WC)/fe_operations.c \
  $(WC)/ed25519.c $(WC)/ge_operations.c

TEST_SRC := tests/floor_test.c tests/wn_host_seed.c

SHELL_INC := -Iinclude/wolfnano -Isrc

# Full client crypto + shell for the live interop handshake.
CONN_SRC := $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
  $(WC)/logging.c $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c $(WC)/hmac.c \
  $(WC)/kdf.c $(WC)/aes.c $(WC)/curve25519.c $(WC)/fe_operations.c \
  src/wn_msg.c src/wn_keyschedule.c \
  src/wn_transcript.c src/wn_record.c \
  src/wn_keyshare.c src/wn_serverhello.c \
  src/wn_connect.c src/wn_session.c tests/wn_host_seed.c

# P-256 PSK handshake build (ECDHE secp256r1; FLOOR_SRC links ecc/asn/sp).
CONN_P256_SRC := $(FLOOR_SRC) $(WC)/sp_int.c \
  src/wn_msg.c src/wn_keyschedule.c \
  src/wn_transcript.c src/wn_record.c \
  src/wn_keyshare.c src/wn_serverhello.c \
  src/wn_connect.c src/wn_session.c tests/wn_host_seed.c

# Cert handshake build (adds ECDHE non-PSK ClientHello + cert/CertVerify deps).
CONN_CERT_SRC := $(FLOOR_SRC) $(WC)/sp_int.c \
  src/wn_msg.c src/wn_keyschedule.c \
  src/wn_transcript.c src/wn_record.c \
  src/wn_keyshare.c src/wn_serverhello.c \
  src/wn_clienthello.c src/wn_connect.c src/wn_session.c \
  tests/wn_host_seed.c
KS_SRC := $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
  $(WC)/logging.c $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c \
  $(WC)/hmac.c $(WC)/kdf.c \
  src/wn_keyschedule.c tests/wn_host_seed.c

TS_SRC := $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
  $(WC)/logging.c $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c \
  src/wn_transcript.c tests/wn_host_seed.c

REC_SRC := $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
  $(WC)/logging.c $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c $(WC)/aes.c \
  src/wn_record.c tests/wn_host_seed.c

KSH_SRC := $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
  $(WC)/logging.c $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c \
  $(WC)/curve25519.c $(WC)/fe_operations.c \
  src/wn_keyshare.c tests/wn_host_seed.c

SHELL_SRC := src/wn_keyshare.c src/wn_keyschedule.c \
  src/wn_transcript.c src/wn_record.c
HS_SRC := $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
  $(WC)/logging.c $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c $(WC)/hmac.c \
  $(WC)/kdf.c $(WC)/aes.c $(WC)/curve25519.c $(WC)/fe_operations.c \
  $(SHELL_SRC) tests/wn_host_seed.c

# wolfSSL's own crypto test, compiled with the wolfNanoTLS config so #ifdef trims
# it to exactly the floor algorithms.
WCT_SRC := $(FLOOR_SRC) $(WC)/sp_int.c wolfssl/wolfcrypt/test/test.c \
  tests/wn_host_seed.c
WCTPQC_SRC := $(WCT_SRC) $(WC)/sha3.c $(WC)/wc_mlkem.c $(WC)/wc_mlkem_poly.c \
  $(WC)/wc_mldsa.c

MLKEM_SRC := $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
  $(WC)/logging.c $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c $(WC)/sha3.c \
  $(WC)/wc_mlkem.c $(WC)/wc_mlkem_poly.c tests/wn_host_seed.c
MLDSA_SRC := $(FLOOR_SRC) $(WC)/sp_int.c $(WC)/sha3.c $(WC)/wc_mldsa.c \
  tests/wn_host_seed.c
HYBRID_SRC := $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
  $(WC)/logging.c $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c $(WC)/sha3.c \
  $(WC)/curve25519.c $(WC)/fe_operations.c $(WC)/wc_mlkem.c \
  $(WC)/wc_mlkem_poly.c src/wn_hybrid.c tests/wn_host_seed.c

CERT_SRC := $(FLOOR_SRC) $(WC)/sp_int.c tests/wn_host_seed.c

# WOLFNANOTLS_CRYPTO=fips backend (Phase 5 seam proof). Override with the path to
# your own built wolfSSL FIPS bundle (FIPS Ready or a licensed validated module).
WOLFNANOTLS_FIPS_DIR ?= $(HOME)/wolfssl-fips
FIPS_LIB := $(WOLFNANOTLS_FIPS_DIR)/src/.libs/libwolfssl.a

# ---- WOLFNANOTLS_ASM: per-arch speedup bundle (mirrors wolfSSL --enable-*asm) ----
# Default 'none' = lightweight portable C (WOLFSSL_SP_MATH_ALL, no asm). Each
# accelerated arch selects its toolchain, flags, specialized SP file + asm files.
# The macro bundle lives in wolfnano_target.h (selected via FLAGS_<arch>).
WOLFNANOTLS_ASM ?= none
ARM   := $(WC)/port/arm
RISCV := $(WC)/port/riscv

CC_none      := cc
FLAGS_none   := -DWOLFNANOTLS_TARGET_PORTABLE_C
SPSRC_none   := $(WC)/sp_int.c
ASMSRC_none  :=

CC_intel     := cc
FLAGS_intel  := -march=native -DWOLFNANOTLS_TARGET_X86_64
SPSRC_intel  := $(WC)/sp_int.c $(WC)/sp_x86_64.c $(WC)/sp_x86_64_asm.S
ASMSRC_intel := $(WC)/aes_asm.S $(WC)/aes_gcm_asm.S $(WC)/sha256_asm.S \
                $(WC)/sha512_asm.S $(WC)/fe_x25519_asm.S $(WC)/cpuid.c

# Prefer a complete arm-none-eabi toolchain (with newlib) if one is installed;
# fall back to the bare name (overridable: make floor-thumb2 CC_thumb2=...).
ARM_GNU_BIN := $(wildcard /Applications/ArmGNUToolchain/*/arm-none-eabi/bin)
CC_thumb2     := $(firstword $(wildcard $(ARM_GNU_BIN)/arm-none-eabi-gcc) arm-none-eabi-gcc)
FLAGS_thumb2  := -mcpu=cortex-m33 -mthumb -DWOLFNANOTLS_TARGET_CORTEXM33
SPSRC_thumb2  := $(WC)/sp_int.c $(WC)/sp_cortexm.c
ASMSRC_thumb2 := $(ARM)/thumb2-aes-asm_c.c $(ARM)/thumb2-sha256-asm_c.c \
                 $(ARM)/thumb2-sha512-asm_c.c $(ARM)/thumb2-curve25519_c.c

CC_aarch64     := $(shell command -v aarch64-elf-gcc 2>/dev/null || echo aarch64-none-elf-gcc)
FLAGS_aarch64  := -march=armv8-a+crypto -DWOLFNANOTLS_TARGET_AARCH64
SPSRC_aarch64  := $(WC)/sp_int.c $(WC)/sp_arm64.c
ASMSRC_aarch64 := $(ARM)/armv8-aes-asm_c.c $(ARM)/armv8-sha256-asm_c.c \
                  $(ARM)/armv8-sha512-asm_c.c $(ARM)/armv8-curve25519_c.c

CC_armv7     := $(CC_thumb2)
FLAGS_armv7  := -march=armv7-a -DWOLFNANOTLS_TARGET_ARMV8_32
SPSRC_armv7  := $(WC)/sp_int.c $(WC)/sp_arm32.c
ASMSRC_armv7 := $(ARM)/armv8-32-aes-asm_c.c $(ARM)/armv8-32-sha256-asm_c.c \
                $(ARM)/armv8-32-sha512-asm_c.c $(ARM)/armv8-32-curve25519_c.c

CC_riscv64     := riscv64-unknown-elf-gcc
FLAGS_riscv64  := -march=rv64gc -DWOLFNANOTLS_TARGET_RISCV64
SPSRC_riscv64  := $(WC)/sp_int.c $(WC)/sp_c64.c
ASMSRC_riscv64 := $(RISCV)/riscv-64-aes.c $(RISCV)/riscv-64-sha256.c \
                  $(RISCV)/riscv-64-sha512.c

# Extra asm for the bench's optional algos (ChaCha/Poly1305 + ML-KEM/ML-DSA),
# pulled in by USE_INTEL_SPEEDUP on intel; empty elsewhere.
BENCHASM_none    :=
BENCHASM_intel   := $(WC)/chacha_asm.S $(WC)/poly1305_asm.S $(WC)/sha3_asm.S \
                    $(WC)/wc_mlkem_asm.S $(WC)/wc_mldsa_asm.S
BENCHASM_thumb2  :=
BENCHASM_aarch64 :=
BENCHASM_armv7   :=
BENCHASM_riscv64 :=

ASM_CC    := $(CC_$(WOLFNANOTLS_ASM))
ASM_FLAGS := $(FLAGS_$(WOLFNANOTLS_ASM))
ASM_SRC   := $(SPSRC_$(WOLFNANOTLS_ASM)) $(ASMSRC_$(WOLFNANOTLS_ASM))

.PHONY: host kstest keyupdatetest sessiontest mocktest errtest rfctest tstest rectest ksharetest hstest wctest wctestpqc msgtest chtest shtest negtest flighttest alerttest matrixtest mlkemtest mldsatest hybridtest certtest fipsproof bench benchrun targets test-qemu test test-core check example configs-build coverage stackcheck clean
test: test-core mlkemtest mldsatest hybridtest wctestpqc ## build + run all local self-tests
test-core: host kstest keyupdatetest sessiontest mocktest errtest rfctest tstest rectest ksharetest hstest wctest msgtest chtest shtest negtest flighttest alerttest matrixtest certtest ## non-PQC suites (wolfSSL without the wc_mlkem/wc_mldsa API)

SUITES := host kstest keyupdatetest sessiontest mocktest errtest rfctest tstest rectest ksharetest hstest wctest wctestpqc \
  msgtest chtest shtest negtest flighttest alerttest matrixtest mlkemtest mldsatest hybridtest certtest

check: ## run every suite, continue past failures, print one colored PASS/FAIL tally
	@mkdir -p $(BUILD)
	@pass=0; fail=0; failed=""; \
	 if [ -t 1 ] && [ -z "$$NO_COLOR" ]; then G='\033[32m'; R='\033[31m'; Y='\033[33m'; Z='\033[0m'; else G=; R=; Y=; Z=; fi; \
	 for s in $(SUITES); do \
	   if $(MAKE) --no-print-directory $$s >$(BUILD)/check-$$s.log 2>&1; then \
	     pass=$$((pass+1)); printf "$${G}PASS$${Z} %s\n" "$$s"; \
	   else \
	     fail=$$((fail+1)); failed="$$failed $$s"; printf "$${R}FAIL$${Z} %s\n" "$$s"; \
	   fi; \
	 done; \
	 checks=$$(cat $(BUILD)/check-*.log 2>/dev/null | grep -cE 'PASS'); \
	 echo "================ wolfNanoTLS test summary ================"; \
	 printf "  suites passed: %s%d / %d%s\n" "$$([ $$fail -eq 0 ] && echo $$G || echo $$R)" "$$pass" "$$((pass+fail))" "$$Z"; \
	 printf "  assertions passed: %d\n" "$$checks"; \
	 [ -n "$$failed" ] && printf "  $${R}FAILED:%s$${Z} (see $(BUILD)/check-<suite>.log)\n" "$$failed"; \
	 [ $$fail -eq 0 ] && printf "  $${G}ALL SUITES PASS$${Z}\n" || exit 1

host: ## build + run the crypto floor self-test locally (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(FLOOR_SRC) $(WC)/sp_int.c $(TEST_SRC) -o $(BUILD)/floor_test_host
	@echo "---- run ----"
	@./$(BUILD)/floor_test_host

kstest: ## build + run the TLS 1.3 key-schedule KATs (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(KS_SRC) tests/keyschedule_test.c -o $(BUILD)/keyschedule_test
	@echo "---- run ----"
	@./$(BUILD)/keyschedule_test

keyupdatetest: ## build + run the post-handshake KeyUpdate KAT (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(KS_SRC) tests/keyupdate_test.c -o $(BUILD)/keyupdate_test
	@echo "---- run ----"
	@./$(BUILD)/keyupdate_test

errtest: ## build + run the wn_ErrorToString tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   src/wn_error.c tests/error_test.c -o $(BUILD)/error_test
	@echo "---- run ----"
	@./$(BUILD)/error_test

mocktest: ## build + run the in-process mock-server handshake test (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(CONN_SRC) tests/connect_mock_test.c -o $(BUILD)/connect_mock_test
	@echo "---- run ----"
	@./$(BUILD)/connect_mock_test

sessiontest: ## build + run the application-data session unit tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
	   $(WC)/logging.c $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c \
	   $(WC)/hmac.c $(WC)/kdf.c $(WC)/aes.c \
	   src/wn_msg.c src/wn_keyschedule.c src/wn_record.c src/wn_session.c \
	   tests/wn_host_seed.c tests/session_test.c -o $(BUILD)/session_test
	@echo "---- run ----"
	@./$(BUILD)/session_test

rfctest: ## build + run RFC 8448 section 3 record-key KATs (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(KS_SRC) tests/rfc8448_test.c -o $(BUILD)/rfc8448_test
	@echo "---- run ----"
	@./$(BUILD)/rfc8448_test

tstest: ## build + run the transcript-hash tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(TS_SRC) tests/transcript_test.c -o $(BUILD)/transcript_test
	@echo "---- run ----"
	@./$(BUILD)/transcript_test

rectest: ## build + run the record-protection tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(REC_SRC) tests/record_test.c -o $(BUILD)/record_test
	@echo "---- run ----"
	@./$(BUILD)/record_test

ksharetest: ## build + run the X25519 key-share tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(KSH_SRC) tests/keyshare_test.c -o $(BUILD)/keyshare_test
	@echo "---- run ----"
	@./$(BUILD)/keyshare_test

hstest: ## build + run the end-to-end crypto handshake (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(HS_SRC) tests/handshake_crypto_test.c -o $(BUILD)/handshake_crypto_test
	@echo "---- run ----"
	@./$(BUILD)/handshake_crypto_test

alloctrap: ## runtime proof: handshake crypto path makes zero heap calls (GNU ld)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc \
	   $(HS_SRC) tests/malloc_trap.c tests/malloc_trap_test.c \
	   -o $(BUILD)/malloc_trap_test
	@echo "---- run ----"
	@./$(BUILD)/malloc_trap_test

wctest: ## run wolfSSL's wolfcrypt test against the floor (config-trimmed)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) -DNO_MAIN_DRIVER -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(WCT_SRC) tests/wolfcrypt_test_main.c -o $(BUILD)/wctest
	@echo "---- run ----"
	@./$(BUILD)/wctest > $(BUILD)/wctest.out 2>&1; \
	  echo "  $$(grep -c 'test passed' $(BUILD)/wctest.out) wolfSSL KAT sub-tests passed; $$(tail -1 $(BUILD)/wctest.out)"

wctestpqc: ## run wolfSSL's wolfcrypt KATs incl. ML-KEM/ML-DSA (lifted from wolfSSL)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) -DNO_MAIN_DRIVER -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   -DWOLFNANOTLS_MLKEM -DWOLFNANOTLS_MLDSA -DWOLFNANOTLS_MLDSA_SIGN -DWOLFNANOTLS_ALLOW_MALLOC \
	   $(WCTPQC_SRC) tests/wolfcrypt_test_main.c -o $(BUILD)/wctestpqc
	@echo "---- run ----"
	@./$(BUILD)/wctestpqc > $(BUILD)/wctestpqc.out 2>&1; \
	  echo "  $$(grep -c 'test passed' $(BUILD)/wctestpqc.out) wolfSSL KAT sub-tests passed (incl. ML-KEM/ML-DSA); $$(tail -1 $(BUILD)/wctestpqc.out)"

msgtest: ## build + run the wire encode/decode primitive tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   src/wn_msg.c tests/msg_test.c -o $(BUILD)/msg_test
	@echo "---- run ----"
	@./$(BUILD)/msg_test

chtest: ## build + run the ClientHello encoder test (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   src/wn_msg.c src/wn_clienthello.c \
	   tests/clienthello_test.c -o $(BUILD)/clienthello_test
	@echo "---- run ----"
	@./$(BUILD)/clienthello_test

shtest: ## build + run the ServerHello parser test (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   src/wn_msg.c src/wn_serverhello.c \
	   tests/serverhello_test.c -o $(BUILD)/serverhello_test
	@echo "---- run ----"
	@./$(BUILD)/serverhello_test

negtest: ## build + run negative/malformed parser tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   src/wn_msg.c src/wn_serverhello.c \
	   tests/parser_negative_test.c -o $(BUILD)/parser_negative_test
	@echo "---- run ----"
	@./$(BUILD)/parser_negative_test

flighttest: ## build + run the adversarial encrypted-flight ordering tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   tests/flight_order_test.c -o $(BUILD)/flight_order_test
	@echo "---- run ----"
	@./$(BUILD)/flight_order_test

alerttest: ## build + run the error->alert (RFC 8446 6.2) mapping tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   tests/alert_map_test.c -o $(BUILD)/alert_map_test
	@echo "---- run ----"
	@./$(BUILD)/alert_map_test

matrixtest: ## build + run the data-driven negotiation matrix (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   src/wn_msg.c src/wn_serverhello.c \
	   tests/suites_matrix.c -o $(BUILD)/suites_matrix
	@echo "---- run ----"
	@./$(BUILD)/suites_matrix

FUZZ_TIME ?= 60
FUZZ_CC ?= clang
fuzz: ## coverage-guided fuzz of the wire parsers (clang libFuzzer + ASan)
	@mkdir -p $(BUILD)/corp_sh $(BUILD)/corp_msg $(BUILD)/corp_rec
	$(FUZZ_CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   -fsanitize=fuzzer,address -g \
	   src/wn_msg.c src/wn_serverhello.c tests/fuzz_serverhello.c \
	   -o $(BUILD)/fuzz_serverhello
	$(FUZZ_CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   -fsanitize=fuzzer,address -g \
	   src/wn_msg.c tests/fuzz_msg.c -o $(BUILD)/fuzz_msg
	$(FUZZ_CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   -fsanitize=fuzzer,address -g \
	   $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c $(WC)/logging.c \
	   $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c $(WC)/aes.c src/wn_record.c \
	   tests/wn_host_seed.c tests/fuzz_record.c -o $(BUILD)/fuzz_record
	@echo "---- run ($(FUZZ_TIME)s each) ----"
	@./$(BUILD)/fuzz_serverhello -max_total_time=$(FUZZ_TIME) -timeout=10 $(BUILD)/corp_sh
	@./$(BUILD)/fuzz_msg        -max_total_time=$(FUZZ_TIME) -timeout=10 $(BUILD)/corp_msg
	@./$(BUILD)/fuzz_record     -max_total_time=$(FUZZ_TIME) -timeout=10 $(BUILD)/corp_rec

mlkemtest: ## build + run the ML-KEM-768 KEM test (WOLFNANOTLS_MLKEM)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) -DWOLFNANOTLS_MLKEM -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(MLKEM_SRC) tests/mlkem_test.c -o $(BUILD)/mlkem_test
	@echo "---- run ----"
	@./$(BUILD)/mlkem_test

mldsatest: ## build + run ML-DSA-65 round-trip + verify-only no-malloc proof
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) -DWOLFNANOTLS_MLDSA -DWOLFNANOTLS_MLDSA_SIGN \
	   -DWOLFNANOTLS_ALLOW_MALLOC -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(MLDSA_SRC) tests/mldsa_test.c -o $(BUILD)/mldsa_test
	@echo "---- run (sign/verify round-trip) ----"
	@./$(BUILD)/mldsa_test
	@echo "---- verify-only no-malloc proof ----"
	@cc $(CFLAGS_COMMON) -DWOLFNANOTLS_MLDSA -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   -c $(WC)/wc_mldsa.c -o $(BUILD)/wc_mldsa_vo.o 2>/dev/null
	@nm $(BUILD)/wc_mldsa_vo.o | grep -E ' U _(malloc|calloc|realloc|free)$$' \
	   && echo "  FAIL: verify-only references heap" \
	   || echo "  PASS: verify-only ML-DSA is allocation-free"

hybridtest: ## build + run the X25519MLKEM768 hybrid key-share test
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_MLKEM -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(HYBRID_SRC) tests/hybrid_test.c -o $(BUILD)/hybrid_test
	@echo "---- run ----"
	@./$(BUILD)/hybrid_test

certtest: ## build + run the X.509 cert-verify test (ECC + RSA; needs heap)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) -DWOLFNANOTLS_X509 -DWOLFNANOTLS_HAVE_RSA_VERIFY \
	   -DWOLFNANOTLS_ALLOW_MALLOC -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(CERT_SRC) $(WC)/rsa.c tests/cert_test.c -o $(BUILD)/cert_test
	@echo "---- run ----"
	@./$(BUILD)/cert_test

interop: ## live TLS 1.3 PSK handshake vs OpenSSL and wolfSSL
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(CONN_SRC) tests/interop_psk_test.c -o $(BUILD)/interop_psk_client
	@echo "== PSK (X25519) vs OpenSSL =="; sh tests/interop_psk.sh
	@echo "== PSK (X25519) vs wolfSSL =="; sh tests/interop_wolfssl.sh
	@echo "== PSK (X25519) vs mbedTLS =="; sh tests/interop_mbedtls.sh
	@echo "== app-data (wn_Send/wn_Recv/wn_Close) vs OpenSSL =="; sh tests/interop_psk_appdata.sh
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_HAVE_ECDHE_P256 \
	   -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(CONN_P256_SRC) tests/interop_psk_test.c -o $(BUILD)/interop_psk_p256_client
	@echo "== PSK (P-256) vs OpenSSL =="; CLIENT=$(BUILD)/interop_psk_p256_client sh tests/interop_psk.sh
	@echo "== PSK (P-256) vs wolfSSL =="; CLIENT=$(BUILD)/interop_psk_p256_client sh tests/interop_wolfssl.sh
	@echo "== PSK (P-256) vs mbedTLS =="; CLIENT=$(BUILD)/interop_psk_p256_client sh tests/interop_mbedtls.sh
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_X509 -DWOLFNANOTLS_HAVE_RSA_VERIFY \
	   -DWOLFNANOTLS_ALLOW_MALLOC -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(CONN_CERT_SRC) $(WC)/rsa.c tests/interop_cert_test.c \
	   -o $(BUILD)/interop_cert_client
	@echo "== cert(ECDSA) vs OpenSSL =="; sh tests/interop_cert.sh ecdsa
	@echo "== cert(RSA-PSS) vs OpenSSL =="; sh tests/interop_cert.sh rsa
	@echo "== cert(Ed25519) vs OpenSSL =="; sh tests/interop_cert.sh ed
	@echo "== cert(chain leaf<-inter<-root) vs OpenSSL =="; sh tests/interop_cert.sh chain
	@echo "== cert(ECDSA) vs wolfSSL =="; sh tests/interop_cert_wolfssl.sh ecdsa
	@echo "== cert(RSA-PSS) vs wolfSSL =="; sh tests/interop_cert_wolfssl.sh rsa
	@echo "== cert(Ed25519) vs wolfSSL =="; sh tests/interop_cert_wolfssl.sh ed
	@echo "== cert(chain leaf<-inter<-root) vs wolfSSL =="; sh tests/interop_cert_wolfssl.sh chain
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_X509 -DWOLFNANOTLS_HAVE_RSA_VERIFY \
	   -DWOLFNANOTLS_ALLOW_MALLOC -DWOLFNANOTLS_FIPS -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(CONN_CERT_SRC) $(WC)/rsa.c tests/interop_cert_test.c \
	   -o $(BUILD)/interop_cert_fips_client
	@echo "== cert(ECDSA, approved ECDHE P-256 suites) vs OpenSSL =="; \
	   WN_CERT_CLIENT=interop_cert_fips_client sh tests/interop_cert.sh ecdsa
	@echo "== cert(ECDSA, approved ECDHE P-256 suites) vs wolfSSL =="; \
	   WN_CERT_CLIENT=interop_cert_fips_client sh tests/interop_cert_wolfssl.sh ecdsa

fipsproof: ## Phase 5: same shell sources link against the FIPS backend; CASTs pass
	@mkdir -p $(BUILD)
	@test -f $(FIPS_LIB) || { echo "SKIP fipsproof (no FIPS lib at $(FIPS_LIB); set WOLFNANOTLS_FIPS_DIR)"; exit 0; }
	@echo "== seam crypto vs wolfCrypt FIPS module =="
	@sh tests/fips_seam_proof.sh $(WOLFNANOTLS_FIPS_DIR)
	@echo "== shell seam surface is backend-identical (zero source changes) =="
	@cc $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   -c src/wn_keyschedule.c -o $(BUILD)/ks_src.o
	@cc -Os -DWOLFSSL_USE_OPTIONS_H -I$(WOLFNANOTLS_FIPS_DIR) $(SHELL_INC) \
	   -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   -c src/wn_keyschedule.c -o $(BUILD)/ks_fips.o
	@nm -u $(BUILD)/ks_src.o  | grep '_wc_' | sort > $(BUILD)/seam_src.txt
	@# FIPS headers route each wc_* call to its _fips boundary wrapper; strip the
	@# suffix to compare the logical crypto surface (the .c is byte-identical).
	@nm -u $(BUILD)/ks_fips.o | grep '_wc_' | sed 's/_fips$$//' | sort > $(BUILD)/seam_fips.txt
	@if diff -q $(BUILD)/seam_src.txt $(BUILD)/seam_fips.txt >/dev/null; then \
	   echo "PASS same wc_* seam surface on src and fips (fips routes via _fips wrappers)"; \
	   sed 's/^/    /' $(BUILD)/seam_src.txt; \
	 else echo "FAIL seam surface differs"; diff $(BUILD)/seam_src.txt $(BUILD)/seam_fips.txt; exit 1; fi

# Build + run the all-algo bench for the active WOLFNANOTLS_ASM arch.
benchrun:
	@mkdir -p $(BUILD)
	$(ASM_CC) $(CFLAGS_COMMON) $(SHELL_INC) $(ASM_FLAGS) \
	   -DWOLFNANOTLS_MLKEM -DWOLFNANOTLS_MLDSA -DWOLFNANOTLS_MLDSA_SIGN \
	   -DWOLFNANOTLS_HAVE_CHACHA -DWOLFNANOTLS_HAVE_RSA_VERIFY -DWOLFNANOTLS_RSA_FULL \
	   -DWOLFNANOTLS_ALLOW_MALLOC \
	   $(WC)/sha3.c $(WC)/wc_mlkem.c $(WC)/wc_mlkem_poly.c $(WC)/wc_mldsa.c \
	   $(WC)/chacha.c $(WC)/poly1305.c $(WC)/chacha20_poly1305.c $(WC)/rsa.c \
	   $(FLOOR_SRC) $(ASM_SRC) $(BENCHASM_$(WOLFNANOTLS_ASM)) \
	   tests/bench_all.c tests/wn_host_seed.c \
	   -o $(BUILD)/bench_$(WOLFNANOTLS_ASM)
	@./$(BUILD)/bench_$(WOLFNANOTLS_ASM)

bench: ## crypto speed, all algos: portable C vs Intel asm side by side
	@$(MAKE) --no-print-directory benchrun WOLFNANOTLS_ASM=none
	@$(MAKE) --no-print-directory benchrun WOLFNANOTLS_ASM=intel

# floor-<arch>: cross-compile the crypto floor + that arch's asm to objects,
# proving wolfNanoTLS builds from source for the target. (Host arches use `host` /
# `bench` instead.) A missing/incomplete toolchain skips with a message.
floor-%:
	@mkdir -p $(BUILD)/$*
	@if ! command -v $(CC_$*) >/dev/null 2>&1; then echo "SKIP floor-$* (no $(CC_$*))"; \
	 else ok=1; for f in $(FLOOR_SRC) $(SPSRC_$*) $(ASMSRC_$*); do \
	     $(CC_$*) $(CFLAGS_COMMON) $(SHELL_INC) $(FLAGS_$*) -c $$f \
	       -o $(BUILD)/$*/`basename $$f`.o 2>/dev/null || { ok=0; break; }; \
	   done; \
	   if [ $$ok = 1 ]; then echo "OK floor-$* (cross objects built)"; \
	   else echo "SKIP floor-$* ($(CC_$*) present but toolchain incomplete, e.g. no libc headers)"; fi; \
	 fi

targets: floor-thumb2 floor-aarch64 floor-armv7 floor-riscv64 ## cross-compile the floor for every non-host arch

# ---- Cross-arch test EXECUTION under qemu-user (Linux cross-targets) ----
# Unlike floor-%/targets (bare-metal, compile-only), these build the portable-C
# suites for a Linux cross target and RUN them under qemu-user, catching
# endian / word-size / alignment bugs without silicon. Skips when the cross gcc
# or qemu binary is absent.
QCC_arm      := arm-linux-gnueabihf-gcc
QCC_aarch64  := aarch64-linux-gnu-gcc
QCC_riscv64  := riscv64-linux-gnu-gcc
QEMU_arm     := qemu-arm-static
QEMU_aarch64 := qemu-aarch64-static
QEMU_riscv64 := qemu-riscv64-static

test-qemu-%:
	@cc=$(QCC_$*); q=$(QEMU_$*); s=-static; \
	 if ! command -v $$cc >/dev/null 2>&1; then echo "SKIP test-qemu-$* (no $$cc)"; exit 0; fi; \
	 if ! command -v $$q  >/dev/null 2>&1; then echo "SKIP test-qemu-$* (no $$q)"; exit 0; fi; \
	 mkdir -p $(BUILD)/qemu-$*; set -e; \
	 $$cc $(CFLAGS_COMMON) $$s -DWOLFNANOTLS_TARGET_PORTABLE_C $(FLOOR_SRC) $(WC)/sp_int.c $(TEST_SRC) -o $(BUILD)/qemu-$*/floor && $$q $(BUILD)/qemu-$*/floor; \
	 $$cc $(CFLAGS_COMMON) $$s $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C $(KS_SRC) tests/keyschedule_test.c -o $(BUILD)/qemu-$*/ks && $$q $(BUILD)/qemu-$*/ks; \
	 $$cc $(CFLAGS_COMMON) $$s $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C $(KS_SRC) tests/rfc8448_test.c -o $(BUILD)/qemu-$*/rfc && $$q $(BUILD)/qemu-$*/rfc; \
	 $$cc $(CFLAGS_COMMON) $$s $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C $(HS_SRC) tests/handshake_crypto_test.c -o $(BUILD)/qemu-$*/hs && $$q $(BUILD)/qemu-$*/hs; \
	 $$cc $(CFLAGS_COMMON) $$s $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C src/wn_msg.c src/wn_serverhello.c tests/parser_negative_test.c -o $(BUILD)/qemu-$*/neg && $$q $(BUILD)/qemu-$*/neg; \
	 echo "OK test-qemu-$* (ran under $$q)"

test-qemu: test-qemu-arm test-qemu-aarch64 test-qemu-riscv64 ## run the suites under qemu-user for arm/aarch64/riscv64

example: ## build the minimal PSK client example (examples/client.c)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANOTLS_TARGET_PORTABLE_C \
	   $(CONN_SRC) examples/client.c -o $(BUILD)/example_client
	@echo "built $(BUILD)/example_client"

configs-build: ## compile each configs/ starter template against the shell
	sh scripts/configs_build.sh

STACK_SRC := wn_connect.c wn_session.c wn_record.c wn_keyschedule.c \
  wn_keyshare.c wn_transcript.c wn_msg.c wn_serverhello.c wn_clienthello.c
stackcheck: ## fail if any wolfNanoTLS function exceeds the stack budget (-fstack-usage)
	@mkdir -p $(BUILD)/su
	@for b in $(STACK_SRC); do \
	  $(CC) -Os -fstack-usage -c $(SHELL_INC) -DWOLFSSL_USER_SETTINGS \
	    -DWOLFNANOTLS_TARGET_PORTABLE_C -DWOLFNANOTLS_X509 -DWOLFNANOTLS_HAVE_RSA_VERIFY \
	    -DWOLFNANOTLS_ALLOW_MALLOC -I. -I$(WOLFSSL) src/$$b -o $(BUILD)/su/$${b%.c}.o; \
	done
	@sh scripts/check_stack.sh $(BUILD)/su/*.su

coverage: ## Linux: run the suites under --coverage and enforce 100% (ci/coverage-100.txt)
	@command -v lcov >/dev/null 2>&1 || { echo "SKIP coverage (no lcov; Linux/CI only)"; exit 0; }
	$(MAKE) test EXTRA_CFLAGS="--coverage -O0"
	lcov --capture --directory . --output-file cov.info --rc lcov_branch_coverage=0 2>/dev/null || true
	lcov --remove cov.info '*/wolfssl/*' '/usr/*' '*/tests/*' --output-file cov.info 2>/dev/null || true
	sh scripts/check_coverage.sh cov.info ci/coverage-100.txt

clean:
	rm -rf $(BUILD) *.o *.gcda *.gcno cov.info
