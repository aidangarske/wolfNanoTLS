# wolfNanoTLS — plain Makefile (no ./configure)
# Default backend: src (selected wolfcrypt sources from the pinned submodule).

WOLFSSL  := wolfssl
WC       := $(WOLFSSL)/wolfcrypt/src
BUILD    := build
CC       ?= cc

# Pass MALLOC=1 to relax the true-no-allocator bar during bring-up.
ifeq ($(MALLOC),1)
  MALLOC_FLAG := -DWOLFNANO_ALLOW_MALLOC
endif

# X.509 backend for the cert handshake path. Default: wolfSSL asn.c/DecodedCert
# (full feature set). X509_LITE=1: the smaller native wn_x509 parser (drops
# asn.c's reachable cert parser for ~10 KB less .text).
ifeq ($(X509_LITE),1)
  X509_BACKEND_FLAG := -DWOLFNANO_X509_LITE
  X509_BACKEND_SRC  := src/wn_x509.c
else
  X509_BACKEND_FLAG :=
  X509_BACKEND_SRC  :=
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
# Minimal single-curve P-256 cert build: no rsa.c, sha512.c, or ed25519.c deps.
CONN_CERT_P256MIN_SRC := $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c \
  $(WC)/hash.c $(WC)/random.c $(WC)/wolfmath.c $(WC)/logging.c $(WC)/coding.c \
  $(WC)/sha256.c $(WC)/hmac.c $(WC)/kdf.c $(WC)/aes.c $(WC)/asn.c $(WC)/ecc.c \
  $(WC)/curve25519.c $(WC)/fe_operations.c $(WC)/sp_int.c \
  src/wn_msg.c src/wn_keyschedule.c src/wn_transcript.c src/wn_record.c \
  src/wn_keyshare.c src/wn_serverhello.c src/wn_clienthello.c \
  src/wn_connect.c src/wn_session.c tests/wn_host_seed.c
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

# ML-DSA-65 CertVerify test: full client connect deps (the test #includes
# wn_connect.c, so it is omitted here) plus SHA3 + wc_mldsa.
CERTMLDSA_SRC := $(FLOOR_SRC) $(WC)/sp_int.c $(WC)/sha3.c $(WC)/wc_mldsa.c \
  $(WC)/rsa.c src/wn_msg.c src/wn_keyschedule.c src/wn_transcript.c \
  src/wn_record.c src/wn_keyshare.c src/wn_serverhello.c \
  src/wn_clienthello.c src/wn_session.c tests/wn_host_seed.c

# X25519MLKEM768 hybrid handshake (PSK path): adds ML-KEM-768 + SHA3 + wn_hybrid.
MOCKHYB_SRC := $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
  $(WC)/logging.c $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c $(WC)/sha3.c \
  $(WC)/hmac.c $(WC)/kdf.c $(WC)/aes.c $(WC)/curve25519.c $(WC)/fe_operations.c \
  $(WC)/wc_mlkem.c $(WC)/wc_mlkem_poly.c $(WC)/sp_int.c \
  src/wn_msg.c src/wn_keyschedule.c src/wn_transcript.c src/wn_record.c \
  src/wn_keyshare.c src/wn_serverhello.c src/wn_hybrid.c src/wn_connect.c \
  src/wn_session.c tests/wn_host_seed.c

# ---- WOLFNANO_ASM: per-arch speedup bundle (mirrors wolfSSL --enable-*asm) ----
# Default 'none' = lightweight portable C (WOLFSSL_SP_MATH_ALL, no asm). Each
# accelerated arch selects its toolchain, flags, specialized SP file + asm files.
# The macro bundle lives in wolfnano_target.h (selected via FLAGS_<arch>).
WOLFNANO_ASM ?= none
ARM   := $(WC)/port/arm
RISCV := $(WC)/port/riscv

CC_none      := cc
FLAGS_none   := -DWOLFNANO_TARGET_PORTABLE_C
SPSRC_none   := $(WC)/sp_int.c
ASMSRC_none  :=

CC_intel     := cc
FLAGS_intel  := -march=native -DWOLFNANO_TARGET_X86_64
SPSRC_intel  := $(WC)/sp_int.c $(WC)/sp_x86_64.c $(WC)/sp_x86_64_asm.S
# 64-bit AES-NI is in aes_x86_64_asm.S; aes_asm.S is now WOLFSSL_X86_BUILD (32-bit) only
ASMSRC_intel := $(WC)/aes_x86_64_asm.S $(WC)/aes_gcm_asm.S $(WC)/sha256_asm.S \
                $(WC)/sha512_asm.S $(WC)/fe_x25519_asm.S $(WC)/cpuid.c

# Prefer a complete arm-none-eabi toolchain (with newlib) if one is installed;
# fall back to the bare name (overridable: make floor-thumb2 CC_thumb2=...).
ARM_GNU_BIN := $(wildcard /Applications/ArmGNUToolchain/*/arm-none-eabi/bin)
CC_thumb2     := $(firstword $(wildcard $(ARM_GNU_BIN)/arm-none-eabi-gcc) arm-none-eabi-gcc)
FLAGS_thumb2  := -mcpu=cortex-m33 -mthumb -DWOLFNANO_TARGET_CORTEXM33
SPSRC_thumb2  := $(WC)/sp_int.c $(WC)/sp_cortexm.c
ASMSRC_thumb2 := $(ARM)/thumb2-aes-asm_c.c $(ARM)/thumb2-sha256-asm_c.c \
                 $(ARM)/thumb2-sha512-asm_c.c $(ARM)/thumb2-curve25519_c.c

CC_aarch64     := $(shell command -v aarch64-elf-gcc 2>/dev/null || echo aarch64-none-elf-gcc)
FLAGS_aarch64  := -march=armv8-a+crypto -DWOLFNANO_TARGET_AARCH64
SPSRC_aarch64  := $(WC)/sp_int.c $(WC)/sp_arm64.c
ASMSRC_aarch64 := $(ARM)/armv8-aes-asm_c.c $(ARM)/armv8-sha256-asm_c.c \
                  $(ARM)/armv8-sha512-asm_c.c $(ARM)/armv8-curve25519_c.c

CC_armv7     := $(CC_thumb2)
FLAGS_armv7  := -march=armv7-a -DWOLFNANO_TARGET_ARMV8_32
SPSRC_armv7  := $(WC)/sp_int.c $(WC)/sp_arm32.c
ASMSRC_armv7 := $(ARM)/armv8-32-aes-asm_c.c $(ARM)/armv8-32-sha256-asm_c.c \
                $(ARM)/armv8-32-sha512-asm_c.c $(ARM)/armv8-32-curve25519_c.c

CC_riscv64     := riscv64-unknown-elf-gcc
FLAGS_riscv64  := -march=rv64gc -DWOLFNANO_TARGET_RISCV64
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

ASM_CC    := $(CC_$(WOLFNANO_ASM))
ASM_FLAGS := $(FLAGS_$(WOLFNANO_ASM))
ASM_SRC   := $(SPSRC_$(WOLFNANO_ASM)) $(ASMSRC_$(WOLFNANO_ASM))

.PHONY: host kstest keyupdatetest sessiontest mocktest mockhybridtest errtest rfctest tstest rectest ksharetest hstest wctest wctestpqc msgtest chtest shtest negtest flighttest alerttest matrixtest mlkemtest mldsatest certmldsatest certnegtest certnegpintest certgentest hybridtest certtest x509diff x509verifytest x509negtest x509negvectest x509probetest x509covtest bench benchrun targets test-qemu test test-core test-x509 test-cert check example example-cert example-cert-min example-cert-pqc cert-notime-build example-https example-https-lite example-pqc configs-build m33mu coverage stackcheck clean
test: test-core test-x509 mlkemtest mldsatest hybridtest mockhybridtest wctestpqc ## build + run all local self-tests (certmldsatest runs separately; compiling X509 here would drag the interop-only cert path into the coverage build)
test-core: host kstest keyupdatetest sessiontest mocktest errtest rfctest tstest rectest ksharetest hstest wctest msgtest chtest shtest negtest flighttest alerttest matrixtest ## protocol + crypto suites (no cert/X.509; those are test-x509 / test-cert)
test-x509: certtest x509diff x509verifytest x509negtest x509negvectest x509covtest x509probetest ## native wn_x509 parser + cert-verify unit tests
test-cert: certnegtest certnegpintest certgentest ## X.509 cert-path chain-constraint tests (backend selected by X509_LITE)

SUITES := host kstest keyupdatetest sessiontest mocktest mockhybridtest errtest rfctest tstest rectest ksharetest hstest wctest wctestpqc \
  msgtest chtest shtest negtest flighttest alerttest matrixtest mlkemtest mldsatest certmldsatest certnegtest certnegpintest certgentest hybridtest certtest \
  x509diff x509verifytest x509negtest x509negvectest x509covtest

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
	$(CC) $(CFLAGS_COMMON) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(FLOOR_SRC) $(WC)/sp_int.c $(TEST_SRC) -o $(BUILD)/floor_test_host
	@echo "---- run ----"
	@./$(BUILD)/floor_test_host

kstest: ## build + run the TLS 1.3 key-schedule KATs (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(KS_SRC) tests/keyschedule_test.c -o $(BUILD)/keyschedule_test
	@echo "---- run ----"
	@./$(BUILD)/keyschedule_test

keyupdatetest: ## build + run the post-handshake KeyUpdate KAT (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(KS_SRC) tests/keyupdate_test.c -o $(BUILD)/keyupdate_test
	@echo "---- run ----"
	@./$(BUILD)/keyupdate_test

errtest: ## build + run the wn_ErrorToString tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   src/wn_error.c tests/error_test.c -o $(BUILD)/error_test
	@echo "---- run ----"
	@./$(BUILD)/error_test

mocktest: ## build + run the in-process mock-server handshake test (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CONN_SRC) tests/connect_mock_test.c -o $(BUILD)/connect_mock_test
	@echo "---- run ----"
	@./$(BUILD)/connect_mock_test

mockhybridtest: ## build + run the X25519MLKEM768 hybrid mock-server handshake test
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   -DWOLFNANO_HAVE_MLKEM_HYBRID \
	   $(MOCKHYB_SRC) tests/connect_mock_hybrid_test.c \
	   -o $(BUILD)/connect_mock_hybrid_test
	@echo "---- run ----"
	@./$(BUILD)/connect_mock_hybrid_test

sessiontest: ## build + run the application-data session unit tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c \
	   $(WC)/logging.c $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c \
	   $(WC)/hmac.c $(WC)/kdf.c $(WC)/aes.c \
	   src/wn_msg.c src/wn_keyschedule.c src/wn_record.c src/wn_session.c \
	   tests/wn_host_seed.c tests/session_test.c -o $(BUILD)/session_test
	@echo "---- run ----"
	@./$(BUILD)/session_test

rfctest: ## build + run RFC 8448 section 3 record-key KATs (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(KS_SRC) tests/rfc8448_test.c -o $(BUILD)/rfc8448_test
	@echo "---- run ----"
	@./$(BUILD)/rfc8448_test

tstest: ## build + run the transcript-hash tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(TS_SRC) tests/transcript_test.c -o $(BUILD)/transcript_test
	@echo "---- run ----"
	@./$(BUILD)/transcript_test

rectest: ## build + run the record-protection tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(REC_SRC) tests/record_test.c -o $(BUILD)/record_test
	@echo "---- run ----"
	@./$(BUILD)/record_test

ksharetest: ## build + run the X25519 key-share tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(KSH_SRC) tests/keyshare_test.c -o $(BUILD)/keyshare_test
	@echo "---- run ----"
	@./$(BUILD)/keyshare_test

hstest: ## build + run the end-to-end crypto handshake (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(HS_SRC) tests/handshake_crypto_test.c -o $(BUILD)/handshake_crypto_test
	@echo "---- run ----"
	@./$(BUILD)/handshake_crypto_test

alloctrap: ## runtime proof: handshake crypto path makes zero heap calls (GNU ld)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc \
	   $(HS_SRC) tests/malloc_trap.c tests/malloc_trap_test.c \
	   -o $(BUILD)/malloc_trap_test
	@echo "---- run ----"
	@./$(BUILD)/malloc_trap_test

wctest: ## run wolfSSL's wolfcrypt test against the floor (config-trimmed)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) -DNO_MAIN_DRIVER -DWOLFNANO_TARGET_PORTABLE_C \
	   $(WCT_SRC) tests/wolfcrypt_test_main.c -o $(BUILD)/wctest
	@echo "---- run ----"
	@./$(BUILD)/wctest > $(BUILD)/wctest.out 2>&1; \
	  echo "  $$(grep -c 'test passed' $(BUILD)/wctest.out) wolfSSL KAT sub-tests passed; $$(tail -1 $(BUILD)/wctest.out)"

wctestpqc: ## run wolfSSL's wolfcrypt KATs incl. ML-KEM/ML-DSA (lifted from wolfSSL)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) -DNO_MAIN_DRIVER -DWOLFNANO_TARGET_PORTABLE_C \
	   -DWOLFNANO_MLKEM -DWOLFNANO_MLDSA -DWOLFNANO_MLDSA_SIGN -DWOLFNANO_ALLOW_MALLOC \
	   $(WCTPQC_SRC) tests/wolfcrypt_test_main.c -o $(BUILD)/wctestpqc
	@echo "---- run ----"
	@./$(BUILD)/wctestpqc > $(BUILD)/wctestpqc.out 2>&1; \
	  echo "  $$(grep -c 'test passed' $(BUILD)/wctestpqc.out) wolfSSL KAT sub-tests passed (incl. ML-KEM/ML-DSA); $$(tail -1 $(BUILD)/wctestpqc.out)"

msgtest: ## build + run the wire encode/decode primitive tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   src/wn_msg.c tests/msg_test.c -o $(BUILD)/msg_test
	@echo "---- run ----"
	@./$(BUILD)/msg_test

chtest: ## build + run the ClientHello encoder test (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   src/wn_msg.c src/wn_clienthello.c \
	   tests/clienthello_test.c -o $(BUILD)/clienthello_test
	@echo "---- run ----"
	@./$(BUILD)/clienthello_test

shtest: ## build + run the ServerHello parser test (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   src/wn_msg.c src/wn_serverhello.c \
	   tests/serverhello_test.c -o $(BUILD)/serverhello_test
	@echo "---- run ----"
	@./$(BUILD)/serverhello_test

negtest: ## build + run negative/malformed parser tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   src/wn_msg.c src/wn_serverhello.c \
	   tests/parser_negative_test.c -o $(BUILD)/parser_negative_test
	@echo "---- run ----"
	@./$(BUILD)/parser_negative_test

flighttest: ## build + run the adversarial encrypted-flight ordering tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   tests/flight_order_test.c -o $(BUILD)/flight_order_test
	@echo "---- run ----"
	@./$(BUILD)/flight_order_test

alerttest: ## build + run the error->alert (RFC 8446 6.2) mapping tests (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   tests/alert_map_test.c -o $(BUILD)/alert_map_test
	@echo "---- run ----"
	@./$(BUILD)/alert_map_test

matrixtest: ## build + run the data-driven negotiation matrix (PORTABLE_C)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   src/wn_msg.c src/wn_serverhello.c \
	   tests/suites_matrix.c -o $(BUILD)/suites_matrix
	@echo "---- run ----"
	@./$(BUILD)/suites_matrix

FUZZ_TIME ?= 60
FUZZ_CC ?= clang
fuzz: ## coverage-guided fuzz of the wire parsers (clang libFuzzer + ASan)
	@mkdir -p $(BUILD)/corp_sh $(BUILD)/corp_msg $(BUILD)/corp_rec $(BUILD)/corp_x509
	$(FUZZ_CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   -fsanitize=fuzzer,address,undefined -g \
	   src/wn_x509.c tests/fuzz_x509.c -o $(BUILD)/fuzz_x509
	$(FUZZ_CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   -fsanitize=fuzzer,address -g \
	   src/wn_msg.c src/wn_serverhello.c tests/fuzz_serverhello.c \
	   -o $(BUILD)/fuzz_serverhello
	$(FUZZ_CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   -fsanitize=fuzzer,address -g \
	   src/wn_msg.c tests/fuzz_msg.c -o $(BUILD)/fuzz_msg
	$(FUZZ_CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   -fsanitize=fuzzer,address -g \
	   $(WC)/wc_port.c $(WC)/memory.c $(WC)/error.c $(WC)/hash.c $(WC)/logging.c \
	   $(WC)/random.c $(WC)/sha256.c $(WC)/sha512.c $(WC)/aes.c src/wn_record.c \
	   tests/wn_host_seed.c tests/fuzz_record.c -o $(BUILD)/fuzz_record
	@echo "---- run ($(FUZZ_TIME)s each) ----"
	@./$(BUILD)/fuzz_x509       -max_total_time=$(FUZZ_TIME) -timeout=10 $(BUILD)/corp_x509
	@./$(BUILD)/fuzz_serverhello -max_total_time=$(FUZZ_TIME) -timeout=10 $(BUILD)/corp_sh
	@./$(BUILD)/fuzz_msg        -max_total_time=$(FUZZ_TIME) -timeout=10 $(BUILD)/corp_msg
	@./$(BUILD)/fuzz_record     -max_total_time=$(FUZZ_TIME) -timeout=10 $(BUILD)/corp_rec

mlkemtest: ## build + run the ML-KEM-768 KEM test (WOLFNANO_MLKEM)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) -DWOLFNANO_MLKEM -DWOLFNANO_TARGET_PORTABLE_C \
	   $(MLKEM_SRC) tests/mlkem_test.c -o $(BUILD)/mlkem_test
	@echo "---- run ----"
	@./$(BUILD)/mlkem_test

mldsatest: ## build + run ML-DSA-65 round-trip + verify-only no-malloc proof
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) -DWOLFNANO_MLDSA -DWOLFNANO_MLDSA_SIGN \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(MLDSA_SRC) tests/mldsa_test.c -o $(BUILD)/mldsa_test
	@echo "---- run (sign/verify round-trip) ----"
	@./$(BUILD)/mldsa_test
	@echo "---- verify-only no-malloc proof ----"
	@cc $(CFLAGS_COMMON) -DWOLFNANO_MLDSA -DWOLFNANO_TARGET_PORTABLE_C \
	   -c $(WC)/wc_mldsa.c -o $(BUILD)/wc_mldsa_vo.o 2>/dev/null
	@if nm $(BUILD)/wc_mldsa_vo.o | grep -E ' U _(malloc|calloc|realloc|free)$$'; \
	 then echo "  FAIL: verify-only references heap"; exit 1; \
	 else echo "  PASS: verify-only ML-DSA is allocation-free"; fi

certmldsatest: ## build + run the ML-DSA CertificateVerify test at each level (44/65/87)
	@mkdir -p $(BUILD)
	@for lvl in 2 3 5; do \
	   echo "---- ML-DSA level $$lvl ----"; \
	   $(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 \
	      -DWOLFNANO_HAVE_RSA_VERIFY -DWOLFNANO_MLDSA -DWOLFNANO_MLDSA_SIGN \
	      -DWOLFNANO_MLDSA_LEVEL=$$lvl $(X509_BACKEND_FLAG) \
	      -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	      $(CERTMLDSA_SRC) $(X509_BACKEND_SRC) tests/cert_mldsa_test.c \
	      -o $(BUILD)/cert_mldsa_test || exit 1; \
	   ./$(BUILD)/cert_mldsa_test || exit 1; \
	 done

certnegtest: ## build + run X.509 negative auth tests (chain + hostname + ECDSA CertVerify)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 $(X509_BACKEND_FLAG) \
	   -DWOLFNANO_HAVE_RSA_VERIFY -DWOLFNANO_RSA_FULL \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CERTMLDSA_SRC) $(X509_BACKEND_SRC) tests/cert_neg_test.c \
	   -o $(BUILD)/cert_neg_test
	@echo "---- run ----"
	@./$(BUILD)/cert_neg_test

certgentest: ## build + run generated-PKI chain-constraint tests (CA flag, keyUsage, EKU)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 $(X509_BACKEND_FLAG) \
	   -DWOLFNANO_HAVE_RSA_VERIFY -DWOLFNANO_RSA_FULL \
	   -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT -DWOLFSSL_KEY_GEN \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CERTMLDSA_SRC) $(X509_BACKEND_SRC) tests/cert_gen_test.c \
	   -o $(BUILD)/cert_gen_test
	@echo "---- run ----"
	@./$(BUILD)/cert_gen_test

certnegpintest: ## build + run the key-pin-only cert tier (WOLFNANO_X509_HOSTNAME=0)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 $(X509_BACKEND_FLAG) \
	   -DWOLFNANO_X509_HOSTNAME=0 -DWOLFNANO_HAVE_RSA_VERIFY -DWOLFNANO_RSA_FULL \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CERTMLDSA_SRC) $(X509_BACKEND_SRC) tests/cert_neg_test.c \
	   -o $(BUILD)/cert_neg_pin_test
	@echo "---- run ----"
	@./$(BUILD)/cert_neg_pin_test

hybridtest: ## build + run the X25519MLKEM768 hybrid key-share test
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_MLKEM -DWOLFNANO_TARGET_PORTABLE_C \
	   $(HYBRID_SRC) tests/hybrid_test.c -o $(BUILD)/hybrid_test
	@echo "---- run ----"
	@./$(BUILD)/hybrid_test

certtest: ## build + run the X.509 cert-verify test (ECC + RSA; needs heap)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) -DWOLFNANO_X509 -DWOLFNANO_HAVE_RSA_VERIFY \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CERT_SRC) $(WC)/rsa.c tests/cert_test.c -o $(BUILD)/cert_test
	@echo "---- run ----"
	@./$(BUILD)/cert_test

x509diff: ## differential-test wn_x509 vs wolfSSL wc_ParseCert over embedded certs
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 -DWOLFNANO_X509_HOSTNAME \
	   -DWOLFNANO_HAVE_RSA_VERIFY \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CERT_SRC) src/wn_x509.c $(WC)/rsa.c tests/x509_wolfssl_diff.c \
	   -o $(BUILD)/x509_wolfssl_diff
	@echo "---- run ----"
	@./$(BUILD)/x509_wolfssl_diff

x509negtest: ## negative/adversarial wn_x509 tests (crit-unknown, inner!=outer, truncation)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 -DWOLFNANO_X509_HOSTNAME \
	   -DWOLFNANO_HAVE_RSA_VERIFY \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CERT_SRC) src/wn_x509.c $(WC)/rsa.c tests/x509_neg_test.c \
	   -o $(BUILD)/x509_neg_test
	@echo "---- run ----"
	@./$(BUILD)/x509_neg_test

x509verifytest: ## wn_X509_VerifySignedBy + TimeValid (chain verify vs wolfSSL, tamper reject)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 -DWOLFNANO_X509_HOSTNAME \
	   -DWOLFNANO_HAVE_RSA_VERIFY \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CERT_SRC) src/wn_x509.c $(WC)/rsa.c \
	   tests/x509_verify_test.c -o $(BUILD)/x509_verify_test
	@echo "---- run ----"
	@./$(BUILD)/x509_verify_test

x509covtest: ## wn_x509 coverage: feature certs (RSA-SHA384/512, crit EKU/SAN, 2-byte KU) + Ed sweep + NULL args
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 -DWOLFNANO_X509_HOSTNAME \
	   -DWOLFNANO_HAVE_RSA_VERIFY \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CERT_SRC) src/wn_x509.c $(WC)/rsa.c \
	   tests/x509_cov_test.c -o $(BUILD)/x509_cov_test
	@echo "---- run ----"
	@./$(BUILD)/x509_cov_test

x509negvectest: ## wn_x509 vs wolfSSL on malformed cert vectors (lifted from wolfSSL certs/test)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 -DWOLFNANO_X509_HOSTNAME \
	   -DWOLFNANO_HAVE_RSA_VERIFY \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CERT_SRC) src/wn_x509.c $(WC)/rsa.c tests/x509_negvec_test.c \
	   -o $(BUILD)/x509_negvec_test
	@echo "---- run ----"
	@./$(BUILD)/x509_negvec_test

x509probetest: example-x509probe ## run the wn_x509 probe over captured real-world chains (deterministic; live any-endpoint via examples/x509-probe.sh)
	@echo "---- wn_x509 probe: captured real-world chains ----"
	@./$(BUILD)/example_x509_probe tests/pki/live/ecdsa_p256_leaf.der tests/pki/live/ecdsa_p256_int1.der tests/pki/live/ecdsa_p256_int2.der
	@./$(BUILD)/example_x509_probe tests/pki/live/ecdsa_p384_leaf.der tests/pki/live/ecdsa_p384_int1.der
	@./$(BUILD)/example_x509_probe tests/pki/live/rsa4096_leaf.der tests/pki/live/rsa4096_int1.der
	@echo "x509probe: ALL PASS"

interop: ## live TLS 1.3 PSK handshake vs OpenSSL and wolfSSL
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CONN_SRC) tests/interop_psk_test.c -o $(BUILD)/interop_psk_client
	@echo "== PSK (X25519) vs OpenSSL =="; sh tests/interop_psk.sh
	@echo "== PSK (X25519) vs wolfSSL =="; sh tests/interop_wolfssl.sh
	@echo "== PSK (X25519) vs mbedTLS =="; sh tests/interop_mbedtls.sh
	@echo "== app-data (wn_Send/wn_Recv/wn_Close) vs OpenSSL =="; sh tests/interop_psk_appdata.sh
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_HAVE_ECDHE_P256 \
	   -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CONN_P256_SRC) tests/interop_psk_test.c -o $(BUILD)/interop_psk_p256_client
	@echo "== PSK (P-256) vs OpenSSL =="; CLIENT=$(BUILD)/interop_psk_p256_client sh tests/interop_psk.sh
	@echo "== PSK (P-256) vs wolfSSL =="; CLIENT=$(BUILD)/interop_psk_p256_client sh tests/interop_wolfssl.sh
	@echo "== PSK (P-256) vs mbedTLS =="; CLIENT=$(BUILD)/interop_psk_p256_client sh tests/interop_mbedtls.sh
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_HAVE_MLKEM_HYBRID \
	   -DWOLFNANO_TARGET_PORTABLE_C \
	   $(MOCKHYB_SRC) tests/interop_psk_test.c -o $(BUILD)/interop_psk_hybrid_client
	@echo "== PSK (X25519MLKEM768) vs wolfSSL =="; CLIENT=$(BUILD)/interop_psk_hybrid_client sh tests/interop_wolfssl_hybrid.sh
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 $(X509_BACKEND_FLAG) \
	   -DWOLFNANO_HAVE_RSA_VERIFY \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CONN_CERT_SRC) $(WC)/rsa.c $(X509_BACKEND_SRC) tests/interop_cert_test.c \
	   -o $(BUILD)/interop_cert_client
	@echo "== cert(ECDSA) vs OpenSSL =="; sh tests/interop_cert.sh ecdsa
	@echo "== cert(RSA-PSS) vs OpenSSL =="; sh tests/interop_cert.sh rsa
	@echo "== cert(Ed25519) vs OpenSSL =="; sh tests/interop_cert.sh ed
	@echo "== cert(chain leaf<-inter<-root) vs OpenSSL =="; sh tests/interop_cert.sh chain
	@echo "== cert(ECDSA) vs wolfSSL =="; sh tests/interop_cert_wolfssl.sh ecdsa
	@echo "== cert(RSA-PSS) vs wolfSSL =="; sh tests/interop_cert_wolfssl.sh rsa
	@echo "== cert(Ed25519) vs wolfSSL =="; sh tests/interop_cert_wolfssl.sh ed
	@echo "== cert(chain leaf<-inter<-root) vs wolfSSL =="; sh tests/interop_cert_wolfssl.sh chain

# Build + run the all-algo bench for the active WOLFNANO_ASM arch.
benchrun:
	@mkdir -p $(BUILD)
	$(ASM_CC) $(CFLAGS_COMMON) $(SHELL_INC) $(ASM_FLAGS) \
	   -DWOLFNANO_MLKEM -DWOLFNANO_MLDSA -DWOLFNANO_MLDSA_SIGN \
	   -DWOLFNANO_HAVE_CHACHA -DWOLFNANO_HAVE_RSA_VERIFY -DWOLFNANO_RSA_FULL \
	   -DWOLFNANO_ALLOW_MALLOC \
	   $(WC)/sha3.c $(WC)/wc_mlkem.c $(WC)/wc_mlkem_poly.c $(WC)/wc_mldsa.c \
	   $(WC)/chacha.c $(WC)/poly1305.c $(WC)/chacha20_poly1305.c $(WC)/rsa.c \
	   $(FLOOR_SRC) $(ASM_SRC) $(BENCHASM_$(WOLFNANO_ASM)) \
	   tests/bench_all.c tests/wn_host_seed.c \
	   -o $(BUILD)/bench_$(WOLFNANO_ASM)
	@./$(BUILD)/bench_$(WOLFNANO_ASM)

bench: ## crypto speed, all algos: portable C vs Intel asm side by side
	@$(MAKE) --no-print-directory benchrun WOLFNANO_ASM=none
	@$(MAKE) --no-print-directory benchrun WOLFNANO_ASM=intel

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
	 $$cc $(CFLAGS_COMMON) $$s -DWOLFNANO_TARGET_PORTABLE_C $(FLOOR_SRC) $(WC)/sp_int.c $(TEST_SRC) -o $(BUILD)/qemu-$*/floor && $$q $(BUILD)/qemu-$*/floor; \
	 $$cc $(CFLAGS_COMMON) $$s $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C $(KS_SRC) tests/keyschedule_test.c -o $(BUILD)/qemu-$*/ks && $$q $(BUILD)/qemu-$*/ks; \
	 $$cc $(CFLAGS_COMMON) $$s $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C $(KS_SRC) tests/rfc8448_test.c -o $(BUILD)/qemu-$*/rfc && $$q $(BUILD)/qemu-$*/rfc; \
	 $$cc $(CFLAGS_COMMON) $$s $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C $(HS_SRC) tests/handshake_crypto_test.c -o $(BUILD)/qemu-$*/hs && $$q $(BUILD)/qemu-$*/hs; \
	 $$cc $(CFLAGS_COMMON) $$s $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C src/wn_msg.c src/wn_serverhello.c tests/parser_negative_test.c -o $(BUILD)/qemu-$*/neg && $$q $(BUILD)/qemu-$*/neg; \
	 echo "OK test-qemu-$* (ran under $$q)"

test-qemu: test-qemu-arm test-qemu-aarch64 test-qemu-riscv64 ## run the suites under qemu-user for arm/aarch64/riscv64

example: ## build the minimal PSK client example (examples/client.c)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CONN_SRC) examples/client.c -o $(BUILD)/example_client
	@echo "built $(BUILD)/example_client"

example-cert: ## build the X.509 server-cert client example (examples/client_cert.c)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 $(X509_BACKEND_FLAG) \
	   -DWOLFNANO_HAVE_RSA_VERIFY \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CONN_CERT_SRC) $(WC)/rsa.c $(X509_BACKEND_SRC) examples/client_cert.c \
	   -o $(BUILD)/example_client_cert
	@echo "built $(BUILD)/example_client_cert"

example-cert-lite: ## build the cert client on the native wn_x509 LITE backend (examples/client_cert.c)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 -DWOLFNANO_X509_LITE \
	   -DWOLFNANO_HAVE_RSA_VERIFY \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CONN_CERT_SRC) $(WC)/rsa.c src/wn_x509.c examples/client_cert.c \
	   -o $(BUILD)/example_client_cert_lite
	@echo "built $(BUILD)/example_client_cert_lite"

example-cert-min: ## build the minimal single-curve P-256 cert client (private PKI, anchor-pinned)
	@mkdir -p $(BUILD)/certmin
	@cp configs/user_settings_cert_p256min.h $(BUILD)/certmin/user_settings.h
	$(CC) -I$(BUILD)/certmin $(CFLAGS_COMMON) $(SHELL_INC) \
	   -DWOLFNANO_X509_LITE -DWOLFNANO_ALLOW_MALLOC \
	   -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CONN_CERT_P256MIN_SRC) src/wn_x509.c examples/client_cert_min.c \
	   -o $(BUILD)/example_client_cert_min
	@echo "built $(BUILD)/example_client_cert_min"

example-cert-pqc: ## build the PQC HTTPS client: X25519MLKEM768 hybrid KEX + X.509 cert
	@mkdir -p $(BUILD)/certpqc
	@cp configs/user_settings_cert_pqc.h $(BUILD)/certpqc/user_settings.h
	$(CC) -I$(BUILD)/certpqc $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 $(X509_BACKEND_FLAG) \
	   -DWOLFNANO_HAVE_RSA_VERIFY -DWOLFNANO_HAVE_MLKEM_HYBRID \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CONN_CERT_SRC) $(WC)/rsa.c $(WC)/sha3.c $(WC)/wc_mlkem.c $(WC)/wc_mlkem_poly.c \
	   src/wn_hybrid.c $(X509_BACKEND_SRC) examples/client_cert.c \
	   -o $(BUILD)/example_client_cert_pqc
	@echo "built $(BUILD)/example_client_cert_pqc"

cert-notime-build: ## compile-check the clockless cert tier (WOLFNANO_NO_X509_TIME)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 $(X509_BACKEND_FLAG) \
	   -DWOLFNANO_HAVE_RSA_VERIFY -DWOLFNANO_NO_X509_TIME \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CONN_CERT_SRC) $(WC)/rsa.c $(X509_BACKEND_SRC) examples/client_cert.c \
	   -o $(BUILD)/example_client_cert_notime
	@echo "built $(BUILD)/example_client_cert_notime"

example-https: ## build the live HTTPS client example (examples/client_https.c)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 $(X509_BACKEND_FLAG) \
	   -DWOLFNANO_HAVE_RSA_VERIFY \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CONN_CERT_SRC) $(WC)/rsa.c $(X509_BACKEND_SRC) examples/client_https.c \
	   -o $(BUILD)/example_client_https
	@echo "built $(BUILD)/example_client_https"

example-https-lite: ## build the live HTTPS client on the native wn_x509 LITE backend
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 -DWOLFNANO_X509_LITE \
	   -DWOLFNANO_HAVE_RSA_VERIFY \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CONN_CERT_SRC) $(WC)/rsa.c src/wn_x509.c examples/client_https.c \
	   -o $(BUILD)/example_client_https_lite
	@echo "built $(BUILD)/example_client_https_lite"

example-https-pqc: ## build the PQC HTTPS client: X25519MLKEM768 hybrid KEX, validates a real public chain
	@mkdir -p $(BUILD)/httpspqc
	@cp configs/user_settings_cert_pqc.h $(BUILD)/httpspqc/user_settings.h
	$(CC) -I$(BUILD)/httpspqc $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 -DWOLFNANO_X509_LITE \
	   -DWOLFNANO_HAVE_RSA_VERIFY -DWOLFNANO_HAVE_MLKEM_HYBRID \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CONN_CERT_SRC) $(WC)/rsa.c $(WC)/sha3.c $(WC)/wc_mlkem.c $(WC)/wc_mlkem_poly.c \
	   src/wn_hybrid.c src/wn_x509.c examples/client_https.c \
	   -o $(BUILD)/example_client_https_pqc
	@echo "built $(BUILD)/example_client_https_pqc"

example-x509probe: ## build the wn_x509 cert-chain probe (examples/x509_probe.c); point examples/x509-probe.sh at any endpoint
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_X509 -DWOLFNANO_X509_HOSTNAME \
	   -DWOLFNANO_HAVE_RSA_VERIFY \
	   -DWOLFNANO_ALLOW_MALLOC -DWOLFNANO_TARGET_PORTABLE_C \
	   $(CERT_SRC) src/wn_x509.c $(WC)/rsa.c examples/x509_probe.c \
	   -o $(BUILD)/example_x509_probe
	@echo "built $(BUILD)/example_x509_probe"

example-pqc: ## build the X25519MLKEM768 hybrid PSK client example (examples/client_pqc.c)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(SHELL_INC) -DWOLFNANO_HAVE_MLKEM_HYBRID \
	   -DWOLFNANO_TARGET_PORTABLE_C \
	   $(MOCKHYB_SRC) examples/client_pqc.c -o $(BUILD)/example_client_pqc
	@echo "built $(BUILD)/example_client_pqc"

configs-build: ## compile each configs/ starter template against the shell
	sh scripts/configs_build.sh

m33mu: ## build + run the wolfNanoTLS floor on an emulated Cortex-M33 (STM32H563)
	sh scripts/m33mu_run.sh

STACK_SRC := wn_connect.c wn_session.c wn_record.c wn_keyschedule.c \
  wn_keyshare.c wn_transcript.c wn_msg.c wn_serverhello.c wn_clienthello.c
stackcheck: ## fail if any wolfNanoTLS function exceeds the stack budget (-fstack-usage)
	@mkdir -p $(BUILD)/su
	@for b in $(STACK_SRC); do \
	  $(CC) -Os -fstack-usage -c $(SHELL_INC) -DWOLFSSL_USER_SETTINGS \
	    -DWOLFNANO_TARGET_PORTABLE_C -DWOLFNANO_X509 -DWOLFNANO_HAVE_RSA_VERIFY \
	    -DWOLFNANO_ALLOW_MALLOC -I. -I$(WOLFSSL) src/$$b -o $(BUILD)/su/$${b%.c}.o; \
	done
	@sh scripts/check_stack.sh $(BUILD)/su/*.su

coverage: ## Linux: run the suites under --coverage and enforce 100% (.github/ci/coverage-100.txt)
	@command -v lcov >/dev/null 2>&1 || { echo "SKIP coverage (no lcov; Linux/CI only)"; exit 0; }
	$(MAKE) test EXTRA_CFLAGS="--coverage -O0"
	lcov --capture --directory . --output-file cov.info --rc lcov_branch_coverage=0 2>/dev/null || true
	lcov --remove cov.info '*/wolfssl/*' '/usr/*' '*/tests/*' --output-file cov.info 2>/dev/null || true
	sh scripts/check_coverage.sh cov.info .github/ci/coverage-100.txt
	find . -name '*.gcda' -delete
	$(MAKE) test-x509 test-cert certmldsatest X509_LITE=1 EXTRA_CFLAGS="--coverage -O0"
	lcov --capture --directory . --output-file cov-lite.info --rc lcov_branch_coverage=0 2>/dev/null || true
	lcov --remove cov-lite.info '*/wolfssl/*' '/usr/*' '*/tests/*' --output-file cov-lite.info 2>/dev/null || true
	sh scripts/check_coverage.sh cov-lite.info .github/ci/coverage-100-lite.txt

clean:
	rm -rf $(BUILD) *.o *.gcda *.gcno cov.info cov-lite.info
