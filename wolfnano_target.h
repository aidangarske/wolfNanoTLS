/* wolfnano_target.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfNanoTLS.
 *
 * wolfNanoTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfNanoTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef WOLFNANOTLS_TARGET_H
#define WOLFNANOTLS_TARGET_H

/* One target macro (set by the Makefile from WOLFNANOTLS_ASM=<arch>) selects the
 * whole asm bundle. The default PORTABLE_C path is lightweight generic math
 * (WOLFSSL_SP_MATH_ALL, no asm); every accelerated target opts into the fast
 * specialized SP backend (WOLFSSL_SP_MATH + per-arch SP file) plus the symmetric
 * asm, mirroring wolfSSL --enable-*asm / --enable-sp=yes,asm. Macro/file names
 * locked against wolfssl master 59295869; re-verify on submodule re-pin (R4). */

#if defined(WOLFNANOTLS_TARGET_X86_64)
    /* Intel: AES-NI + AVX1/2 hash + SP x86_64 asm. CPUID-detected at runtime. */
    #define WOLFSSL_AESNI
    #define HAVE_INTEL_AVX1
    #define HAVE_INTEL_AVX2
    #define USE_INTEL_SPEEDUP          /* ML-KEM / ML-DSA AVX2 asm */
    #define WOLFSSL_X86_64_BUILD

    #define WOLFSSL_SP_MATH            /* specialized SP (NOT _ALL) */
    #define WOLFSSL_HAVE_SP_ECC
    #define WOLFSSL_HAVE_SP_RSA
    #define WOLFSSL_SP_X86_64          /* sp_int.c x86_64 inline asm helpers */
    #define WOLFSSL_SP_X86_64_ASM      /* sp_x86_64.c + asm; auto SP_ASM/AVX/64 */

#elif defined(WOLFNANOTLS_TARGET_CORTEXM33)
    /* Thumb2 inline asm (selects thumb2-*-asm_c.c) + SP Cortex-M asm. */
    #define WOLFSSL_ARMASM
    #define WOLFSSL_ARMASM_THUMB2
    #define WOLFSSL_ARMASM_INLINE
    #define WOLFSSL_ARMASM_NO_HW_CRYPTO /* M33 core has no AES/SHA instructions */
    #define WOLFSSL_ARMASM_NO_NEON
    #define WOLFSSL_ARM_ARCH 7

    #define WOLFSSL_SP_MATH
    #define WOLFSSL_HAVE_SP_ECC
    #define WOLFSSL_HAVE_SP_RSA
    #define WOLFSSL_SP_ARM_CORTEX_M_ASM /* sp_cortexm.c; auto SP_ASM */
    #define SP_WORD_SIZE 32
    #define TFM_NO_ASM

#elif defined(WOLFNANOTLS_TARGET_AARCH64)
    /* ARMv8 aarch64: NEON + (optional) crypto-extension AES/SHA + SP arm64 asm. */
    #define WOLFSSL_ARMASM
    #define WOLFSSL_ARMASM_NEON

    #define WOLFSSL_SP_MATH
    #define WOLFSSL_HAVE_SP_ECC
    #define WOLFSSL_HAVE_SP_RSA
    #define WOLFSSL_SP_ARM64_ASM        /* sp_arm64.c; auto SP_ASM/64 */

#elif defined(WOLFNANOTLS_TARGET_ARMV8_32)
    /* 32-bit ARM (ARMv7-a / ARMv8-32): SP arm32 asm + armv8-32 symmetric asm. */
    #define WOLFSSL_ARMASM

    #define WOLFSSL_SP_MATH
    #define WOLFSSL_HAVE_SP_ECC
    #define WOLFSSL_HAVE_SP_RSA
    #define WOLFSSL_SP_ARM32_ASM        /* sp_arm32.c; auto SP_ASM */
    #define SP_WORD_SIZE 32

#elif defined(WOLFNANOTLS_TARGET_RISCV64)
    /* RISC-V 64: scalar symmetric/hash asm only; SP ECC stays portable sp_c64.c. */
    #define WOLFSSL_RISCV_ASM

    #define WOLFSSL_SP_MATH
    #define WOLFSSL_HAVE_SP_ECC
    #define WOLFSSL_HAVE_SP_RSA
    #define SP_WORD_SIZE 64

#elif defined(WOLFNANOTLS_TARGET_PORTABLE_C)
    /* pure C, no asm: lightweight default + CI baseline (generic SP math). */
    #define WOLFSSL_SP_MATH_ALL

#else
    #error "Define a WOLFNANOTLS_TARGET_* (set via WOLFNANOTLS_ASM=<arch> in the Makefile)"
#endif

/* Specialized SP backends implement P-256 by default; P-384 is opt-in. The
 * generic WOLFSSL_SP_MATH_ALL path (PORTABLE_C) covers all sizes already. */
#if defined(WOLFSSL_HAVE_SP_ECC) && !defined(WOLFSSL_SP_MATH_ALL)
    #define WOLFSSL_SP_384
#endif

#endif /* WOLFNANOTLS_TARGET_H */
