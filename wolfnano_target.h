/* wolfnano_target.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfNano.
 *
 * wolfNano is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfNano is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef WOLFNANO_TARGET_H
#define WOLFNANO_TARGET_H

/* One target macro selects the whole asm bundle.
 *
 * Active target: PORTABLE_C (local mac/linux testing). The hardware/asm target
 * below is DEFERRED and not built yet; it is kept only as the verified record
 * of the asm macro/file names (locked against wolfssl master 59295869,
 * re-verify on submodule re-pin) for when hardware work begins. */

#if defined(WOLFNANO_TARGET_CORTEXM33) /* deferred: hardware target, not built yet */
    /* symmetric + hash: Thumb2 inline asm (selects thumb2-*-asm_c.c) */
    #define WOLFSSL_ARMASM
    #define WOLFSSL_ARMASM_THUMB2
    #define WOLFSSL_ARMASM_INLINE
    #define WOLFSSL_ARMASM_NO_HW_CRYPTO /* M33 core has no AES/SHA instructions */
    #define WOLFSSL_ARMASM_NO_NEON
    #define WOLFSSL_ARM_ARCH 7

    /* public-key: SP Cortex-M asm (sp_cortexm.c) */
    #define WOLFSSL_SP_MATH_ALL
    #define WOLFSSL_HAVE_SP_ECC
    #define WOLFSSL_SP_ASM
    #define WOLFSSL_SP_ARM_CORTEX_M_ASM
    #define SP_WORD_SIZE 32
    #define TFM_NO_ASM

#elif defined(WOLFNANO_TARGET_PORTABLE_C)
    /* pure C, no asm: reference + CI baseline */
    #define WOLFSSL_SP_MATH_ALL

#else
    #error "Define a WOLFNANO_TARGET_* (e.g. WOLFNANO_TARGET_CORTEXM33)"
#endif

#endif /* WOLFNANO_TARGET_H */
