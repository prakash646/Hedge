/* Cycle attribution (see prof.c). SPDX-License-Identifier: MIT */
#ifndef HEDGE_PROF_H
#define HEDGE_PROF_H
#include <stdint.h>

enum { PS_OTHER, PS_XWING, PS_HSTAR, PS_KDF, PS_COMB, PROF_NSCOPE };
enum { PP_TOTAL, PP_MLKEM, PP_X25519, PP_SHA3, PP_ASCON, PP_ROMULUS, PROF_NPRIM };

extern uint64_t prof_cyc[PROF_NSCOPE][PROF_NPRIM];
extern uint32_t prof_calls[PROF_NSCOPE][PROF_NPRIM];
extern int prof_on;
void prof_reset(void);

#define PROF_WRAP_FLAGS \
  -Wl,--wrap=xwing_encaps_derand -Wl,--wrap=hedge_hstar -Wl,--wrap=hedge_kdf \
  -Wl,--wrap=hedge_comb_encrypt -Wl,--wrap=mlkem_enc_derand -Wl,--wrap=crypto_x25519 \
  -Wl,--wrap=crypto_x25519_public_key -Wl,--wrap=sha3_init -Wl,--wrap=sha3_update \
  -Wl,--wrap=sha3_final -Wl,--wrap=shake_xof -Wl,--wrap=shake_out \
  -Wl,--wrap=ascon_hash256 -Wl,--wrap=ascon_cxof128 \
  -Wl,--wrap=hedge_ascon_encrypt -Wl,--wrap=hedge_romulus_encrypt
#endif
