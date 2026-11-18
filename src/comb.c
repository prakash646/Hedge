/* Tidy-cascade AEAD combiner:
 *   Enc: C1 = Romulus-N.Enc(k_in, N, A, M);  C = Ascon-AEAD128.Enc(k_out, N, A, C1)
 *   Dec: C1 = Ascon-AEAD128.Dec(k_out, N, A, C) or reject;  M = Romulus-N.Dec(k_in, N, A, C1)
 * No re-encryption check: Ascon-AEAD128 (the outer component) is tidy.
 * SPDX-License-Identifier: MIT */
#include <string.h>
#include "hedge.h"

#ifndef HEDGE_UNHEDGED
int hedge_comb_encrypt(uint8_t *c, const hedge_comb_key *k,
                       const uint8_t n[HEDGE_NONCE_BYTES],
                       const uint8_t *ad, size_t adlen,
                       const uint8_t *m, size_t mlen)
{
    uint8_t c1[HEDGE_COMB_MAX_MSG + HEDGE_TAG_BYTES];
    int r = -1;
    if (mlen > HEDGE_COMB_MAX_MSG) return -1;
    if (hedge_romulus_encrypt(c1, k->k_in, n, ad, adlen, m, mlen) != 0) goto out;
    if (hedge_ascon_encrypt(c, k->k_out, n, ad, adlen, c1, mlen + HEDGE_TAG_BYTES) != 0) goto out;
    r = 0;
out:
    hedge_wipe(c1, sizeof c1);
    return r;
}

int hedge_comb_decrypt(uint8_t *m, const hedge_comb_key *k,
                       const uint8_t n[HEDGE_NONCE_BYTES],
                       const uint8_t *ad, size_t adlen,
                       const uint8_t *c, size_t clen)
{
    uint8_t c1[HEDGE_COMB_MAX_MSG + HEDGE_TAG_BYTES];
    int r = -1;
    if (clen < HEDGE_COMB_OVERHEAD || clen - HEDGE_COMB_OVERHEAD > HEDGE_COMB_MAX_MSG) return -1;
    /* Outer layer first: forged records are rejected after one Ascon pass. */
    if (hedge_ascon_decrypt(c1, k->k_out, n, ad, adlen, c, clen) != 0) goto fail;
    if (hedge_romulus_decrypt(m, k->k_in, n, ad, adlen, c1, clen - HEDGE_TAG_BYTES) != 0) goto fail;
    r = 0;
    goto out;
fail:
    memset(m, 0, clen - HEDGE_COMB_OVERHEAD);
out:
    hedge_wipe(c1, sizeof c1);
    return r;
}

#else /* HEDGE_UNHEDGED baseline: Ascon-AEAD128 alone (k_in unused) */
int hedge_comb_encrypt(uint8_t *c, const hedge_comb_key *k, const uint8_t n[HEDGE_NONCE_BYTES],
                       const uint8_t *ad, size_t adlen, const uint8_t *m, size_t mlen)
{
    if (mlen > HEDGE_COMB_MAX_MSG) return -1;
    return hedge_ascon_encrypt(c, k->k_out, n, ad, adlen, m, mlen);
}
int hedge_comb_decrypt(uint8_t *m, const hedge_comb_key *k, const uint8_t n[HEDGE_NONCE_BYTES],
                       const uint8_t *ad, size_t adlen, const uint8_t *c, size_t clen)
{
    if (clen < HEDGE_COMB_OVERHEAD || clen - HEDGE_COMB_OVERHEAD > HEDGE_COMB_MAX_MSG) return -1;
    if (hedge_ascon_decrypt(m, k->k_out, n, ad, adlen, c, clen) != 0) {
        memset(m, 0, clen - HEDGE_COMB_OVERHEAD);
        return -1;
    }
    return 0;
}
#endif

static void record_nonce(uint8_t n[16], const uint8_t iv[16], uint64_t seq)
{
    memcpy(n, iv, 16);
    for (int i = 0; i < 8; i++) n[15 - i] ^= (uint8_t)(seq >> (8 * i));
}

int hedge_record_seal(uint8_t *c, const hedge_comb_key *k, const uint8_t iv[16],
                      uint64_t seq, const uint8_t *ad, size_t adlen,
                      const uint8_t *m, size_t mlen)
{
    uint8_t n[16];
    record_nonce(n, iv, seq);
    return hedge_comb_encrypt(c, k, n, ad, adlen, m, mlen);
}

int hedge_record_open(uint8_t *m, const hedge_comb_key *k, const uint8_t iv[16],
                      uint64_t seq, const uint8_t *ad, size_t adlen,
                      const uint8_t *c, size_t clen)
{
    uint8_t n[16];
    record_nonce(n, iv, seq);
    return hedge_comb_decrypt(m, k, n, ad, adlen, c, clen);
}
