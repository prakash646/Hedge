/* Thin wrappers over the vendored Ascon (ascon-c ref) and Romulus-N
 * (rweather/lwc-finalists) implementations, plus small utilities.
 * SPDX-License-Identifier: MIT */
#include <string.h>
#include "hedge.h"
#include "romulus-n-aead.h"
#include "monocypher.h"

/* Renamed at compile time from crypto_aead_encrypt / crypto_aead_decrypt
 * of vendor/ascon/aead128 (see CMakeLists.txt). */
int ascon_aead128_encrypt(unsigned char *c, unsigned long long *clen,
                          const unsigned char *m, unsigned long long mlen,
                          const unsigned char *ad, unsigned long long adlen,
                          const unsigned char *nsec, const unsigned char *npub,
                          const unsigned char *k);
int ascon_aead128_decrypt(unsigned char *m, unsigned long long *mlen,
                          unsigned char *nsec, const unsigned char *c,
                          unsigned long long clen, const unsigned char *ad,
                          unsigned long long adlen, const unsigned char *npub,
                          const unsigned char *k);

int hedge_ascon_encrypt(uint8_t *c, const uint8_t k[16], const uint8_t n[16],
                        const uint8_t *ad, size_t adlen,
                        const uint8_t *m, size_t mlen)
{
    unsigned long long clen = 0;
    if (ascon_aead128_encrypt(c, &clen, m, mlen, ad, adlen, NULL, n, k) != 0)
        return -1;
    return (clen == mlen + HEDGE_TAG_BYTES) ? 0 : -1;
}

int hedge_ascon_decrypt(uint8_t *m, const uint8_t k[16], const uint8_t n[16],
                        const uint8_t *ad, size_t adlen,
                        const uint8_t *c, size_t clen)
{
    unsigned long long mlen = 0;
    if (clen < HEDGE_TAG_BYTES) return -1;
    int v = ascon_aead128_decrypt(m, &mlen, NULL, c, clen, ad, adlen, n, k);
    HEDGE_DECLASSIFY(&v, sizeof v);                 /* accept/reject is public */
    if (v != 0)
        return -1;
    return (mlen == clen - HEDGE_TAG_BYTES) ? 0 : -1;
}

int hedge_romulus_encrypt(uint8_t *c, const uint8_t k[16], const uint8_t n[16],
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *m, size_t mlen)
{
    size_t clen = 0;
    if (romulus_n_aead_encrypt(c, &clen, m, mlen, ad, adlen, n, k) != 0)
        return -1;
    return (clen == mlen + HEDGE_TAG_BYTES) ? 0 : -1;
}

int hedge_romulus_decrypt(uint8_t *m, const uint8_t k[16], const uint8_t n[16],
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *c, size_t clen)
{
    size_t mlen = 0;
    if (clen < HEDGE_TAG_BYTES) return -1;
    int v = romulus_n_aead_decrypt(m, &mlen, c, clen, ad, adlen, n, k);
    HEDGE_DECLASSIFY(&v, sizeof v);                 /* accept/reject is public */
    if (v != 0)
        return -1;
    return (mlen == clen - HEDGE_TAG_BYTES) ? 0 : -1;
}

void hedge_wipe(void *p, size_t n) { crypto_wipe(p, n); }

int hedge_ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    /* constant-time: d == 0 -> 1 */
    return (int)(1u & (((uint32_t)d - 1u) >> 8));
}
