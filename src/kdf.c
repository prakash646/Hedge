/* Hash and KDF combiners.
 *   H*(x)            = SHAKE256(x, 32) || Ascon-Hash256(x)                (concatenation: CR if either is)
 *   KDF(ikm,l,ctx,L) = SHAKE256(<l,ctx,ikm>, L) XOR Ascon-CXOF128(<ctx,ikm>, L; Z = l)
 *                                                                         (XOR: PRF/KDF if either is)
 * <a,b,...> = concatenation of 2-byte big-endian length || field.
 * SPDX-License-Identifier: MIT */
#include <string.h>
#include "hedge.h"
#include "sha3.h"

/* Renamed at compile time (see CMakeLists.txt). */
int ascon_hash256(unsigned char *out, const unsigned char *in, unsigned long long inlen);
int ascon_cxof128(unsigned char *out, unsigned long long outlen,
                  const unsigned char *in, unsigned long long inlen,
                  const unsigned char *cs, unsigned long long cslen);

/* Ascon reference code is one-shot, so inputs are assembled in a buffer.
 * Largest H* input in the handshake: M1||M2 = 1256 bytes. */
#define HSTAR_MAX_INPUT 1600
#define KDF_MAX_INPUT   256
#define KDF_MAX_OUTPUT  128

#ifndef HEDGE_UNHEDGED
int hedge_hstar(uint8_t out[HEDGE_TH_BYTES], const hedge_seg *segs, size_t nsegs)
{
    uint8_t buf[HSTAR_MAX_INPUT];
    size_t len = 0;
    sha3_ctx_t ctx;

    shake256_init(&ctx);
    for (size_t i = 0; i < nsegs; i++) {
        if (len + segs[i].len > sizeof buf) return -1;
        shake_update(&ctx, segs[i].p, segs[i].len);
        memcpy(buf + len, segs[i].p, segs[i].len);
        len += segs[i].len;
    }
    shake_xof(&ctx);
    shake_out(&ctx, out, 32);
    if (ascon_hash256(out + 32, buf, len) != 0) return -1;
    hedge_wipe(buf, len);
    return 0;
}

#endif /* !HEDGE_UNHEDGED (H*) */
static size_t put_field(uint8_t *dst, const uint8_t *p, size_t n)
{
    dst[0] = (uint8_t)(n >> 8);
    dst[1] = (uint8_t)n;
    if (n) memcpy(dst + 2, p, n);
    return n + 2;
}

#ifndef HEDGE_UNHEDGED
int hedge_kdf(uint8_t *out, size_t outlen,
              const uint8_t *ikm, size_t ikmlen,
              const char *label,
              const uint8_t *ctx, size_t ctxlen)
{
    uint8_t in1[KDF_MAX_INPUT], in2[KDF_MAX_INPUT], t[KDF_MAX_OUTPUT];
    size_t llen = strlen(label), n1 = 0, n2 = 0;
    sha3_ctx_t sc;

    if (outlen > KDF_MAX_OUTPUT || llen + ctxlen + ikmlen + 6 > KDF_MAX_INPUT) return -1;

    /* X1 = SHAKE256(<label, ctx, ikm>) */
    n1 += put_field(in1 + n1, (const uint8_t *)label, llen);
    n1 += put_field(in1 + n1, ctx, ctxlen);
    n1 += put_field(in1 + n1, ikm, ikmlen);
    shake256_init(&sc);
    shake_update(&sc, in1, n1);
    shake_xof(&sc);
    shake_out(&sc, out, outlen);

    /* X2 = Ascon-CXOF128(<ctx, ikm>; Z = label) */
    n2 += put_field(in2 + n2, ctx, ctxlen);
    n2 += put_field(in2 + n2, ikm, ikmlen);
    if (ascon_cxof128(t, outlen, in2, n2, (const uint8_t *)label, llen) != 0) return -1;
    for (size_t i = 0; i < outlen; i++) out[i] ^= t[i];

    hedge_wipe(in1, sizeof in1);
    hedge_wipe(in2, sizeof in2);
    hedge_wipe(t, sizeof t);
    hedge_wipe(&sc, sizeof sc);
    return 0;
}
#else /* HEDGE_UNHEDGED baseline: Ascon only, same input encodings */
int hedge_hstar(uint8_t out[HEDGE_TH_BYTES], const hedge_seg *segs, size_t nsegs)
{
    uint8_t buf[HSTAR_MAX_INPUT];
    size_t len = 0;
    for (size_t i = 0; i < nsegs; i++) {
        if (len + segs[i].len > sizeof buf) return -1;
        memcpy(buf + len, segs[i].p, segs[i].len);
        len += segs[i].len;
    }
    if (ascon_hash256(out, buf, len) != 0) return -1;
    hedge_wipe(buf, len);
    return 0;
}
int hedge_kdf(uint8_t *out, size_t outlen, const uint8_t *ikm, size_t ikmlen,
              const char *label, const uint8_t *ctx, size_t ctxlen)
{
    uint8_t in2[KDF_MAX_INPUT];
    size_t llen = strlen(label), n2 = 0;
    if (outlen > KDF_MAX_OUTPUT || llen + ctxlen + ikmlen + 6 > KDF_MAX_INPUT) return -1;
    n2 += put_field(in2 + n2, ctx, ctxlen);
    n2 += put_field(in2 + n2, ikm, ikmlen);
    if (ascon_cxof128(out, outlen, in2, n2, (const uint8_t *)label, llen) != 0) return -1;
    hedge_wipe(in2, sizeof in2);
    return 0;
}
#endif
