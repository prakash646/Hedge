/* X-Wing hybrid KEM (Barbosa et al., IACR CiC 2024; draft-connolly-cfrg-xwing-kem),
 * built from mlkem-native (ML-KEM-768), Monocypher (X25519) and tiny_sha3 (SHA3-256, SHAKE256).
 * Follows spec/xwing.py of the draft repository line by line.
 * SPDX-License-Identifier: MIT */
#include <string.h>
#include "hedge.h"
#include "sha3.h"
#include "monocypher.h"
#include "mlkem_native.h"

#ifndef HEDGE_UNHEDGED
#define MLKEM_PK 1184
#define MLKEM_SK 2400
#define MLKEM_CT 1088

static const uint8_t XWING_LABEL[6] = { 0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c }; /* "\./" "/^\" */

static int expand(uint8_t skM[MLKEM_SK], uint8_t skX[32],
                  uint8_t pkM[MLKEM_PK], uint8_t pkX[32], const uint8_t seed[32])
{
    uint8_t ex[96];
    sha3_ctx_t c;
    shake256_init(&c);
    shake_update(&c, seed, 32);
    shake_xof(&c);
    shake_out(&c, ex, sizeof ex);
    if (mlkem_keypair_derand(pkM, skM, ex) != 0) { hedge_wipe(ex, sizeof ex); return -1; }
    memcpy(skX, ex + 64, 32);
    crypto_x25519_public_key(pkX, skX);
    hedge_wipe(ex, sizeof ex);
    hedge_wipe(&c, sizeof c);
    return 0;
}

static void combiner(uint8_t ss[32], const uint8_t ssM[32], const uint8_t ssX[32],
                     const uint8_t ctX[32], const uint8_t pkX[32])
{
    sha3_ctx_t c;
    sha3_init(&c, 32);
    sha3_update(&c, ssM, 32);
    sha3_update(&c, ssX, 32);
    sha3_update(&c, ctX, 32);
    sha3_update(&c, pkX, 32);
    sha3_update(&c, XWING_LABEL, sizeof XWING_LABEL);
    sha3_final(ss, &c);
}

int xwing_keygen_derand(uint8_t pk[XWING_PK_BYTES], uint8_t sk[XWING_SK_BYTES],
                        const uint8_t seed[XWING_KGSEED_BYTES])
{
    uint8_t skM[MLKEM_SK], skX[32];
    int r = expand(skM, skX, pk, pk + MLKEM_PK, seed);
    if (r == 0) memcpy(sk, seed, 32);
    hedge_wipe(skM, sizeof skM);
    hedge_wipe(skX, sizeof skX);
    return r;
}

int xwing_keygen(uint8_t pk[XWING_PK_BYTES], uint8_t sk[XWING_SK_BYTES])
{
    uint8_t seed[32];
    int r;
    if (hedge_randombytes(seed, sizeof seed) != 0) return -1;
    r = xwing_keygen_derand(pk, sk, seed);
    hedge_wipe(seed, sizeof seed);
    return r;
}

int xwing_encaps_derand(uint8_t ct[XWING_CT_BYTES], uint8_t ss[XWING_SS_BYTES],
                        const uint8_t pk[XWING_PK_BYTES],
                        const uint8_t eseed[XWING_ESEED_BYTES])
{
    const uint8_t *pkM = pk, *pkX = pk + MLKEM_PK;
    const uint8_t *ekX = eseed + 32;
    uint8_t ssX[32], ssM[32];
    uint8_t *ctX = ct + MLKEM_CT;

    crypto_x25519_public_key(ctX, ekX);
    crypto_x25519(ssX, ekX, pkX);
    if (mlkem_enc_derand(ct, ssM, pkM, eseed) != 0) {
        hedge_wipe(ssX, 32);
        return -1;
    }
    combiner(ss, ssM, ssX, ctX, pkX);
    hedge_wipe(ssX, 32);
    hedge_wipe(ssM, 32);
    return 0;
}

int xwing_encaps(uint8_t ct[XWING_CT_BYTES], uint8_t ss[XWING_SS_BYTES],
                 const uint8_t pk[XWING_PK_BYTES])
{
    uint8_t eseed[XWING_ESEED_BYTES];
    int r;
    if (hedge_randombytes(eseed, sizeof eseed) != 0) return -1;
    r = xwing_encaps_derand(ct, ss, pk, eseed);
    hedge_wipe(eseed, sizeof eseed);
    return r;
}

int xwing_decaps(uint8_t ss[XWING_SS_BYTES], const uint8_t ct[XWING_CT_BYTES],
                 const uint8_t sk[XWING_SK_BYTES])
{
    uint8_t skM[MLKEM_SK], skX[32], pkM[MLKEM_PK], pkX[32], ssM[32], ssX[32];
    const uint8_t *ctX = ct + MLKEM_CT;
    int r = -1;
    if (expand(skM, skX, pkM, pkX, sk) != 0) goto out;
    if (mlkem_dec(ssM, ct, skM) != 0) goto out;
    crypto_x25519(ssX, skX, ctX);
    combiner(ss, ssM, ssX, ctX, pkX);
    r = 0;
out:
    hedge_wipe(skM, sizeof skM);
    hedge_wipe(skX, sizeof skX);
    hedge_wipe(ssM, sizeof ssM);
    hedge_wipe(ssX, sizeof ssX);
    return r;
}
#else /* HEDGE_UNHEDGED: the xwing_* API is plain ML-KEM-768 (baseline only) */
#include <string.h>
#include "hedge.h"
#include "mlkem_native.h"
int xwing_keygen_derand(uint8_t pk[XWING_PK_BYTES], uint8_t sk[XWING_SK_BYTES], const uint8_t seed[XWING_KGSEED_BYTES])
{
    uint8_t skM[2400];
    int r = mlkem_keypair_derand(pk, skM, seed);
    if (r == 0) memcpy(sk, seed, 64);
    hedge_wipe(skM, sizeof skM);
    return r;
}
int xwing_keygen(uint8_t pk[XWING_PK_BYTES], uint8_t sk[XWING_SK_BYTES])
{
    uint8_t seed[64]; int r;
    if (hedge_randombytes(seed, sizeof seed) != 0) return -1;
    r = xwing_keygen_derand(pk, sk, seed);
    hedge_wipe(seed, sizeof seed);
    return r;
}
int xwing_encaps_derand(uint8_t ct[XWING_CT_BYTES], uint8_t ss[32], const uint8_t pk[XWING_PK_BYTES],
                        const uint8_t eseed[XWING_ESEED_BYTES])
{ return mlkem_enc_derand(ct, ss, pk, eseed); }
int xwing_encaps(uint8_t ct[XWING_CT_BYTES], uint8_t ss[32], const uint8_t pk[XWING_PK_BYTES])
{
    uint8_t e[XWING_ESEED_BYTES]; int r;
    if (hedge_randombytes(e, sizeof e) != 0) return -1;
    r = xwing_encaps_derand(ct, ss, pk, e);
    hedge_wipe(e, sizeof e);
    return r;
}
int xwing_decaps(uint8_t ss[32], const uint8_t ct[XWING_CT_BYTES], const uint8_t sk[XWING_SK_BYTES])
{   /* re-expand the stored seed, as X-Wing does */
    uint8_t pkM[1184], skM[2400]; int r = -1;
    if (mlkem_keypair_derand(pkM, skM, sk) == 0) r = mlkem_dec(ss, ct, skM);
    hedge_wipe(skM, sizeof skM);
    return r;
}
#endif
