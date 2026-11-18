/*
 * HEDGE: algorithm-hedged, sign-less post-quantum AKE and record layer
 * for microcontroller-class IoT devices.
 *
 * Public API. All functions return 0 on success and a negative value on
 * failure. No function allocates heap memory.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef HEDGE_H
#define HEDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Sizes (bytes)                                                       */
/* ------------------------------------------------------------------ */
/* -DHEDGE_UNHEDGED builds the single-primitive baseline used in the paper's
 * cost-of-hedging comparison: ML-KEM-768 only, Ascon-Hash256 only,
 * Ascon-CXOF128 only and Ascon-AEAD128 only, with the same message flow,
 * key schedule and code paths. It is NOT the HEDGE protocol. */
#define HEDGE_KEY_BYTES       16   /* per-component AEAD key           */
#define HEDGE_NONCE_BYTES     16
#define HEDGE_TAG_BYTES       16   /* per-component tag                */
#ifdef HEDGE_UNHEDGED
#define HEDGE_COMB_OVERHEAD   16   /* one tag                          */
#else
#define HEDGE_COMB_OVERHEAD   32   /* two tags                         */
#endif
#define HEDGE_COMB_MAX_MSG    1024 /* max record payload               */

#define HEDGE_ID_BYTES        8
#define HEDGE_KD_BYTES        32   /* PUF-derived device key           */
#ifdef HEDGE_UNHEDGED
#define HEDGE_TH_BYTES        32   /* Ascon-Hash256 only               */
#else
#define HEDGE_TH_BYTES        64   /* H* output: SHAKE256 || Ascon-Hash256 */
#endif
#define HEDGE_MS_BYTES        32
#define HEDGE_FIN_BYTES       16

#ifdef HEDGE_UNHEDGED              /* "xwing_*" = plain ML-KEM-768      */
#define XWING_PK_BYTES        1184
#define XWING_CT_BYTES        1088
#define XWING_SS_BYTES        32
#define XWING_SK_BYTES        64   /* ML-KEM key-generation seed d || z */
#define XWING_ESEED_BYTES     32
#define XWING_KGSEED_BYTES    64
#else
#define XWING_PK_BYTES        1216
#define XWING_CT_BYTES        1120
#define XWING_SS_BYTES        32
#define XWING_SK_BYTES        32   /* decapsulation key = 32-byte seed  */
#define XWING_ESEED_BYTES     64
#define XWING_KGSEED_BYTES    32
#endif

#define HEDGE_M1_BYTES  16                                        /* n_D */
#define HEDGE_M2_BYTES  (16 + HEDGE_ID_BYTES + XWING_PK_BYTES)    /* 1240 (unhedged 1208) */
#define HEDGE_C3_BYTES  (HEDGE_ID_BYTES + HEDGE_FIN_BYTES + HEDGE_COMB_OVERHEAD) /* 56 (40) */
#define HEDGE_M3_BYTES  (XWING_CT_BYTES + HEDGE_C3_BYTES)         /* 1176 (1128) */
#define HEDGE_M4_BYTES  HEDGE_FIN_BYTES                           /* 16 */

/* ------------------------------------------------------------------ */
/* Component primitives (thin wrappers over the vendored code)        */
/* ------------------------------------------------------------------ */
int hedge_ascon_encrypt(uint8_t *c, const uint8_t k[16], const uint8_t n[16],
                        const uint8_t *ad, size_t adlen,
                        const uint8_t *m, size_t mlen);
int hedge_ascon_decrypt(uint8_t *m, const uint8_t k[16], const uint8_t n[16],
                        const uint8_t *ad, size_t adlen,
                        const uint8_t *c, size_t clen);
int hedge_romulus_encrypt(uint8_t *c, const uint8_t k[16], const uint8_t n[16],
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *m, size_t mlen);
int hedge_romulus_decrypt(uint8_t *m, const uint8_t k[16], const uint8_t n[16],
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *c, size_t clen);

/* ------------------------------------------------------------------ */
/* Record layer: tidy cascade Comb[Out = Ascon-AEAD128, In = Romulus-N] */
/* ------------------------------------------------------------------ */
typedef struct {
    uint8_t k_out[HEDGE_KEY_BYTES];  /* Ascon-AEAD128 key (outer) */
    uint8_t k_in[HEDGE_KEY_BYTES];   /* Romulus-N key (inner)     */
} hedge_comb_key;

/* c must hold mlen + HEDGE_COMB_OVERHEAD bytes. */
int hedge_comb_encrypt(uint8_t *c, const hedge_comb_key *k,
                       const uint8_t n[HEDGE_NONCE_BYTES],
                       const uint8_t *ad, size_t adlen,
                       const uint8_t *m, size_t mlen);
/* m must hold clen - HEDGE_COMB_OVERHEAD bytes; it is zeroed on failure. */
int hedge_comb_decrypt(uint8_t *m, const hedge_comb_key *k,
                       const uint8_t n[HEDGE_NONCE_BYTES],
                       const uint8_t *ad, size_t adlen,
                       const uint8_t *c, size_t clen);

/* ------------------------------------------------------------------ */
/* Hash and KDF combiners                                              */
/* ------------------------------------------------------------------ */
/* H*(x) = SHAKE256(x, 32) || Ascon-Hash256(x); x = concatenation of segments */
typedef struct { const uint8_t *p; size_t len; } hedge_seg;
int hedge_hstar(uint8_t out[HEDGE_TH_BYTES], const hedge_seg *segs, size_t nsegs);

/* KDF(ikm, label, ctx, L) = SHAKE256(<label,ctx,ikm>, L) XOR Ascon-CXOF128(<ctx,ikm>, L; Z = label)
 * <...> is a 2-byte big-endian length prefix per field. */
int hedge_kdf(uint8_t *out, size_t outlen,
              const uint8_t *ikm, size_t ikmlen,
              const char *label,
              const uint8_t *ctx, size_t ctxlen);

/* ------------------------------------------------------------------ */
/* X-Wing (draft-connolly-cfrg-xwing-kem): ML-KEM-768 + X25519         */
/* ------------------------------------------------------------------ */
int xwing_keygen_derand(uint8_t pk[XWING_PK_BYTES], uint8_t sk[XWING_SK_BYTES],
                        const uint8_t seed[XWING_KGSEED_BYTES]);
int xwing_keygen(uint8_t pk[XWING_PK_BYTES], uint8_t sk[XWING_SK_BYTES]);
int xwing_encaps_derand(uint8_t ct[XWING_CT_BYTES], uint8_t ss[XWING_SS_BYTES],
                        const uint8_t pk[XWING_PK_BYTES],
                        const uint8_t eseed[XWING_ESEED_BYTES]);
int xwing_encaps(uint8_t ct[XWING_CT_BYTES], uint8_t ss[XWING_SS_BYTES],
                 const uint8_t pk[XWING_PK_BYTES]);
int xwing_decaps(uint8_t ss[XWING_SS_BYTES], const uint8_t ct[XWING_CT_BYTES],
                 const uint8_t sk[XWING_SK_BYTES]);

/* ------------------------------------------------------------------ */
/* Handshake                                                           */
/* ------------------------------------------------------------------ */
typedef struct {
    hedge_comb_key k_dg;  uint8_t iv_dg[HEDGE_NONCE_BYTES];   /* device -> gateway */
    hedge_comb_key k_gd;  uint8_t iv_gd[HEDGE_NONCE_BYTES];   /* gateway -> device */
} hedge_session_keys;

typedef struct {
    int     state;
    uint8_t id[HEDGE_ID_BYTES];
    uint8_t m1[HEDGE_M1_BYTES];
    uint8_t th3[HEDGE_TH_BYTES];
    uint8_t ms[HEDGE_MS_BYTES];
    uint8_t tau_d[HEDGE_FIN_BYTES];
} hedge_device;

typedef struct {
    int     state;
    uint8_t id[HEDGE_ID_BYTES];
    uint8_t xw_sk[XWING_SK_BYTES];   /* erased right after decapsulation */
    uint8_t th2[HEDGE_TH_BYTES];
} hedge_gateway;

/* Gateway credential lookup: copy K_D for id into kd and return 0, or return <0. */
typedef int (*hedge_lookup_fn)(const uint8_t id[HEDGE_ID_BYTES],
                               uint8_t kd[HEDGE_KD_BYTES], void *arg);

/* Device side */
int hedge_dev_start(hedge_device *d, const uint8_t id[HEDGE_ID_BYTES],
                    uint8_t m1[HEDGE_M1_BYTES]);
int hedge_dev_respond(hedge_device *d, const uint8_t kd[HEDGE_KD_BYTES],
                      const uint8_t m2[HEDGE_M2_BYTES], uint8_t m3[HEDGE_M3_BYTES]);
int hedge_dev_respond_derand(hedge_device *d, const uint8_t kd[HEDGE_KD_BYTES],
                             const uint8_t m2[HEDGE_M2_BYTES], uint8_t m3[HEDGE_M3_BYTES],
                             const uint8_t eseed[XWING_ESEED_BYTES]);
int hedge_dev_finish(hedge_device *d, const uint8_t m4[HEDGE_M4_BYTES],
                     hedge_session_keys *keys);

/* Gateway side */
int hedge_gw_respond(hedge_gateway *g, const uint8_t id[HEDGE_ID_BYTES],
                     const uint8_t m1[HEDGE_M1_BYTES], uint8_t m2[HEDGE_M2_BYTES]);
int hedge_gw_finish(hedge_gateway *g, hedge_lookup_fn lookup, void *arg,
                    const uint8_t m3[HEDGE_M3_BYTES], uint8_t m4[HEDGE_M4_BYTES],
                    hedge_session_keys *keys, uint8_t peer_id[HEDGE_ID_BYTES]);

/* Application records: nonce = iv XOR (0^64 || be64(seq)) */
int hedge_record_seal(uint8_t *c, const hedge_comb_key *k, const uint8_t iv[16],
                      uint64_t seq, const uint8_t *ad, size_t adlen,
                      const uint8_t *m, size_t mlen);
int hedge_record_open(uint8_t *m, const hedge_comb_key *k, const uint8_t iv[16],
                      uint64_t seq, const uint8_t *ad, size_t adlen,
                      const uint8_t *c, size_t clen);

/* Constant-time testing (tools/ct_check.c, Valgrind memcheck): secret data is
 * marked undefined; HEDGE_DECLASSIFY marks values that are public by design
 * (tag-verification results). No-op in normal builds. */
#ifdef HEDGE_CT_TESTING
#include <valgrind/memcheck.h>
#define HEDGE_DECLASSIFY(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))
#else
#define HEDGE_DECLASSIFY(p, n) ((void)0)
#endif

/* Utilities */
void hedge_wipe(void *p, size_t n);
int  hedge_ct_equal(const uint8_t *a, const uint8_t *b, size_t n); /* 1 if equal */
int  hedge_randombytes(uint8_t *out, size_t n); /* platform-provided */

#ifdef __cplusplus
}
#endif
#endif /* HEDGE_H */
