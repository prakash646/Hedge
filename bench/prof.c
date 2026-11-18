/* Cycle attribution for one device handshake (linked with -Wl,--wrap=... ).
 * Every wrapped call adds its elapsed time to prof_cyc[scope][prim], where
 * `scope` is the protocol-level operation currently running (X-Wing encaps,
 * H*, KDF, Comb) and `prim` the primitive being called. Only calls that cross
 * translation units can be wrapped; all calls listed here do.
 * SPDX-License-Identifier: MIT */
#include <stdint.h>
#include <stddef.h>
#include "hedge.h"
#include "sha3.h"
#include "prof.h"

uint64_t bench_now(void);

uint64_t prof_cyc[PROF_NSCOPE][PROF_NPRIM];
uint32_t prof_calls[PROF_NSCOPE][PROF_NPRIM];
int prof_on = 0;
static int scope = PS_OTHER;

void prof_reset(void)
{
    for (int i = 0; i < PROF_NSCOPE; i++)
        for (int j = 0; j < PROF_NPRIM; j++) { prof_cyc[i][j] = 0; prof_calls[i][j] = 0; }
    scope = PS_OTHER;
}

#define ACC(s, p, t0) do { if (prof_on) { prof_cyc[s][p] += bench_now() - (t0); prof_calls[s][p]++; } } while (0)

/* ---- scopes (protocol-level operations) ---- */
int __real_xwing_encaps_derand(uint8_t *, uint8_t *, const uint8_t *, const uint8_t *);
int __wrap_xwing_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *e)
{ int o = scope; scope = PS_XWING; uint64_t t = bench_now(); int r = __real_xwing_encaps_derand(ct, ss, pk, e); ACC(PS_XWING, PP_TOTAL, t); scope = o; return r; }

int __real_hedge_hstar(uint8_t *, const hedge_seg *, size_t);
int __wrap_hedge_hstar(uint8_t *out, const hedge_seg *s, size_t n)
{ int o = scope; scope = PS_HSTAR; uint64_t t = bench_now(); int r = __real_hedge_hstar(out, s, n); ACC(PS_HSTAR, PP_TOTAL, t); scope = o; return r; }

int __real_hedge_kdf(uint8_t *, size_t, const uint8_t *, size_t, const char *, const uint8_t *, size_t);
int __wrap_hedge_kdf(uint8_t *out, size_t ol, const uint8_t *ikm, size_t il, const char *lb, const uint8_t *c, size_t cl)
{ int o = scope; scope = PS_KDF; uint64_t t = bench_now(); int r = __real_hedge_kdf(out, ol, ikm, il, lb, c, cl); ACC(PS_KDF, PP_TOTAL, t); scope = o; return r; }

int __real_hedge_comb_encrypt(uint8_t *, const hedge_comb_key *, const uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t);
int __wrap_hedge_comb_encrypt(uint8_t *c, const hedge_comb_key *k, const uint8_t *n, const uint8_t *a, size_t al, const uint8_t *m, size_t ml)
{ int o = scope; scope = PS_COMB; uint64_t t = bench_now(); int r = __real_hedge_comb_encrypt(c, k, n, a, al, m, ml); ACC(PS_COMB, PP_TOTAL, t); scope = o; return r; }

/* ---- primitives ---- */
int __real_mlkem_enc_derand(uint8_t *, uint8_t *, const uint8_t *, const uint8_t *);
int __wrap_mlkem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins)
{ uint64_t t = bench_now(); int r = __real_mlkem_enc_derand(ct, ss, pk, coins); ACC(scope, PP_MLKEM, t); return r; }

void __real_crypto_x25519(uint8_t *, const uint8_t *, const uint8_t *);
void __wrap_crypto_x25519(uint8_t *s, const uint8_t *k, const uint8_t *p)
{ uint64_t t = bench_now(); __real_crypto_x25519(s, k, p); ACC(scope, PP_X25519, t); }

void __real_crypto_x25519_public_key(uint8_t *, const uint8_t *);
void __wrap_crypto_x25519_public_key(uint8_t *p, const uint8_t *k)
{ uint64_t t = bench_now(); __real_crypto_x25519_public_key(p, k); ACC(scope, PP_X25519, t); }

int __real_sha3_init(sha3_ctx_t *, int);
int __wrap_sha3_init(sha3_ctx_t *c, int l)
{ uint64_t t = bench_now(); int r = __real_sha3_init(c, l); ACC(scope, PP_SHA3, t); return r; }
int __real_sha3_update(sha3_ctx_t *, const void *, size_t);
int __wrap_sha3_update(sha3_ctx_t *c, const void *d, size_t n)
{ uint64_t t = bench_now(); int r = __real_sha3_update(c, d, n); ACC(scope, PP_SHA3, t); return r; }
int __real_sha3_final(void *, sha3_ctx_t *);
int __wrap_sha3_final(void *md, sha3_ctx_t *c)
{ uint64_t t = bench_now(); int r = __real_sha3_final(md, c); ACC(scope, PP_SHA3, t); return r; }
void __real_shake_xof(sha3_ctx_t *);
void __wrap_shake_xof(sha3_ctx_t *c)
{ uint64_t t = bench_now(); __real_shake_xof(c); ACC(scope, PP_SHA3, t); }
void __real_shake_out(sha3_ctx_t *, void *, size_t);
void __wrap_shake_out(sha3_ctx_t *c, void *o, size_t n)
{ uint64_t t = bench_now(); __real_shake_out(c, o, n); ACC(scope, PP_SHA3, t); }

int __real_ascon_hash256(unsigned char *, const unsigned char *, unsigned long long);
int __wrap_ascon_hash256(unsigned char *o, const unsigned char *i, unsigned long long n)
{ uint64_t t = bench_now(); int r = __real_ascon_hash256(o, i, n); ACC(scope, PP_ASCON, t); return r; }
int __real_ascon_cxof128(unsigned char *, unsigned long long, const unsigned char *, unsigned long long, const unsigned char *, unsigned long long);
int __wrap_ascon_cxof128(unsigned char *o, unsigned long long ol, const unsigned char *i, unsigned long long il, const unsigned char *z, unsigned long long zl)
{ uint64_t t = bench_now(); int r = __real_ascon_cxof128(o, ol, i, il, z, zl); ACC(scope, PP_ASCON, t); return r; }

int __real_hedge_ascon_encrypt(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t);
int __wrap_hedge_ascon_encrypt(uint8_t *c, const uint8_t *k, const uint8_t *n, const uint8_t *a, size_t al, const uint8_t *m, size_t ml)
{ uint64_t t = bench_now(); int r = __real_hedge_ascon_encrypt(c, k, n, a, al, m, ml); ACC(scope, PP_ASCON, t); return r; }
int __real_hedge_romulus_encrypt(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t);
int __wrap_hedge_romulus_encrypt(uint8_t *c, const uint8_t *k, const uint8_t *n, const uint8_t *a, size_t al, const uint8_t *m, size_t ml)
{ uint64_t t = bench_now(); int r = __real_hedge_romulus_encrypt(c, k, n, a, al, m, ml); ACC(scope, PP_ROMULUS, t); return r; }
