/* Cost-of-hedging measurements: every hedged layer next to each of its single
 * components, on the same inputs, plus a per-primitive attribution of one
 * complete device handshake (needs prof.c and PROF_WRAP_FLAGS).
 * SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>
#include "hedge.h"
#include "sha3.h"
#include "monocypher.h"
#include "mlkem_native.h"
#include "prof.h"

uint64_t bench_now(void);
const char *bench_unit(void);
int ascon_hash256(unsigned char *out, const unsigned char *in, unsigned long long inlen);
int ascon_cxof128(unsigned char *out, unsigned long long outlen, const unsigned char *in,
                  unsigned long long inlen, const unsigned char *cs, unsigned long long cslen);

#define MAXR 201
static uint64_t sm[MAXR];
static void rep(const char *name, int n)
{
    for (int i = 1; i < n; i++) { uint64_t v = sm[i]; int j = i - 1; while (j >= 0 && sm[j] > v) { sm[j + 1] = sm[j]; j--; } sm[j + 1] = v; }
    printf("%-34s %10llu %s  (median of %d; min %llu, max %llu)\n", name,
           (unsigned long long)sm[n / 2], bench_unit(), n,
           (unsigned long long)sm[0], (unsigned long long)sm[n - 1]);
}
#define T(name, reps, op) do { int n_ = (reps) > MAXR ? MAXR : (reps); \
    for (int i_ = 0; i_ < n_; i_++) { uint64_t t0_ = bench_now(); op; sm[i_] = bench_now() - t0_; } \
    rep(name, n_); } while (0)

/* single-component versions of H* and KDF, same encoding as src/kdf.c */
static void shake_only(uint8_t *out, size_t ol, const uint8_t *in, size_t il)
{ sha3_ctx_t c; shake256_init(&c); shake_update(&c, in, il); shake_xof(&c); shake_out(&c, out, ol); }

static const uint8_t ID_G[8] = { 'G', 'W', '0', '0', '0', '0', '0', '1' };
static const uint8_t ID_D[8] = { 'D', 'E', 'V', '0', '0', '4', '2', '0' };
static uint8_t KDv[32];
static int lookup(const uint8_t id[8], uint8_t kd[32], void *arg)
{ (void)arg; if (memcmp(id, ID_D, 8)) return -1; memcpy(kd, KDv, 32); return 0; }

void bench_ablation(int reps_sym, int reps_kem, const uint8_t kd[32])
{
    static uint8_t pkM[MLKEM768_PUBLICKEYBYTES], skM[MLKEM768_SECRETKEYBYTES], ctM[MLKEM768_CIPHERTEXTBYTES];
    static uint8_t coins[64], ss[32], a[32], b[32], c[32], in[1256], kin[134], out[96];
    static uint8_t m[64], ad[16], n[16], ct[128], pt[128], k16[16];
    static uint8_t m1[16], m2[HEDGE_M2_BYTES], m3[HEDGE_M3_BYTES], m4[16], peer[8];
    static hedge_device d; static hedge_gateway g; static hedge_session_keys ka, kb;
    volatile int sink = 0;

    hedge_randombytes(coins, sizeof coins); hedge_randombytes(a, 32); hedge_randombytes(in, sizeof in);
    hedge_randombytes(kin, sizeof kin); hedge_randombytes(m, 64); hedge_randombytes(ad, 16);
    hedge_randombytes(n, 16); hedge_randombytes(k16, 16);
    sink += mlkem_keypair_derand(pkM, skM, coins);
    crypto_x25519_public_key(b, a);

    printf("--- ablation: KEM layer (X-Wing = ML-KEM-768 + X25519 + SHA3-256 combiner) ---\n");
    T("ML-KEM-768 KeyGen", reps_kem, sink += mlkem_keypair_derand(pkM, skM, coins));
    T("ML-KEM-768 Encaps", reps_kem, sink += mlkem_enc_derand(ctM, ss, pkM, coins));
    T("ML-KEM-768 Decaps", reps_kem, sink += mlkem_dec(ss, ctM, skM));
    T("X25519 public key (fixed base)", reps_kem, crypto_x25519_public_key(c, a));
    T("X25519 shared secret (var. base)", reps_kem, crypto_x25519(c, a, b));

    printf("--- ablation: transcript hash, 1256-byte input ---\n");
    T("SHAKE256 only (32 B out)", reps_sym, shake_only(out, 32, in, sizeof in));
    T("Ascon-Hash256 only", reps_sym, sink += ascon_hash256(out, in, sizeof in));
    {
        hedge_seg s[1] = { { in, sizeof in } };
        T("H* = SHAKE256 || Ascon-Hash256", reps_sym, sink += hedge_hstar(out, s, 1));
    }

    printf("--- ablation: KDF, 32-byte output, 134-byte input ---\n");
    T("SHAKE256 only", reps_sym, shake_only(out, 32, kin, sizeof kin));
    T("Ascon-CXOF128 only", reps_sym, sink += ascon_cxof128(out, 32, kin, 132, (const uint8_t *)"ms", 2));
    T("KDF = SHAKE256 xor Ascon-CXOF128", reps_sym, sink += hedge_kdf(out, 32, kin, 64, "ms", kin + 64, 64));

    printf("--- ablation: record layer, 64-byte message, 16-byte AD ---\n");
    hedge_ascon_encrypt(ct, k16, n, ad, 16, m, 64);
    T("Ascon-AEAD128 decrypt only", reps_sym, sink += hedge_ascon_decrypt(pt, k16, n, ad, 16, ct, 80));
    hedge_romulus_encrypt(ct, k16, n, ad, 16, m, 64);
    T("Romulus-N decrypt only", reps_sym, sink += hedge_romulus_decrypt(pt, k16, n, ad, 16, ct, 80));

    /* ---- per-primitive attribution of one device handshake (respond + finish) ---- */
    {
        memcpy(KDv, kd, 32);
        uint64_t tot = 0;
        int runs = 5;
        static uint64_t acc[PROF_NSCOPE][PROF_NPRIM];
        static uint32_t cnt[PROF_NSCOPE][PROF_NPRIM];
        memset(acc, 0, sizeof acc); memset(cnt, 0, sizeof cnt);
        for (int r = 0; r < runs; r++) {
            hedge_dev_start(&d, ID_D, m1); hedge_gw_respond(&g, ID_G, m1, m2);
            prof_reset(); prof_on = 1;
            uint64_t t0 = bench_now();
            sink += hedge_dev_respond(&d, KDv, m2, m3);
            uint64_t t1 = bench_now();
            prof_on = 0;
            sink += hedge_gw_finish(&g, lookup, NULL, m3, m4, &kb, peer);
            prof_on = 1;
            uint64_t t2 = bench_now();
            sink += hedge_dev_finish(&d, m4, &ka);
            uint64_t t3 = bench_now();
            prof_on = 0;
            tot += (t1 - t0) + (t3 - t2);
            for (int i = 0; i < PROF_NSCOPE; i++) for (int j = 0; j < PROF_NPRIM; j++) { acc[i][j] += prof_cyc[i][j]; cnt[i][j] = prof_calls[i][j]; }
        }
        static const char *sn[PROF_NSCOPE] = { "other", "X-Wing Encaps", "H*", "KDF", "Comb.Enc" };
        static const char *pn[PROF_NPRIM] = { "TOTAL", "ML-KEM-768", "X25519", "Keccak/SHA3", "Ascon", "Romulus-N" };
        printf("--- attribution: device respond + finish, mean of %d runs (wrapper overhead included) ---\n", runs);
        printf("device total (respond+finish)                    %10llu %s\n", (unsigned long long)(tot / runs), bench_unit());
        for (int i = 1; i < PROF_NSCOPE; i++)
            for (int j = 0; j < PROF_NPRIM; j++)
                if (cnt[i][j])
                    printf("  %-14s %-12s %3u calls %10llu %s\n", sn[i], pn[j], (unsigned)cnt[i][j],
                           (unsigned long long)(acc[i][j] / runs), bench_unit());
    }
    printf("(ablation sink %d)\n", (int)sink);
}
