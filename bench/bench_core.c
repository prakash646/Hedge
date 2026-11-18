/* Platform-independent benchmark core. Each platform supplies:
 *   uint64_t bench_now(void);          monotonic time in bench_unit()
 *   const char *bench_unit(void);      e.g. "ns" or "cycles"
 * Reports the median of `reps` runs for every operation of paper Table VIII.
 * SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>
#include "hedge.h"
#include "bench_core.h"

#define MAXREPS 2001
static uint64_t samples[MAXREPS];

static int cmp(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}
static uint64_t median(int n)
{
    /* insertion sort: avoids qsort on tiny targets */
    for (int i = 1; i < n; i++) {
        uint64_t v = samples[i]; int j = i - 1;
        while (j >= 0 && cmp(&samples[j], &v) > 0) { samples[j + 1] = samples[j]; j--; }
        samples[j + 1] = v;
    }
    return samples[n / 2];
}

static void report(const char *name, int n)
{
    uint64_t med = median(n);   /* sorts samples[0..n-1] */
    printf("%-34s %12llu %s  (median of %d; min %llu, max %llu)\n", name, (unsigned long long)med,
           bench_unit(), n, (unsigned long long)samples[0], (unsigned long long)samples[n - 1]);
}

#define TIME(name, reps, setup, op)                                   \
    do {                                                              \
        int n_ = (reps) > MAXREPS ? MAXREPS : (reps);                 \
        for (int i_ = 0; i_ < n_; i_++) {                             \
            setup;                                                    \
            uint64_t t0_ = bench_now();                               \
            op;                                                       \
            samples[i_] = bench_now() - t0_;                          \
        }                                                             \
        report(name, n_);                                             \
    } while (0)

static const uint8_t ID_G[8] = { 'G', 'W', '0', '0', '0', '0', '0', '1' };
static const uint8_t ID_D[8] = { 'D', 'E', 'V', '0', '0', '4', '2', '0' };
static uint8_t KD[32];
static int lookup(const uint8_t id[8], uint8_t kd[32], void *arg)
{ (void)arg; if (memcmp(id, ID_D, 8)) return -1; memcpy(kd, KD, 32); return 0; }

void bench_run(int reps_sym, int reps_kem)
{
    static uint8_t m[64], ad[16], n[16], c[128], b[128], ikm[64], ctx[64], out[96], big[1256];
    static uint8_t pk[XWING_PK_BYTES], sk[XWING_SK_BYTES], ct[XWING_CT_BYTES], ss[32];
    static uint8_t m1[16], m2[HEDGE_M2_BYTES], m3[HEDGE_M3_BYTES], m4[16], peer[8];
    static hedge_device d; static hedge_gateway g; static hedge_session_keys kd_, kg_;
    hedge_comb_key k; uint8_t k16[16];
    volatile int sink = 0;

    hedge_randombytes(m, sizeof m); hedge_randombytes(ad, sizeof ad); hedge_randombytes(n, sizeof n);
    hedge_randombytes((uint8_t *)&k, sizeof k); hedge_randombytes(k16, 16);
    hedge_randombytes(ikm, sizeof ikm); hedge_randombytes(ctx, sizeof ctx); hedge_randombytes(big, sizeof big);
    hedge_randombytes(KD, sizeof KD);

    printf("--- record layer (64-byte message, 16-byte AD) ---\n");
    TIME("Ascon-AEAD128 encrypt", reps_sym, , sink += hedge_ascon_encrypt(c, k16, n, ad, 16, m, 64));
    TIME("Romulus-N encrypt", reps_sym, , sink += hedge_romulus_encrypt(c, k16, n, ad, 16, m, 64));
    TIME("Comb.Enc", reps_sym, , sink += hedge_comb_encrypt(c, &k, n, ad, 16, m, 64));
    hedge_comb_encrypt(c, &k, n, ad, 16, m, 64);
    TIME("Comb.Dec (valid)", reps_sym, , sink += hedge_comb_decrypt(b, &k, n, ad, 16, c, 64 + HEDGE_COMB_OVERHEAD));
    {
        static uint8_t f[64 + HEDGE_COMB_OVERHEAD];
        volatile int rej = 0;
        memcpy(f, c, 64 + HEDGE_COMB_OVERHEAD); f[5] ^= 1;
        TIME("Comb.Dec (forged, early reject)", reps_sym, , rej += hedge_comb_decrypt(b, &k, n, ad, 16, f, 64 + HEDGE_COMB_OVERHEAD) != 0);
        (void)rej;
    }

    printf("--- hash / KDF combiners ---\n");
    TIME("KDF, 32-byte output", reps_sym, , sink += hedge_kdf(out, 32, ikm, 64, "ms", ctx, 64));
    TIME("KDF, 96-byte output", reps_sym, , sink += hedge_kdf(out, 96, ikm, 32, "app", ctx, 64));
    {
        hedge_seg s[1] = { { big, sizeof big } };
        TIME("H*, 1256-byte input", reps_sym, , sink += hedge_hstar(out, s, 1));
    }

    printf("--- X-Wing (ML-KEM-768 + X25519) ---\n");
    TIME("X-Wing KeyGen (gateway)", reps_kem, , sink += xwing_keygen(pk, sk));
    TIME("X-Wing Encaps (device)", reps_kem, , sink += xwing_encaps(ct, ss, pk));
    TIME("X-Wing Decaps (gateway)", reps_kem, , sink += xwing_decaps(ss, ct, sk));

    printf("--- full handshake ---\n");
    /* Device-side total = respond + finish (start only draws 16 random bytes). */
    TIME("Device respond (encaps + KDFs + C3)", reps_kem,
         { hedge_dev_start(&d, ID_D, m1); hedge_gw_respond(&g, ID_G, m1, m2); },
         sink += hedge_dev_respond(&d, KD, m2, m3));
    TIME("Device finish (verify tau_G + keys)", reps_kem,
         { hedge_dev_start(&d, ID_D, m1); hedge_gw_respond(&g, ID_G, m1, m2);
           hedge_dev_respond(&d, KD, m2, m3); hedge_gw_finish(&g, lookup, NULL, m3, m4, &kg_, peer); },
         sink += hedge_dev_finish(&d, m4, &kd_));
    TIME("Gateway respond (keygen + th2)", reps_kem,
         hedge_dev_start(&d, ID_D, m1),
         sink += hedge_gw_respond(&g, ID_G, m1, m2));
    TIME("Gateway finish (decaps + verify)", reps_kem,
         { hedge_dev_start(&d, ID_D, m1); hedge_gw_respond(&g, ID_G, m1, m2); hedge_dev_respond(&d, KD, m2, m3); },
         sink += hedge_gw_finish(&g, lookup, NULL, m3, m4, &kg_, peer));
    printf("(status sink %d: 0 means every call succeeded)\n", (int)sink);
}
