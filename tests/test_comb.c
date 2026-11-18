/* Record-layer tests:
 *  1. correctness over all message lengths 0..300 and several AD lengths
 *  2. rejection of every single-bit flip, truncation, wrong nonce, wrong AD, wrong key half
 *  3. randomized tidiness test (paper Sec. IV): for each component and for Comb,
 *     every accepted ciphertext must re-encrypt to itself; mutated ciphertexts
 *     must never be accepted.
 * SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hedge.h"

static int failures = 0;
#define CHECK(cond, ...) do { if (!(cond)) { failures++; if (failures < 20) { fprintf(stderr, "FAIL: " __VA_ARGS__); fprintf(stderr, "\n"); } } } while (0)

/* deterministic PRNG (xorshift64*) for reproducible test inputs */
static uint64_t rs = 0x9E3779B97F4A7C15ull;
static uint64_t rnd(void) { rs ^= rs >> 12; rs ^= rs << 25; rs ^= rs >> 27; return rs * 0x2545F4914F6CDD1Dull; }
static void fill(uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) p[i] = (uint8_t)rnd(); }

static void test_correctness(void)
{
    static uint8_t m[400], c[440], b[400], ad[70], n[16];
    hedge_comb_key k;
    const size_t adl[] = { 0, 1, 15, 16, 17, 64 };
    int cases = 0;
    for (size_t a = 0; a < sizeof adl / sizeof adl[0]; a++)
        for (size_t L = 0; L <= 300; L++) {
            fill((uint8_t *)&k, sizeof k); fill(n, 16); fill(ad, adl[a]); fill(m, L);
            CHECK(hedge_comb_encrypt(c, &k, n, ad, adl[a], m, L) == 0, "enc L=%zu", L);
            CHECK(hedge_comb_decrypt(b, &k, n, ad, adl[a], c, L + 32) == 0 && memcmp(b, m, L) == 0, "dec L=%zu", L);
            cases++;
        }
    printf("  correctness: %d (length, AD) cases\n", cases);
}

static void test_rejection(void)
{
    static uint8_t m[64], c[96], x[96], b[64], ad[16], n[16];
    hedge_comb_key k, k2;
    long rejected = 0, total = 0;
    fill((uint8_t *)&k, sizeof k); fill(n, 16); fill(ad, 16); fill(m, 64);
    hedge_comb_encrypt(c, &k, n, ad, 16, m, 64);
    for (int bit = 0; bit < 96 * 8; bit++) {          /* every single-bit flip */
        memcpy(x, c, 96); x[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        total++; rejected += hedge_comb_decrypt(b, &k, n, ad, 16, x, 96) != 0;
    }
    for (size_t L = 32; L < 96; L++) {                 /* every truncation */
        total++; rejected += hedge_comb_decrypt(b, &k, n, ad, 16, c, L) != 0;
    }
    n[0] ^= 1; total++; rejected += hedge_comb_decrypt(b, &k, n, ad, 16, c, 96) != 0; n[0] ^= 1;
    ad[5] ^= 1; total++; rejected += hedge_comb_decrypt(b, &k, n, ad, 16, c, 96) != 0; ad[5] ^= 1;
    k2 = k; k2.k_out[0] ^= 1; total++; rejected += hedge_comb_decrypt(b, &k2, n, ad, 16, c, 96) != 0;
    k2 = k; k2.k_in[0] ^= 1;  total++; rejected += hedge_comb_decrypt(b, &k2, n, ad, 16, c, 96) != 0;
    CHECK(rejected == total, "rejection %ld/%ld", rejected, total);
    /* failed decryption must not leave plaintext in the output buffer */
    memset(b, 0xAA, sizeof b); x[0] = c[0] ^ 1; memcpy(x + 1, c + 1, 95);
    hedge_comb_decrypt(b, &k, n, ad, 16, x, 96);
    { int zero = 1; for (int i = 0; i < 64; i++) zero &= b[i] == 0; CHECK(zero, "output not zeroed on failure"); }
    printf("  rejection: %ld/%ld tampered inputs rejected\n", rejected, total);
}

typedef int (*enc_fn)(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t);
typedef int (*dec_fn)(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t);

static int comb_enc_w(uint8_t *c, const uint8_t *k, const uint8_t *n, const uint8_t *ad, size_t al, const uint8_t *m, size_t ml)
{ return hedge_comb_encrypt(c, (const hedge_comb_key *)k, n, ad, al, m, ml); }
static int comb_dec_w(uint8_t *m, const uint8_t *k, const uint8_t *n, const uint8_t *ad, size_t al, const uint8_t *c, size_t cl)
{ return hedge_comb_decrypt(m, (const hedge_comb_key *)k, n, ad, al, c, cl); }

/* Randomized tidiness test. Returns 0 if no violation. */
static void tidiness(const char *name, enc_fn enc, dec_fn dec, size_t keylen, size_t tau, long trials)
{
    static uint8_t k[32], n[16], ad[32], m[128], c[192], x[192], b[192], r[192];
    long accepted_valid = 0, accepted_mut = 0, violations = 0, mutated = 0;
    for (long t = 0; t < trials; t++) {
        size_t L = rnd() % 97, A = rnd() % 33;
        fill(k, keylen); fill(n, 16); fill(ad, A); fill(m, L);
        enc(c, k, n, ad, A, m, L);
        /* (a) accepted ciphertext re-encrypts to itself */
        if (dec(b, k, n, ad, A, c, L + tau) == 0) {
            accepted_valid++;
            enc(r, k, n, ad, A, b, L);
            if (memcmp(r, c, L + tau) != 0) violations++;
        }
        /* (b) a mutated ciphertext: bit flip, byte replace, truncate or extend */
        size_t XL = L + tau;
        memcpy(x, c, XL);
        switch (rnd() % 4) {
        case 0: x[rnd() % XL] ^= (uint8_t)(1u << (rnd() % 8)); break;
        case 1: { size_t i = rnd() % XL; uint8_t v; do v = (uint8_t)rnd(); while (v == x[i]); x[i] = v; } break;
        case 2: if (XL > tau) XL -= 1 + rnd() % (XL - tau); else x[0] ^= 1; break;
        default: x[XL] = (uint8_t)rnd(); XL += 1; break;
        }
        mutated++;
        if (dec(b, k, n, ad, A, x, XL) == 0) {
            accepted_mut++;
            enc(r, k, n, ad, A, b, XL - tau);
            if (memcmp(r, x, XL) != 0) violations++;
        }
    }
    CHECK(violations == 0 && accepted_valid == trials, "%s tidiness", name);
    printf("  tidiness %-14s trials=%ld  valid accepted+re-encrypted=%ld  mutated=%ld accepted=%ld  violations=%ld\n",
           name, trials, accepted_valid, mutated, accepted_mut, violations);
}

int main(int argc, char **argv)
{
    long trials = (argc > 1) ? atol(argv[1]) : 1000000;
    printf("Record-layer tests\n");
    test_correctness();
    test_rejection();
    tidiness("Ascon-AEAD128", hedge_ascon_encrypt, hedge_ascon_decrypt, 16, 16, trials);
    tidiness("Romulus-N", hedge_romulus_encrypt, hedge_romulus_decrypt, 16, 16, trials);
    tidiness("Comb", comb_enc_w, comb_dec_w, 32, 32, trials);
    printf(failures ? "COMB: %d FAILURES\n" : "COMB: all passed\n", failures);
    return failures ? 1 : 0;
}
