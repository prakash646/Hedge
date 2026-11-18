/* HEDGE benchmark on the lowRISC Ibex core (RV32IMC, "small" configuration),
 * run cycle-accurately in the Verilator RTL simulation of Ibex's simple system.
 *  - self-checks X-Wing against official vector 0 and runs one full handshake first
 *  - cycle counts from the mcycle CSR; peak stack by stack painting
 *  - randomness: deterministic xorshift (no TRNG in the simulator); this affects
 *    no timing because all measured code paths are constant-time in their inputs
 * SPDX-License-Identifier: MIT */
#include "simple_system_common.h"   /* before stdio.h: picolibc defines putchar as a macro */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#undef putchar
#include "hedge.h"
#include "bench_core.h"
#include "xwing_vectors.h"

/* ---------------- console ---------------- */
int printf(const char *fmt, ...)
{
    static char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    for (char *p = buf; *p; p++) putchar(*p);
    return n;
}

/* ---------------- randomness (deterministic, see header) ---------------- */
static uint64_t rs = 0x243F6A8885A308D3ull;
int hedge_randombytes(uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17;
        out[i] = (uint8_t)(rs >> 24);
    }
    return 0;
}
int randombytes(uint8_t *out, size_t outlen);
int randombytes(uint8_t *out, size_t outlen) { return hedge_randombytes(out, outlen); }

/* ---------------- cycle counter ---------------- */
uint64_t bench_now(void)
{
    uint32_t hi, lo, hi2;
    do {
        asm volatile("csrr %0, mcycleh" : "=r"(hi));
        asm volatile("csrr %0, mcycle"  : "=r"(lo));
        asm volatile("csrr %0, mcycleh" : "=r"(hi2));
    } while (hi != hi2);
    return ((uint64_t)hi << 32) | lo;
}
const char *bench_unit(void) { return "cycles"; }

/* ---------------- stack painting ---------------- */
#define PAINT_BYTES (64 * 1024)
#define PAINT 0xA5A5A5A5u
static void __attribute__((noinline)) paint(void)
{
    volatile uint32_t region[PAINT_BYTES / 4];
    for (size_t i = 0; i < PAINT_BYTES / 4; i++) region[i] = PAINT;
}
static size_t __attribute__((noinline)) measure(void)
{
    volatile uint32_t region[PAINT_BYTES / 4];
    size_t i = 0;
    while (i < PAINT_BYTES / 4 && region[i] == PAINT) i++;
    return PAINT_BYTES - 4 * i;
}
#define STACK_OF(name, op) do { paint(); op; printf("%-34s %8u bytes peak stack\n", name, (unsigned)measure()); } while (0)

static const uint8_t ID_G[8] = { 'G', 'W', '0', '0', '0', '0', '0', '1' };
static const uint8_t ID_D[8] = { 'D', 'E', 'V', '0', '0', '4', '2', '0' };
static uint8_t KD[32];
static int lookup(const uint8_t id[8], uint8_t kd[32], void *arg)
{ (void)arg; if (memcmp(id, ID_D, 8)) return -1; memcpy(kd, KD, 32); return 0; }

static int self_test(void)
{
    static uint8_t pk[XWING_PK_BYTES], sk[XWING_SK_BYTES], ct[XWING_CT_BYTES], ss[32];
    static uint8_t m1[16], m2[HEDGE_M2_BYTES], m3[HEDGE_M3_BYTES], m4[16], peer[8];
    static hedge_device d; static hedge_gateway g; static hedge_session_keys a, b;
    int ok = 1;
#ifndef HEDGE_UNHEDGED  /* the baseline has no X-Wing; its handshake check below still runs */
    xwing_keygen_derand(pk, sk, xv_seed[0]);
    ok &= memcmp(pk, xv_pk[0], XWING_PK_BYTES) == 0;
    xwing_encaps_derand(ct, ss, pk, xv_eseed[0]);
    ok &= memcmp(ct, xv_ct[0], XWING_CT_BYTES) == 0 && memcmp(ss, xv_ss[0], 32) == 0;
#endif
    hedge_randombytes(KD, 32);
    ok &= hedge_dev_start(&d, ID_D, m1) == 0;
    ok &= hedge_gw_respond(&g, ID_G, m1, m2) == 0;
    ok &= hedge_dev_respond(&d, KD, m2, m3) == 0;
    ok &= hedge_gw_finish(&g, lookup, NULL, m3, m4, &b, peer) == 0;
    ok &= hedge_dev_finish(&d, m4, &a) == 0;
    ok &= memcmp(&a, &b, sizeof a) == 0;
    return ok;
}

static void stack_report(void)
{
    static uint8_t pk[XWING_PK_BYTES], sk[XWING_SK_BYTES], ct[XWING_CT_BYTES], ss[32], c[96], m[64];
    static uint8_t m1[16], m2[HEDGE_M2_BYTES], m3[HEDGE_M3_BYTES], m4[16], peer[8];
    static hedge_device d; static hedge_gateway g; static hedge_session_keys a, b;
    hedge_comb_key k; uint8_t n[16];
    hedge_randombytes((uint8_t *)&k, sizeof k); hedge_randombytes(n, 16);
    printf("--- peak stack (stack painting) ---\n");
    STACK_OF("Comb.Enc 64 B", hedge_comb_encrypt(c, &k, n, NULL, 0, m, 64));
    xwing_keygen(pk, sk);
    STACK_OF("X-Wing Encaps", xwing_encaps(ct, ss, pk));
    hedge_dev_start(&d, ID_D, m1); hedge_gw_respond(&g, ID_G, m1, m2);
    STACK_OF("Device respond", hedge_dev_respond(&d, KD, m2, m3));
    hedge_gw_finish(&g, lookup, NULL, m3, m4, &b, peer);
    STACK_OF("Device finish", hedge_dev_finish(&d, m4, &a));
}

#ifndef REPS_SYM
#define REPS_SYM 11
#endif
#ifndef REPS_KEM
#define REPS_KEM 3
#endif

#ifdef ATTR_ONLY
void bench_ablation(int reps_sym, int reps_kem, const uint8_t kd[32]);
#endif

int main(void)
{
    printf("\nHEDGE on Ibex RV32IMC (small config), Verilator RTL simulation\n");
    printf("self-test (X-Wing vector + full handshake): %s\n", self_test() ? "PASS" : "FAIL");
#if defined(ATTR_ONLY)
    bench_ablation(REPS_SYM, REPS_KEM, KD);    /* ablation + per-primitive attribution */
#else
#ifndef STACK_ONLY
    bench_run(REPS_SYM, REPS_KEM);
#endif
    stack_report();
#endif
    printf("done.\n");
    return 0;
}
