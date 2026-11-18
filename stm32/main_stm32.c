/* HEDGE benchmark firmware for the ST B-L475E-IOT01A Discovery kit
 * (STM32L475VG, Arm Cortex-M4, 80 MHz, 128 KB SRAM). Bare metal, no vendor HAL.
 *
 *  - output: USART1 (PB6/PB7) = ST-LINK virtual COM port, 115200 8N1
 *  - clock:  MSI 4 MHz -> PLL -> 80 MHz SYSCLK, flash 4 wait states, ART cache on
 *  - cycles: DWT->CYCCNT, extended to 64 bits in software
 *  - stack:  peak stack per operation by stack painting
 *  - self-test against the official X-Wing vector and one full handshake first
 *  - randomness: deterministic xorshift (as on Ibex); measured paths are
 *    constant-time in their inputs, so this does not affect timing
 *  - after the report, an ENERGY phase repeats forever, announced on the terminal:
 *      ~10 s back-to-back device handshakes (respond step), then ~10 s idle busy loop
 *    Read the MCU current at the IDD jumper (JP5) with a multimeter in both phases.
 *    LEDs stay off: their current flows through the MCU supply and would bias the reading.
 *    The full report is re-printed every cycle, so a late-opened terminal still sees it.
 * SPDX-License-Identifier: MIT */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "hedge.h"
#include "bench_core.h"
#include "xwing_vectors.h"
void bench_ablation(int reps_sym, int reps_kem, const uint8_t kd[32]);
#ifndef HEDGE_VARIANT
#define HEDGE_VARIANT "portable C (all primitives)"
#endif

#define REG(addr) (*(volatile uint32_t *)(addr))

/* ---------------- registers (RM0351) ---------------- */
#define RCC_BASE      0x40021000u
#define RCC_CR        REG(RCC_BASE + 0x00)
#define RCC_CFGR      REG(RCC_BASE + 0x08)
#define RCC_PLLCFGR   REG(RCC_BASE + 0x0C)
#define RCC_AHB2ENR   REG(RCC_BASE + 0x4C)
#define RCC_APB2ENR   REG(RCC_BASE + 0x60)
#define FLASH_ACR     REG(0x40022000u)
#define GPIOA_BASE    0x48000000u
#define GPIOB_BASE    0x48000400u
#define GPIO_MODER(b) REG((b) + 0x00)
#define GPIO_BSRR(b)  REG((b) + 0x18)
#define GPIO_AFRL(b)  REG((b) + 0x20)
#define USART1_BASE   0x40013800u
#define USART1_CR1    REG(USART1_BASE + 0x00)
#define USART1_BRR    REG(USART1_BASE + 0x0C)
#define USART1_ISR    REG(USART1_BASE + 0x1C)
#define USART1_TDR    REG(USART1_BASE + 0x28)
#define DEMCR         REG(0xE000EDFCu)
#define DWT_CTRL      REG(0xE0001000u)
#define DWT_CYCCNT    REG(0xE0001004u)

static uint32_t sysclk_hz = 4000000u;

/* ---------------- clock: 80 MHz from MSI via PLL ---------------- */
static void clock_80mhz(void)
{
    uint32_t t;
    FLASH_ACR = (FLASH_ACR & ~7u) | 4u | (1u << 8) | (1u << 9) | (1u << 10); /* 4 WS, prefetch, I/D cache */
    for (t = 0; (FLASH_ACR & 7u) != 4u && t < 100000u; t++) { }
    RCC_CR &= ~(1u << 24);                                   /* PLL off */
    for (t = 0; (RCC_CR & (1u << 25)) && t < 100000u; t++) { }
    /* src = MSI (4 MHz), M = 1, N = 40 -> VCO 160 MHz, R = 2 -> 80 MHz */
    RCC_PLLCFGR = (1u << 0) | (0u << 4) | (40u << 8) | (1u << 24) | (0u << 25);
    RCC_CR |= (1u << 24);                                    /* PLL on */
    for (t = 0; !(RCC_CR & (1u << 25)) && t < 1000000u; t++) { }
    if (!(RCC_CR & (1u << 25))) return;                      /* stay on MSI 4 MHz */
    RCC_CFGR = (RCC_CFGR & ~3u) | 3u;                        /* SYSCLK = PLL */
    for (t = 0; ((RCC_CFGR >> 2) & 3u) != 3u && t < 1000000u; t++) { }
    if (((RCC_CFGR >> 2) & 3u) == 3u) sysclk_hz = 80000000u;
}

/* ---------------- USART1 on PB6 (TX) / PB7 (RX), AF7 ---------------- */
static void uart_init(void)
{
    RCC_AHB2ENR |= (1u << 0) | (1u << 1);                    /* GPIOA, GPIOB */
    RCC_APB2ENR |= (1u << 14);                               /* USART1 */
    (void)RCC_APB2ENR;
    GPIO_MODER(GPIOB_BASE) = (GPIO_MODER(GPIOB_BASE) & ~(0xFu << 12)) | (0xAu << 12);
    GPIO_AFRL(GPIOB_BASE)  = (GPIO_AFRL(GPIOB_BASE) & ~(0xFFu << 24)) | (0x77u << 24);
    USART1_CR1 = 0;
    USART1_BRR = (sysclk_hz + 57600u) / 115200u;
    USART1_CR1 = (1u << 3) | (1u << 2) | (1u << 0);          /* TE, RE, UE */
}

static void uart_putc(char c)
{
    if (c == '\n') uart_putc('\r');
    while (!(USART1_ISR & (1u << 7))) { }
    USART1_TDR = (uint8_t)c;
}

/* ---------------- LEDs: LD1 = PA5, LD2 = PB14 ---------------- */
static void led_init(void)
{
    GPIO_MODER(GPIOA_BASE) = (GPIO_MODER(GPIOA_BASE) & ~(3u << 10)) | (1u << 10);
    GPIO_MODER(GPIOB_BASE) = (GPIO_MODER(GPIOB_BASE) & ~(3u << 28)) | (1u << 28);
}
static void led(int on)
{
    GPIO_BSRR(GPIOA_BASE) = on ? (1u << 5) : (1u << 21);
    GPIO_BSRR(GPIOB_BASE) = on ? (1u << 14) : (1u << 30);
}

/* ---------------- tiny printf (s, c, d, u, x with l/ll, width, '-') ----------------
 * Output goes to the UART and, while recording, to a buffer that is re-printed later. */
static char report[12288];
static size_t report_len = 0;
static int recording = 0;

static void out(char c)
{
    uart_putc(c);
    if (recording && report_len < sizeof report - 1) report[report_len++] = c;
}

static void out_pad(const char *s, size_t len, int width, int left)
{
    int pad = width > (int)len ? width - (int)len : 0;
    if (!left) while (pad-- > 0) out(' ');
    for (size_t i = 0; i < len; i++) out(s[i]);
    if (left) while (pad-- > 0) out(' ');
}

int printf(const char *fmt, ...);
int printf(const char *fmt, ...)
{
    va_list ap;
    char num[24];
    va_start(ap, fmt);
    for (const char *p = fmt; *p; p++) {
        if (*p != '%') { out(*p); continue; }
        p++;
        int left = 0, width = 0, lng = 0;
        if (*p == '-') { left = 1; p++; }
        while (*p >= '0' && *p <= '9') width = width * 10 + (*p++ - '0');
        while (*p == 'l') { lng++; p++; }
        switch (*p) {
        case 's': { const char *s = va_arg(ap, const char *); out_pad(s, strlen(s), width, left); break; }
        case 'c': { char c = (char)va_arg(ap, int); out_pad(&c, 1, width, left); break; }
        case 'd': case 'u': case 'x': {
            unsigned long long v; int neg = 0;
            if (*p == 'd') {
                long long sv = lng >= 2 ? va_arg(ap, long long) : lng ? va_arg(ap, long) : va_arg(ap, int);
                neg = sv < 0; v = neg ? (unsigned long long)(-sv) : (unsigned long long)sv;
            } else {
                v = lng >= 2 ? va_arg(ap, unsigned long long) : lng ? va_arg(ap, unsigned long) : va_arg(ap, unsigned);
            }
            unsigned base = (*p == 'x') ? 16u : 10u;
            size_t n = 0;
            do { unsigned dgt = (unsigned)(v % base); num[sizeof num - 1 - n++] = (char)(dgt < 10 ? '0' + dgt : 'a' + dgt - 10); v /= base; } while (v);
            if (neg) num[sizeof num - 1 - n++] = '-';
            out_pad(num + sizeof num - n, n, width, left);
            break;
        }
        case '%': out('%'); break;
        default: out('%'); out(*p); break;
        }
    }
    va_end(ap);
    return 0;
}

/* ---------------- randomness (deterministic, see header) ---------------- */
static uint64_t rs = 0x243F6A8885A308D3ull;
int hedge_randombytes(uint8_t *o, size_t n)
{
    for (size_t i = 0; i < n; i++) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; o[i] = (uint8_t)(rs >> 24); }
    return 0;
}
int randombytes(uint8_t *o, size_t n);
int randombytes(uint8_t *o, size_t n) { return hedge_randombytes(o, n); }

/* ---------------- 64-bit cycle counter ---------------- */
static uint32_t cyc_last = 0, cyc_hi = 0;
static int dwt_ok = 0;
static void cyc_init(void)
{
    DEMCR |= (1u << 24);
    DWT_CYCCNT = 0;
    DWT_CTRL |= 1u;
    uint32_t a = DWT_CYCCNT;
    for (volatile int i = 0; i < 1000; i++) { }
    dwt_ok = DWT_CYCCNT != a;
}
uint64_t bench_now(void)
{
    uint32_t v = DWT_CYCCNT;
    if (v < cyc_last) cyc_hi++;
    cyc_last = v;
    return ((uint64_t)cyc_hi << 32) | v;
}
const char *bench_unit(void) { return "cycles"; }

/* ---------------- stack painting ---------------- */
#define PAINT_BYTES (24 * 1024)
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

static uint8_t pk[XWING_PK_BYTES], sk[XWING_SK_BYTES], ct[XWING_CT_BYTES], ss[32];
static uint8_t m1[16], m2[HEDGE_M2_BYTES], m3[HEDGE_M3_BYTES], m4[16], peer[8];
static hedge_device dv; static hedge_gateway gw; static hedge_session_keys ka, kb;

static int self_test(void)
{
    int ok = 1;
#ifndef HEDGE_UNHEDGED  /* the baseline has no X-Wing; its handshake check below still runs */
    xwing_keygen_derand(pk, sk, xv_seed[0]);
    ok &= memcmp(pk, xv_pk[0], XWING_PK_BYTES) == 0;
    xwing_encaps_derand(ct, ss, pk, xv_eseed[0]);
    ok &= memcmp(ct, xv_ct[0], XWING_CT_BYTES) == 0 && memcmp(ss, xv_ss[0], 32) == 0;
#endif
    hedge_randombytes(KD, 32);
    ok &= hedge_dev_start(&dv, ID_D, m1) == 0;
    ok &= hedge_gw_respond(&gw, ID_G, m1, m2) == 0;
    ok &= hedge_dev_respond(&dv, KD, m2, m3) == 0;
    ok &= hedge_gw_finish(&gw, lookup, NULL, m3, m4, &kb, peer) == 0;
    ok &= hedge_dev_finish(&dv, m4, &ka) == 0;
    ok &= memcmp(&ka, &kb, sizeof ka) == 0;
    return ok;
}


/* Known-answer checks for the symmetric primitives (official KAT files, kat/):
 * guards the assembly build variant, whose handshake self-test alone would not
 * catch a primitive that is wrong in the same way on both sides. */
static const uint8_t KA_CT[48] = { 0x63, 0x73, 0xeb, 0xb2, 0x8b, 0xe9, 0x7c, 0x9b, 0xac, 0x09, 0x0c, 0xf3, 0x99, 0xc1, 0x3e, 0xf1, 0x4e, 0xa6, 0xc5, 0xe5, 0x19, 0xe3, 0x0a, 0x5c, 0x6e, 0xf4, 0x4f, 0x7c, 0xea, 0x88, 0x1a, 0xb7, 0xab, 0xef, 0x17, 0x16, 0x57, 0xd1, 0x9c, 0x6c, 0x11, 0x38, 0xb7, 0x57, 0x76, 0x93, 0xe4, 0x39 };
static const uint8_t KR_CT[48] = { 0x95, 0xa9, 0xcc, 0x01, 0x6d, 0xb1, 0xd5, 0x46, 0x68, 0xcc, 0xa0, 0xdc, 0x7b, 0xc6, 0x44, 0x85, 0x2c, 0xb7, 0xa8, 0x3e, 0x03, 0xea, 0x8c, 0xba, 0x8f, 0x45, 0x2a, 0x89, 0xdc, 0x3e, 0xd3, 0x3a, 0x65, 0x69, 0x26, 0x5f, 0xec, 0x0a, 0x69, 0x3a, 0xfe, 0xf3, 0xc3, 0x4e, 0x61, 0xb3, 0xd9, 0x0e };
static const uint8_t KH_MD[32] = { 0xbd, 0x9d, 0x3d, 0x60, 0xa6, 0x6b, 0x53, 0x86, 0x8e, 0xab, 0x2a, 0x5c, 0x74, 0x53, 0x9a, 0x51, 0x8a, 0x1f, 0x60, 0xf0, 0x1e, 0xb1, 0x76, 0xc6, 0x0e, 0x43, 0xde, 0xe8, 0x16, 0x80, 0xb3, 0x3e };
int ascon_hash256(unsigned char *out, const unsigned char *in, unsigned long long inlen);
static int kat_test(void)
{
    uint8_t k[16], na[16], nr[16], pa[32], pr[32], aa[16], ar[16], c[48], h[32], hm[32];
    for (int i = 0; i < 16; i++) { k[i] = (uint8_t)i; na[i] = (uint8_t)(0x10 + i); nr[i] = (uint8_t)i; aa[i] = (uint8_t)(0x30 + i); ar[i] = (uint8_t)i; }
    for (int i = 0; i < 32; i++) { pa[i] = (uint8_t)(0x20 + i); pr[i] = (uint8_t)i; hm[i] = (uint8_t)i; }
    int ok = 1;
    ok &= hedge_ascon_encrypt(c, k, na, aa, 16, pa, 32) == 0 && memcmp(c, KA_CT, 48) == 0;
    ok &= hedge_romulus_encrypt(c, k, nr, ar, 16, pr, 32) == 0 && memcmp(c, KR_CT, 48) == 0;
    ok &= ascon_hash256(h, hm, 32) == 0 && memcmp(h, KH_MD, 32) == 0;
    return ok;
}

static void stack_report(void)
{
    static uint8_t c[96], m[64];
    hedge_comb_key k; uint8_t n[16];
    hedge_randombytes((uint8_t *)&k, sizeof k); hedge_randombytes(n, 16);
    printf("--- peak stack (stack painting) ---\n");
    STACK_OF("Comb.Enc 64 B", hedge_comb_encrypt(c, &k, n, NULL, 0, m, 64));
    xwing_keygen(pk, sk);
    STACK_OF("X-Wing Encaps", xwing_encaps(ct, ss, pk));
    hedge_dev_start(&dv, ID_D, m1); hedge_gw_respond(&gw, ID_G, m1, m2);
    STACK_OF("Device respond", hedge_dev_respond(&dv, KD, m2, m3));
    hedge_gw_finish(&gw, lookup, NULL, m3, m4, &kb, peer);
    STACK_OF("Device finish", hedge_dev_finish(&dv, m4, &ka));
}

/* Energy window: device-side work only. The gateway messages are prepared
 * before the timed loop so the LED-ON current reflects device computation. */
static void energy_cycle(int round)
{
    static uint8_t m2s[4][HEDGE_M2_BYTES];
    static hedge_gateway gws[4];
    static int prepared = 0;
    uint64_t dev_cycles = 0, t_end;
    unsigned count = 0;

    if (!prepared) {                                    /* gateway work, outside the window */
        for (unsigned i = 0; i < 4; i++) {
            hedge_device tmp; uint8_t t1[16];
            hedge_dev_start(&tmp, ID_D, t1);
            hedge_gw_respond(&gws[i], ID_G, t1, m2s[i]);
        }
        prepared = 1;
    }
    printf(">>> [round %d] NOW RUNNING HANDSHAKES for ~10 s -- read the current now\n", round);
    t_end = bench_now() + 10ull * sysclk_hz;
    while (dwt_ok ? bench_now() < t_end : count < 20u) {
        unsigned j = count % 4u;
        hedge_dev_start(&dv, ID_D, m1);                /* fresh device state */
        uint64_t t0 = bench_now();
        hedge_dev_respond(&dv, KD, m2s[j], m3);
        uint64_t t1 = bench_now();
        dev_cycles += t1 - t0;
        count++;
    }
    printf("    [round %d] done: %u device handshakes (respond step), avg %lu cycles each\n",
           round, count, (unsigned long)(count ? dev_cycles / count : 0));
    printf(">>> [round %d] NOW IDLE for ~10 s -- read the current now\n", round);
    uint64_t t_idle = bench_now() + 10ull * sysclk_hz;
    if (dwt_ok) while (bench_now() < t_idle) { __asm__ volatile("nop"); }
    else for (volatile uint32_t i = 0; i < 20000000u; i++) { }
}

int main(void)
{
    clock_80mhz();
    uart_init();
    led_init();
    led(0);                                            /* LEDs off for the whole run */
    cyc_init();

    recording = 1;
    printf("\n=== HEDGE on STM32L475VG (B-L475E-IOT01A, Cortex-M4) ===\n");
    printf("SYSCLK = %lu Hz, flash 4 WS, ART I/D-cache + prefetch on, gcc -O2\n", (unsigned long)sysclk_hz);
    printf("build variant: %s\n", HEDGE_VARIANT);
    if (!dwt_ok) printf("WARNING: DWT cycle counter not running -- cycle counts below are INVALID\n");
    printf("self-test (X-Wing vector + full handshake): %s\n", self_test() ? "PASS" : "FAIL");
    printf("known-answer tests (Ascon-AEAD128, Romulus-N, Ascon-Hash256): %s\n", kat_test() ? "PASS" : "FAIL");
#ifndef REPS_SYM
#define REPS_SYM 201
#endif
#ifndef REPS_KEM
#define REPS_KEM 21
#endif
    bench_run(REPS_SYM, REPS_KEM);
    stack_report();
    bench_ablation(REPS_SYM, REPS_KEM, KD);
    printf("=== benchmark done ===\n");
    recording = 0;

    for (int round = 1;; round++) {
        printf("\n######## FULL REPORT (repeated every ~20 s) ########\n");
        for (size_t i = 0; i < report_len; i++) uart_putc(report[i]);
        printf("######## ENERGY PHASE: measure current at the IDD jumper ########\n");
        energy_cycle(round);
    }
}
