/* HEDGE benchmark firmware for the Raspberry Pi Pico (RP2040, Cortex-M0+).
 *  - runs the system clock at 133 MHz (same as the RP2040 study cited in the paper)
 *  - self-checks X-Wing against official vector 0 and runs one full handshake
 *    before measuring, so no number comes from a broken build
 *  - cycle counts come from SysTick extended to 64 bits by a wrap interrupt
 *  - peak stack per operation is measured by stack painting
 * Output goes to USB serial (open the COM/tty port at any baud rate, press Enter to start).
 * SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/rand.h"
#include "hardware/clocks.h"
#include "hardware/structs/systick.h"
#include "hardware/exception.h"
#include "hedge.h"
#include "bench_core.h"
#include "xwing_vectors.h"

/* ---------------- randomness ---------------- */
int hedge_randombytes(uint8_t *out, size_t n)
{
    while (n) {
        uint32_t r = get_rand_32();
        size_t c = n < 4 ? n : 4;
        memcpy(out, &r, c);
        out += c; n -= c;
    }
    return 0;
}
int randombytes(uint8_t *out, size_t outlen);
int randombytes(uint8_t *out, size_t outlen) { return hedge_randombytes(out, outlen); }

/* ---------------- 64-bit cycle counter from SysTick ---------------- */
static volatile uint32_t wraps = 0;
static void systick_isr(void) { wraps++; }

static void cyc_init(void)
{
    exception_set_exclusive_handler(SYSTICK_EXCEPTION, systick_isr);
    systick_hw->rvr = 0x00FFFFFF;
    systick_hw->cvr = 0;
    systick_hw->csr = 0x7;               /* processor clock, interrupt, enable */
}
uint64_t bench_now(void)
{
    uint32_t w1, v, w2;
    do { w1 = wraps; v = systick_hw->cvr; w2 = wraps; } while (w1 != w2);
    return ((uint64_t)w1 << 24) + (0x00FFFFFFu - (v & 0x00FFFFFFu));
}
const char *bench_unit(void) { return "cycles"; }

/* ---------------- stack painting ---------------- */
#define PAINT_BYTES (48 * 1024)
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
    return PAINT_BYTES - 4 * i;          /* bytes overwritten below the caller's frame */
}
#define STACK_OF(name, op) do { paint(); op; printf("%-34s %8u bytes peak stack\n", name, (unsigned)measure()); } while (0)

static const uint8_t ID_G[8] = { 'G', 'W', '0', '0', '0', '0', '0', '1' };
static const uint8_t ID_D[8] = { 'D', 'E', 'V', '0', '0', '4', '2', '0' };
static uint8_t KD[32];
static int lookup(const uint8_t id[8], uint8_t kd[32], void *arg)
{ (void)arg; if (memcmp(id, ID_D, 8)) return -1; memcpy(kd, KD, 32); return 0; }

static int self_test(void)
{
    static uint8_t pk[XWING_PK_BYTES], sk[32], ct[XWING_CT_BYTES], ss[32];
    static uint8_t m1[16], m2[HEDGE_M2_BYTES], m3[HEDGE_M3_BYTES], m4[16], peer[8];
    static hedge_device d; static hedge_gateway g; static hedge_session_keys a, b;
    int ok = 1;
    xwing_keygen_derand(pk, sk, xv_seed[0]);
    ok &= memcmp(pk, xv_pk[0], XWING_PK_BYTES) == 0;
    xwing_encaps_derand(ct, ss, pk, xv_eseed[0]);
    ok &= memcmp(ct, xv_ct[0], XWING_CT_BYTES) == 0 && memcmp(ss, xv_ss[0], 32) == 0;
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
    static uint8_t pk[XWING_PK_BYTES], sk[32], ct[XWING_CT_BYTES], ss[32], c[96], m[64];
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

int main(void)
{
    set_sys_clock_khz(133000, true);
    stdio_init_all();
    gpio_init(PICO_DEFAULT_LED_PIN); gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
    /* Wait until a serial terminal is open, then until the user presses Enter,
     * so nothing is printed before anyone is watching. LED blinks while waiting. */
    while (!stdio_usb_connected()) { gpio_xor_mask(1u << PICO_DEFAULT_LED_PIN); sleep_ms(250); }
    for (;;) {
        printf("\rHEDGE benchmark ready. Press ENTER to start.   ");
        int ch = getchar_timeout_us(1000000);
        if (ch == '\r' || ch == '\n') break;
        gpio_xor_mask(1u << PICO_DEFAULT_LED_PIN);
    }
    gpio_put(PICO_DEFAULT_LED_PIN, 1);
    printf("\nRunning, please wait about 1-3 minutes (LED stays on until done)...\n");
    cyc_init();
    printf("\nHEDGE on RP2040 (Cortex-M0+), clk_sys = %lu Hz\n", (unsigned long)clock_get_hz(clk_sys));
    printf("self-test (X-Wing vector + full handshake): %s\n", self_test() ? "PASS" : "FAIL");
    bench_run(201, 21);
    stack_report();
    printf("done.\n");
    gpio_put(PICO_DEFAULT_LED_PIN, 0);
    while (true) sleep_ms(1000);
}
