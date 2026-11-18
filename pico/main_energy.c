/* HEDGE energy-measurement firmware for the Raspberry Pi Pico (RP2040, Cortex-M0+).
 * Runs WITHOUT a PC: power the board from the measuring instrument.
 *
 *  1. Self-test (X-Wing vector 0 + one full handshake).
 *     FAIL -> LED blinks fast (5 Hz) forever; do not measure.
 *  2. Then repeats forever:
 *       IDLE   phase, 5 s : LED off, marker GP15 low,  CPU idle (sleep)
 *       ACTIVE phase, 10 s: LED on,  marker GP15 high, complete HEDGE handshakes
 *                           (device + gateway side) run back to back on the CPU.
 *
 * Energy per device handshake = V_supply * I_active * T_device, with T_device the
 * device cycle count from the benchmark firmware divided by 133 MHz.
 * Both phases use the same 133 MHz clock as the benchmark.
 * SPDX-License-Identifier: MIT */
#include <string.h>
#include "pico/stdlib.h"
#include "pico/rand.h"
#include "hardware/clocks.h"
#include "hedge.h"
#include "xwing_vectors.h"

#define MARKER_PIN 15
#define LED PICO_DEFAULT_LED_PIN

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

static const uint8_t ID_G[8] = { 'G', 'W', '0', '0', '0', '0', '0', '1' };
static const uint8_t ID_D[8] = { 'D', 'E', 'V', '0', '0', '4', '2', '0' };
static uint8_t KD[32];
static int lookup(const uint8_t id[8], uint8_t kd[32], void *arg)
{ (void)arg; if (memcmp(id, ID_D, 8)) return -1; memcpy(kd, KD, 32); return 0; }

static uint8_t m1[16], m2[HEDGE_M2_BYTES], m3[HEDGE_M3_BYTES], m4[16], peer[8];
static hedge_device d; static hedge_gateway g; static hedge_session_keys a, b;

static int handshake(void)
{
    int ok = 1;
    ok &= hedge_dev_start(&d, ID_D, m1) == 0;
    ok &= hedge_gw_respond(&g, ID_G, m1, m2) == 0;
    ok &= hedge_dev_respond(&d, KD, m2, m3) == 0;
    ok &= hedge_gw_finish(&g, lookup, NULL, m3, m4, &b, peer) == 0;
    ok &= hedge_dev_finish(&d, m4, &a) == 0;
    ok &= memcmp(&a, &b, sizeof a) == 0;
    return ok;
}

static int self_test(void)
{
    static uint8_t pk[XWING_PK_BYTES], sk[32], ct[XWING_CT_BYTES], ss[32];
    int ok = 1;
    xwing_keygen_derand(pk, sk, xv_seed[0]);
    ok &= memcmp(pk, xv_pk[0], XWING_PK_BYTES) == 0;
    xwing_encaps_derand(ct, ss, pk, xv_eseed[0]);
    ok &= memcmp(ct, xv_ct[0], XWING_CT_BYTES) == 0 && memcmp(ss, xv_ss[0], 32) == 0;
    hedge_randombytes(KD, 32);
    ok &= handshake();
    return ok;
}

int main(void)
{
    set_sys_clock_khz(133000, true);
    gpio_init(LED); gpio_set_dir(LED, GPIO_OUT); gpio_put(LED, 0);
    gpio_init(MARKER_PIN); gpio_set_dir(MARKER_PIN, GPIO_OUT); gpio_put(MARKER_PIN, 0);

    if (!self_test()) {
        for (;;) { gpio_xor_mask(1u << LED); sleep_ms(100); }
    }
    /* two slow blinks: self-test passed, measurement cycle starts */
    for (int i = 0; i < 4; i++) { gpio_xor_mask(1u << LED); sleep_ms(500); }

    for (;;) {
        gpio_put(LED, 0); gpio_put(MARKER_PIN, 0);
        sleep_ms(5000);                                   /* IDLE */
        gpio_put(LED, 1); gpio_put(MARKER_PIN, 1);
        absolute_time_t end = make_timeout_time_ms(10000); /* ACTIVE */
        while (absolute_time_diff_us(get_absolute_time(), end) > 0) {
            if (!handshake()) {
                gpio_put(MARKER_PIN, 0);
                for (;;) { gpio_xor_mask(1u << LED); sleep_ms(100); }
            }
        }
    }
}
