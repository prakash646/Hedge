/* Emits deterministic vectors for H*, KDF and Comb so an independent
 * implementation (tools/ref_check.py) can cross-check them.
 * SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>
#include "hedge.h"

static void hex(const char *k, const uint8_t *p, size_t n, int last)
{
    printf("  \"%s\": \"", k);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\"%s\n", last ? "" : ",");
}

int main(void)
{
    uint8_t x[1300], ikm[64], ctx[80], out[96], th[64], m[37], c[37 + 32];
    hedge_comb_key k;
    uint8_t n[16];
    for (size_t i = 0; i < sizeof x; i++) x[i] = (uint8_t)(i * 7 + 3);
    for (size_t i = 0; i < sizeof ikm; i++) ikm[i] = (uint8_t)(i + 1);
    for (size_t i = 0; i < sizeof ctx; i++) ctx[i] = (uint8_t)(0xA0 ^ i);
    for (size_t i = 0; i < sizeof m; i++) m[i] = (uint8_t)(0x30 + i);
    for (int i = 0; i < 16; i++) { k.k_out[i] = (uint8_t)i; k.k_in[i] = (uint8_t)(0xF0 | i); n[i] = (uint8_t)(0x10 + i); }

    printf("{\n");
    hex("x", x, sizeof x, 0); hex("ikm", ikm, sizeof ikm, 0); hex("ctx", ctx, sizeof ctx, 0);
    { hedge_seg s[2] = { { x, 1000 }, { x + 1000, 300 } }; hedge_hstar(th, s, 2); hex("hstar", th, 64, 0); }
    hedge_kdf(out, 32, ikm, 64, "ms", ctx, 64); hex("kdf_ms_32", out, 32, 0);
    hedge_kdf(out, 96, ikm, 32, "app", ctx, 80); hex("kdf_app_96", out, 96, 0);
    hedge_kdf(out, 16, ikm, 32, "finD", ctx, 64); hex("kdf_finD_16", out, 16, 0);
    hex("m", m, sizeof m, 0); hex("k_out", k.k_out, 16, 0); hex("k_in", k.k_in, 16, 0); hex("n", n, 16, 0);
    hedge_comb_encrypt(c, &k, n, ctx, 64, m, sizeof m); hex("comb_ct", c, sizeof c, 1);
    printf("}\n");
    return 0;
}
