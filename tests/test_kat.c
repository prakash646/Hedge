/* Known-answer tests for every component primitive:
 *   Ascon-AEAD128, Ascon-Hash256, Ascon-CXOF128  (NIST SP 800-232 KATs from ascon-c)
 *   Romulus-N                                     (final-round KATs from lwc-finalists)
 *   SHA3-256, SHAKE256                            (FIPS 202 empty-string values)
 *   X-Wing                                        (draft-connolly-cfrg-xwing-kem vectors)
 * SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hedge.h"
#include "sha3.h"
#include "xwing_vectors.h"

int ascon_hash256(unsigned char *out, const unsigned char *in, unsigned long long inlen);
int ascon_cxof128(unsigned char *out, unsigned long long outlen,
                  const unsigned char *in, unsigned long long inlen,
                  const unsigned char *cs, unsigned long long cslen);

#ifndef KAT_DIR
#define KAT_DIR "kat"
#endif

static int failures = 0;
#define CHECK(cond, ...) do { if (!(cond)) { failures++; fprintf(stderr, "FAIL: " __VA_ARGS__); fprintf(stderr, "\n"); } } while (0)

static size_t unhex(uint8_t *out, const char *s)
{
    size_t n = 0;
    while (s[0] && s[1] && s[0] != '\n' && s[0] != '\r') {
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1) break;
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

/* Reads "Name = HEX" lines; fields stored in fixed slots in the order given. */
typedef struct { const char *name; uint8_t buf[4096]; size_t len; int set; } field;

static int read_record(FILE *f, field *fs, int nf)
{
    char line[9000];
    int got = 0;
    for (int i = 0; i < nf; i++) fs[i].set = 0;
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '\n' || line[0] == '\r') { if (got) return 1; continue; }
        for (int i = 0; i < nf; i++) {
            size_t L = strlen(fs[i].name);
            if (strncmp(line, fs[i].name, L) == 0 && line[L] == ' ' && line[L + 1] == '=') {
                const char *v = line + L + 2;
                while (*v == ' ') v++;
                fs[i].len = unhex(fs[i].buf, v);
                fs[i].set = 1;
                got = 1;
            }
        }
    }
    return got;
}

static FILE *open_kat(const char *name)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s", KAT_DIR, name);
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); failures++; }
    return f;
}

static void test_aead(const char *file, const char *label,
                      int (*enc)(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t),
                      int (*dec)(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t))
{
    static field fs[5] = { { "Key" }, { "Nonce" }, { "PT" }, { "AD" }, { "CT" } };
    static uint8_t out[4096], back[4096];
    FILE *f = open_kat(file);
    int n = 0;
    if (!f) return;
    while (read_record(f, fs, 5)) {
        enc(out, fs[0].buf, fs[1].buf, fs[3].buf, fs[3].len, fs[2].buf, fs[2].len);
        CHECK(fs[4].len == fs[2].len + 16 && memcmp(out, fs[4].buf, fs[4].len) == 0, "%s enc vector %d", label, n + 1);
        CHECK(dec(back, fs[0].buf, fs[1].buf, fs[3].buf, fs[3].len, fs[4].buf, fs[4].len) == 0 &&
              memcmp(back, fs[2].buf, fs[2].len) == 0, "%s dec vector %d", label, n + 1);
        n++;
    }
    fclose(f);
    printf("  %-16s %4d vectors\n", label, n);
}

static void test_hash256(void)
{
    static field fs[2] = { { "Msg" }, { "MD" } };
    uint8_t md[32];
    FILE *f = open_kat("LWC_HASH_KAT_128_256.txt");
    int n = 0;
    if (!f) return;
    while (read_record(f, fs, 2)) {
        ascon_hash256(md, fs[0].buf, fs[0].len);
        CHECK(memcmp(md, fs[1].buf, 32) == 0, "Ascon-Hash256 vector %d", n + 1);
        n++;
    }
    fclose(f);
    printf("  %-16s %4d vectors\n", "Ascon-Hash256", n);
}

static void test_cxof128(void)
{
    static field fs[3] = { { "Msg" }, { "Z" }, { "MD" } };
    uint8_t md[64];
    FILE *f = open_kat("LWC_CXOF_KAT_128_512.txt");
    int n = 0;
    if (!f) return;
    while (read_record(f, fs, 3)) {
        ascon_cxof128(md, fs[2].len, fs[0].buf, fs[0].len, fs[1].buf, fs[1].len);
        CHECK(memcmp(md, fs[2].buf, fs[2].len) == 0, "Ascon-CXOF128 vector %d", n + 1);
        n++;
    }
    fclose(f);
    printf("  %-16s %4d vectors\n", "Ascon-CXOF128", n);
}

static void test_sha3(void)
{
    static const uint8_t sha3_256_empty[32] = {
        0xa7,0xff,0xc6,0xf8,0xbf,0x1e,0xd7,0x66,0x51,0xc1,0x47,0x56,0xa0,0x61,0xd6,0x62,
        0xf5,0x80,0xff,0x4d,0xe4,0x3b,0x49,0xfa,0x82,0xd8,0x0a,0x4b,0x80,0xf8,0x43,0x4a };
    static const uint8_t shake256_empty[32] = {
        0x46,0xb9,0xdd,0x2b,0x0b,0xa8,0x8d,0x13,0x23,0x3b,0x3f,0xeb,0x74,0x3e,0xeb,0x24,
        0x3f,0xcd,0x52,0xea,0x62,0xb8,0x1b,0x82,0xb5,0x0c,0x27,0x64,0x6e,0xd5,0x76,0x2f };
    uint8_t md[32];
    sha3_ctx_t c;
    sha3("", 0, md, 32);
    CHECK(memcmp(md, sha3_256_empty, 32) == 0, "SHA3-256(\"\")");
    shake256_init(&c); shake_xof(&c); shake_out(&c, md, 32);
    CHECK(memcmp(md, shake256_empty, 32) == 0, "SHAKE256(\"\")");
    printf("  %-16s %4d vectors\n", "SHA3/SHAKE", 2);
}

static void test_xwing(void)
{
    static uint8_t pk[XWING_PK_BYTES], sk[XWING_SK_BYTES], ct[XWING_CT_BYTES], ss[32], ss2[32];
    for (int i = 0; i < XWING_NVEC; i++) {
        CHECK(xwing_keygen_derand(pk, sk, xv_seed[i]) == 0, "xwing keygen %d", i);
        CHECK(memcmp(pk, xv_pk[i], XWING_PK_BYTES) == 0, "xwing pk vector %d", i);
        CHECK(memcmp(sk, xv_sk[i], XWING_SK_BYTES) == 0, "xwing sk vector %d", i);
        CHECK(xwing_encaps_derand(ct, ss, pk, xv_eseed[i]) == 0, "xwing encaps %d", i);
        CHECK(memcmp(ct, xv_ct[i], XWING_CT_BYTES) == 0, "xwing ct vector %d", i);
        CHECK(memcmp(ss, xv_ss[i], 32) == 0, "xwing ss (encaps) vector %d", i);
        CHECK(xwing_decaps(ss2, xv_ct[i], xv_sk[i]) == 0 && memcmp(ss2, xv_ss[i], 32) == 0, "xwing ss (decaps) vector %d", i);
    }
    printf("  %-16s %4d vectors\n", "X-Wing", XWING_NVEC);
}

int main(void)
{
    printf("Known-answer tests\n");
    test_aead("LWC_AEAD_KAT_128_128.txt", "Ascon-AEAD128", hedge_ascon_encrypt, hedge_ascon_decrypt);
    test_aead("Romulus-N.txt", "Romulus-N", hedge_romulus_encrypt, hedge_romulus_decrypt);
    test_hash256();
    test_cxof128();
    test_sha3();
    test_xwing();
    printf(failures ? "KAT: %d FAILURES\n" : "KAT: all passed\n", failures);
    return failures ? 1 : 0;
}
