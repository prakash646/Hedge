/* End-to-end handshake tests: success path, exact message sizes, record exchange,
 * and the negative cases the security analysis relies on.
 * SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>
#include "hedge.h"

_Static_assert(HEDGE_M1_BYTES == 16, "M1 size");
#ifdef HEDGE_UNHEDGED
_Static_assert(HEDGE_M2_BYTES == 1208, "M2 size (baseline)");
_Static_assert(HEDGE_M3_BYTES == 1128, "M3 size (baseline)");
#else
_Static_assert(HEDGE_M2_BYTES == 1240, "M2 size");
_Static_assert(HEDGE_M3_BYTES == 1176, "M3 size");
#endif
_Static_assert(HEDGE_M4_BYTES == 16, "M4 size");

static int failures = 0, checks = 0;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { failures++; fprintf(stderr, "FAIL: " __VA_ARGS__); fprintf(stderr, "\n"); } } while (0)

static const uint8_t ID_G[8] = { 'G', 'W', '-', '0', '0', '0', '0', '1' };
static const uint8_t ID_D[8] = { 'D', 'E', 'V', '-', '0', '0', '4', '2' };
static uint8_t KD[32];

static int lookup(const uint8_t id[8], uint8_t kd[32], void *arg)
{
    (void)arg;
    if (memcmp(id, ID_D, 8) != 0) return -1;
    memcpy(kd, KD, 32);
    return 0;
}

typedef struct {
    uint8_t m1[HEDGE_M1_BYTES], m2[HEDGE_M2_BYTES], m3[HEDGE_M3_BYTES], m4[HEDGE_M4_BYTES];
    hedge_device d; hedge_gateway g;
    hedge_session_keys kd_, kg_;
    uint8_t peer[8];
} run;

/* Executes the four steps; a tamper hook may modify messages in flight. */
enum { T_NONE, T_M2_NONCE, T_M2_ID, T_M2_EK, T_M3_CT, T_M3_C3, T_M4 };
static int handshake(run *r, const uint8_t dev_kd[32], const uint8_t dev_id[8], int tamper, int *dev_ok, int *gw_ok)
{
    *dev_ok = *gw_ok = 0;
    if (hedge_dev_start(&r->d, dev_id, r->m1)) return -1;
    if (hedge_gw_respond(&r->g, ID_G, r->m1, r->m2)) return -1;
    if (tamper == T_M2_NONCE) r->m2[3] ^= 0x01;
    if (tamper == T_M2_ID)    r->m2[16] ^= 0x01;
    if (tamper == T_M2_EK)    r->m2[24 + 500] ^= 0x01;
    if (hedge_dev_respond(&r->d, dev_kd, r->m2, r->m3)) return -2;
    if (tamper == T_M3_CT) r->m3[100] ^= 0x01;
    if (tamper == T_M3_C3) r->m3[XWING_CT_BYTES + 3] ^= 0x01;
    *gw_ok = hedge_gw_finish(&r->g, lookup, NULL, r->m3, r->m4, &r->kg_, r->peer) == 0;
    if (tamper == T_M4) r->m4[0] ^= 0x01;
    *dev_ok = hedge_dev_finish(&r->d, r->m4, &r->kd_) == 0;
    return 0;
}

static void test_success(void)
{
    static run r;
    int dok, gok;
    uint8_t msg[40] = "temperature=23.5C;humidity=41%", c[40 + HEDGE_COMB_OVERHEAD], b[40];
    CHECK(handshake(&r, KD, ID_D, T_NONE, &dok, &gok) == 0 && dok && gok, "honest handshake");
    CHECK(memcmp(&r.kd_, &r.kg_, sizeof r.kd_) == 0, "session keys agree");
    CHECK(memcmp(r.peer, ID_D, 8) == 0, "gateway learned device id");
    /* device -> gateway records */
    for (uint64_t seq = 0; seq < 5; seq++) {
        CHECK(hedge_record_seal(c, &r.kd_.k_dg, r.kd_.iv_dg, seq, NULL, 0, msg, sizeof msg) == 0, "seal");
        CHECK(hedge_record_open(b, &r.kg_.k_dg, r.kg_.iv_dg, seq, NULL, 0, c, sizeof c) == 0 && memcmp(b, msg, sizeof msg) == 0, "open seq %llu", (unsigned long long)seq);
        CHECK(hedge_record_open(b, &r.kg_.k_dg, r.kg_.iv_dg, seq + 1, NULL, 0, c, sizeof c) != 0, "wrong seq rejected");
        CHECK(hedge_record_open(b, &r.kg_.k_gd, r.kg_.iv_gd, seq, NULL, 0, c, sizeof c) != 0, "wrong direction rejected");
    }
    /* distinct sessions -> distinct keys */
    {
        static run r2;
        handshake(&r2, KD, ID_D, T_NONE, &dok, &gok);
        CHECK(dok && gok && memcmp(&r.kd_, &r2.kd_, sizeof r.kd_) != 0, "fresh keys per session");
    }
}

static void test_tamper(void)
{
    static const struct { int t; const char *name; } cases[] = {
        { T_M2_NONCE, "M2 nonce" }, { T_M2_ID, "M2 gateway id" }, { T_M2_EK, "M2 encapsulation key" },
        { T_M3_CT, "M3 KEM ciphertext" }, { T_M3_C3, "M3 encrypted record" }, { T_M4, "M4 gateway tag" } };
    static run r;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        int dok, gok;
        handshake(&r, KD, ID_D, cases[i].t, &dok, &gok);
        /* The device must never accept a tampered run. The gateway must reject
         * every tamper that reaches it before M4 is sent. */
        CHECK(!dok, "device accepted tampered %s", cases[i].name);
        if (cases[i].t != T_M4) CHECK(!gok, "gateway accepted tampered %s", cases[i].name);
        printf("  tamper %-22s device %-8s gateway %s\n", cases[i].name, dok ? "ACCEPT" : "reject", gok ? "accept" : "reject");
    }
}

static void test_wrong_credentials(void)
{
    static run r;
    int dok, gok;
    uint8_t bad[32];
    memcpy(bad, KD, 32); bad[0] ^= 1;
    handshake(&r, bad, ID_D, T_NONE, &dok, &gok);
    CHECK(!gok && !dok, "wrong K_D must fail both sides");
    printf("  wrong device key:          device %s gateway %s\n", dok ? "ACCEPT" : "reject", gok ? "ACCEPT" : "reject");
    {
        const uint8_t unknown[8] = { 'D', 'E', 'V', '-', '9', '9', '9', '9' };
        handshake(&r, KD, unknown, T_NONE, &dok, &gok);
        CHECK(!gok && !dok, "unknown device id must fail");
        printf("  unknown device id:         device %s gateway %s\n", dok ? "ACCEPT" : "reject", gok ? "ACCEPT" : "reject");
    }
}

/* Active MITM replaces ek with its own key. It learns ss and the device identity
 * (documented limitation, goal G4 is passive-only) but cannot complete either side. */
static void test_mitm_ek(void)
{
    static run r;
    static uint8_t m2x[HEDGE_M2_BYTES], adv_sk[XWING_SK_BYTES], ss[32], m4x[16];
    static hedge_gateway g;
    hedge_session_keys k;
    uint8_t peer[8];
    int dok;

    hedge_dev_start(&r.d, ID_D, r.m1);
    hedge_gw_respond(&g, ID_G, r.m1, r.m2);
    memcpy(m2x, r.m2, HEDGE_M2_BYTES);
    xwing_keygen(m2x + 24, adv_sk);                       /* attacker's ek */
    hedge_dev_respond(&r.d, KD, m2x, r.m3);
    CHECK(xwing_decaps(ss, r.m3, adv_sk) == 0, "attacker decapsulates");
    /* Attacker can recompute th2 and k_hs and decrypt C3 -> learns ID_D (expected). */
    {
        hedge_seg s[2] = { { r.m1, 16 }, { m2x, HEDGE_M2_BYTES } };
        uint8_t th2[HEDGE_TH_BYTES], o[48], pt[24];
        hedge_comb_key kh;
        hedge_hstar(th2, s, 2);
        hedge_kdf(o, 48, ss, 32, "hs", th2, HEDGE_TH_BYTES);
        memcpy(kh.k_out, o, 16); memcpy(kh.k_in, o + 16, 16);
        int ok = hedge_comb_decrypt(pt, &kh, o + 32, th2, HEDGE_TH_BYTES, r.m3 + XWING_CT_BYTES, HEDGE_C3_BYTES) == 0;
        CHECK(ok && memcmp(pt, ID_D, 8) == 0, "active attacker learns device id (documented limitation)");
        printf("  MITM ek swap: attacker learns device id: %s (expected; identity privacy is passive-only)\n", ok ? "yes" : "no");
    }
    /* Relaying M3 to the real gateway fails (transcript and KEM secret differ). */
    CHECK(hedge_gw_finish(&g, lookup, NULL, r.m3, m4x, &k, peer) != 0, "gateway rejects relayed M3");
    /* Without K_D the attacker cannot produce tau_G; try a random guess. */
    hedge_randombytes(m4x, 16);
    dok = hedge_dev_finish(&r.d, m4x, &k) == 0;
    CHECK(!dok, "device rejects forged M4");
    printf("  MITM ek swap: gateway rejects relayed M3, device rejects forged M4\n");
}

static void test_replay(void)
{
    static run a, b;
    int dok, gok;
    handshake(&a, KD, ID_D, T_NONE, &dok, &gok);
    /* new gateway session, attacker replays old M3 */
    hedge_dev_start(&b.d, ID_D, b.m1);
    hedge_gw_respond(&b.g, ID_G, b.m1, b.m2);
    CHECK(hedge_gw_finish(&b.g, lookup, NULL, a.m3, b.m4, &b.kg_, b.peer) != 0, "replayed M3 rejected");
    printf("  replayed M3 in a new session: rejected\n");
}

int main(void)
{
    hedge_randombytes(KD, sizeof KD);
    printf("Handshake tests (message sizes M1..M4 = %d, %d, %d, %d bytes; total %d)\n",
           HEDGE_M1_BYTES, HEDGE_M2_BYTES, HEDGE_M3_BYTES, HEDGE_M4_BYTES,
           HEDGE_M1_BYTES + HEDGE_M2_BYTES + HEDGE_M3_BYTES + HEDGE_M4_BYTES);
    test_success();
    test_tamper();
    test_wrong_credentials();
    test_mitm_ek();
    test_replay();
    printf(failures ? "HANDSHAKE: %d of %d checks FAILED\n" : "HANDSHAKE: all %d checks passed\n",
           failures ? failures : checks, checks);
    return failures ? 1 : 0;
}
