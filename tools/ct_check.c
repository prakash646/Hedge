/* Constant-time check with Valgrind memcheck (the ctgrind / TIMECOP method).
 *
 * Every secret input is marked "undefined" with VALGRIND_MAKE_MEM_UNDEFINED.
 * Memcheck then reports any conditional branch or memory address that depends
 * on a secret ("Conditional jump or move depends on uninitialised value(s)",
 * "Use of uninitialised value of size N"). Values that are public by design
 * are declassified: messages put on the wire, transcript hashes, and the
 * accept/reject result of tag verification (HEDGE_DECLASSIFY in src/).
 *
 * Secrets: device key K_D, the device's encapsulation randomness, the
 * gateway's decapsulation key, the shared secret and everything derived from
 * it (ms, tau_D, tau_G, session keys), record keys and record plaintexts.
 *
 * Build (see tools/ct_check.sh) with -DHEDGE_CT_TESTING and mlkem-native's
 * MLK_CONFIG_CT_TESTING_ENABLED, then run under
 *     valgrind --error-exitcode=1 --track-origins=yes ./ct_check
 * A clean run prints "CT-CHECK: 0 errors" in Valgrind's summary.
 * SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>
#include <valgrind/memcheck.h>
#include "hedge.h"

#define SECRET(p, n)  VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#define PUBLIC(p, n)  VALGRIND_MAKE_MEM_DEFINED((p), (n))

static const uint8_t ID_G[8] = { 'G', 'W', '0', '0', '0', '0', '0', '1' };
static const uint8_t ID_D[8] = { 'D', 'E', 'V', '0', '0', '4', '2', '0' };
static uint8_t KD[32];

/* Identity lookup on the gateway is a table search; the identifier is the
 * routing key, not a cryptographic secret, so it is declassified here. The
 * returned K_D is secret. */
static int lookup(const uint8_t id[8], uint8_t kd[32], void *arg)
{
    (void)arg;
    uint8_t idp[8];
    memcpy(idp, id, 8);
    PUBLIC(idp, 8);
    if (memcmp(idp, ID_D, 8) != 0) return -1;
    memcpy(kd, KD, 32);
    SECRET(kd, 32);
    return 0;
}

/* Positive control (argument "leak"): a deliberately variable-time comparison of
 * a secret tag, which the check must flag. Guards against a vacuous clean run. */
static int __attribute__((noinline)) leaky_compare(const uint8_t *a, const uint8_t *b)
{
    for (int i = 0; i < 16; i++) if (a[i] != b[i]) return 0;
    return 1;
}

int main(int argc, char **argv)
{
    static uint8_t m1[HEDGE_M1_BYTES], m2[HEDGE_M2_BYTES], m3[HEDGE_M3_BYTES], m4[HEDGE_M4_BYTES];
    static uint8_t eseed[XWING_ESEED_BYTES], peer[8];
    static hedge_device d; static hedge_gateway g; static hedge_session_keys kd_, kg_;
    int rounds = 3;

    for (int r = 0; r < rounds; r++) {
        hedge_randombytes(KD, sizeof KD);
        hedge_randombytes(eseed, sizeof eseed);

        /* --- M1, M2 (gateway key generation: decapsulation key is secret) --- */
        if (hedge_dev_start(&d, ID_D, m1) != 0) return 2;
        if (hedge_gw_respond(&g, ID_G, m1, m2) != 0) return 2;
        PUBLIC(m2, sizeof m2);                 /* sent on the wire */
        SECRET(g.xw_sk, sizeof g.xw_sk);
        PUBLIC(g.th2, sizeof g.th2);           /* hash of public messages */

        /* --- M3 (device): K_D and encapsulation randomness are secret --- */
        SECRET(KD, sizeof KD);
        SECRET(eseed, sizeof eseed);
        if (hedge_dev_respond_derand(&d, KD, m2, m3, eseed) != 0) return 3;
        PUBLIC(m3, sizeof m3);                 /* sent on the wire */
        PUBLIC(d.th3, sizeof d.th3);           /* hash of public messages */
        PUBLIC(&d.state, sizeof d.state);

        /* --- M4 (gateway) --- */
        int gr = hedge_gw_finish(&g, lookup, NULL, m3, m4, &kg_, peer);
        PUBLIC(&gr, sizeof gr);
        if (gr != 0) return 4;
        PUBLIC(m4, sizeof m4);                 /* sent on the wire */

        if (argc > 1 && strcmp(argv[1], "leak") == 0) {
            volatile int e = leaky_compare(d.tau_d, m4);   /* tau_D is secret */
            (void)e;
        }
        /* --- device finish --- */
        int dr = hedge_dev_finish(&d, m4, &kd_);
        PUBLIC(&dr, sizeof dr);
        if (dr != 0) return 5;

        /* --- record layer: keys and plaintext secret --- */
        {
            uint8_t msg[64], c[64 + HEDGE_COMB_OVERHEAD], back[64];
            memset(msg, 0x5a, sizeof msg);
            SECRET(msg, sizeof msg);
            for (uint64_t seq = 0; seq < 4; seq++) {
                if (hedge_record_seal(c, &kd_.k_dg, kd_.iv_dg, seq, NULL, 0, msg, sizeof msg) != 0) return 6;
                PUBLIC(c, sizeof c);           /* sent on the wire */
                int o = hedge_record_open(back, &kg_.k_dg, kg_.iv_dg, seq, NULL, 0, c, sizeof c);
                PUBLIC(&o, sizeof o);
                if (o != 0) return 7;
                c[3] ^= 1;                     /* forged record: rejection path */
                o = hedge_record_open(back, &kg_.k_dg, kg_.iv_dg, seq, NULL, 0, c, sizeof c);
                PUBLIC(&o, sizeof o);
                if (o == 0) return 8;
            }
        }
        /* a wrong M4 must be rejected without secret-dependent branching */
        {
            hedge_dev_start(&d, ID_D, m1);
            hedge_gw_respond(&g, ID_G, m1, m2);
            PUBLIC(m2, sizeof m2);
            SECRET(KD, sizeof KD);
            hedge_dev_respond_derand(&d, KD, m2, m3, eseed);
            PUBLIC(m3, sizeof m3); PUBLIC(d.th3, sizeof d.th3); PUBLIC(&d.state, sizeof d.state);
            memset(m4, 0, sizeof m4);
            int bad = hedge_dev_finish(&d, m4, &kd_);
            PUBLIC(&bad, sizeof bad);
            if (bad == 0) return 9;
        }
        PUBLIC(KD, sizeof KD);
    }
    printf("ct_check: %d handshakes, %d records sealed/opened/forged per handshake; see Valgrind summary\n", rounds, 4);
    return 0;
}
