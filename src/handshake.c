/* HEDGE handshake (paper Fig. 2, Table II).
 *
 *  D -> G  M1 = n_D
 *  G -> D  M2 = n_G || ID_G || ek                (fresh X-Wing key pair)
 *  D -> G  M3 = ct || C3,  C3 = Comb.Enc(k_hs, iv_hs, th2, ID_D || tau_D)
 *  G -> D  M4 = tau_G
 *
 *  th2 = H*(M1 || M2)
 *  (k_hs.out, k_hs.in, iv_hs) = KDF(ss, "hs", th2, 48)
 *  th3 = H*(th2 || ct || ID_D)
 *  ms  = KDF(ss || K_D, "ms", th3, 32)
 *  tau_D = KDF(ms, "finD", th3, 16)
 *  tau_G = KDF(ms, "finG", th3 || tau_D, 16)
 *  session keys = KDF(ms, "app", th3 || tau_D, 96)
 *
 * SPDX-License-Identifier: MIT */
#include <string.h>
#include "hedge.h"

enum { ST_IDLE = 0, ST_D_SENT_M1, ST_D_SENT_M3, ST_G_SENT_M2, ST_DONE, ST_FAILED };

static int derive_hs(hedge_comb_key *k, uint8_t iv[16],
                     const uint8_t ss[32], const uint8_t th2[HEDGE_TH_BYTES])
{
    uint8_t o[48];
    if (hedge_kdf(o, sizeof o, ss, 32, "hs", th2, HEDGE_TH_BYTES) != 0) return -1;
    memcpy(k->k_out, o, 16);
    memcpy(k->k_in, o + 16, 16);
    memcpy(iv, o + 32, 16);
    hedge_wipe(o, sizeof o);
    return 0;
}

static int derive_th3(uint8_t th3[HEDGE_TH_BYTES], const uint8_t th2[HEDGE_TH_BYTES],
                      const uint8_t ct[XWING_CT_BYTES], const uint8_t id[HEDGE_ID_BYTES])
{
    hedge_seg s[3] = { { th2, HEDGE_TH_BYTES }, { ct, XWING_CT_BYTES }, { id, HEDGE_ID_BYTES } };
    return hedge_hstar(th3, s, 3);
}

static int derive_ms(uint8_t ms[32], const uint8_t ss[32], const uint8_t kd[HEDGE_KD_BYTES],
                     const uint8_t th3[HEDGE_TH_BYTES])
{
    uint8_t ikm[32 + HEDGE_KD_BYTES];
    int r;
    memcpy(ikm, ss, 32);
    memcpy(ikm + 32, kd, HEDGE_KD_BYTES);
    r = hedge_kdf(ms, 32, ikm, sizeof ikm, "ms", th3, HEDGE_TH_BYTES);
    hedge_wipe(ikm, sizeof ikm);
    return r;
}

static int derive_tau_g(uint8_t tau_g[16], const uint8_t ms[32],
                        const uint8_t th3[HEDGE_TH_BYTES], const uint8_t tau_d[16])
{
    uint8_t ctx[HEDGE_TH_BYTES + 16];
    memcpy(ctx, th3, HEDGE_TH_BYTES);
    memcpy(ctx + HEDGE_TH_BYTES, tau_d, 16);
    return hedge_kdf(tau_g, 16, ms, 32, "finG", ctx, sizeof ctx);
}

static int derive_app(hedge_session_keys *keys, const uint8_t ms[32],
                      const uint8_t th3[HEDGE_TH_BYTES], const uint8_t tau_d[16])
{
    uint8_t ctx[HEDGE_TH_BYTES + 16], o[96];
    memcpy(ctx, th3, HEDGE_TH_BYTES);
    memcpy(ctx + HEDGE_TH_BYTES, tau_d, 16);
    if (hedge_kdf(o, sizeof o, ms, 32, "app", ctx, sizeof ctx) != 0) return -1;
    memcpy(keys->k_dg.k_out, o, 16);      memcpy(keys->k_dg.k_in, o + 16, 16); memcpy(keys->iv_dg, o + 32, 16);
    memcpy(keys->k_gd.k_out, o + 48, 16); memcpy(keys->k_gd.k_in, o + 64, 16); memcpy(keys->iv_gd, o + 80, 16);
    hedge_wipe(o, sizeof o);
    return 0;
}

/* ============================ Device ============================ */

int hedge_dev_start(hedge_device *d, const uint8_t id[HEDGE_ID_BYTES], uint8_t m1[HEDGE_M1_BYTES])
{
    memset(d, 0, sizeof *d);
    memcpy(d->id, id, HEDGE_ID_BYTES);
    if (hedge_randombytes(d->m1, HEDGE_M1_BYTES) != 0) { d->state = ST_FAILED; return -1; }
    memcpy(m1, d->m1, HEDGE_M1_BYTES);
    d->state = ST_D_SENT_M1;
    return 0;
}

int hedge_dev_respond_derand(hedge_device *d, const uint8_t kd[HEDGE_KD_BYTES],
                             const uint8_t m2[HEDGE_M2_BYTES], uint8_t m3[HEDGE_M3_BYTES],
                             const uint8_t eseed[XWING_ESEED_BYTES])
{
    const uint8_t *ek = m2 + 16 + HEDGE_ID_BYTES;
    uint8_t ss[32], th2[HEDGE_TH_BYTES], iv[16], pt[HEDGE_ID_BYTES + HEDGE_FIN_BYTES];
    hedge_comb_key khs;
    hedge_seg s[2] = { { d->m1, HEDGE_M1_BYTES }, { m2, HEDGE_M2_BYTES } };
    int r = -1;

    if (d->state != ST_D_SENT_M1) goto out;
    if (xwing_encaps_derand(m3, ss, ek, eseed) != 0) goto out;            /* ct = m3[0..1119] */
    if (hedge_hstar(th2, s, 2) != 0) goto out;
    if (derive_hs(&khs, iv, ss, th2) != 0) goto out;
    if (derive_th3(d->th3, th2, m3, d->id) != 0) goto out;
    if (derive_ms(d->ms, ss, kd, d->th3) != 0) goto out;
    if (hedge_kdf(d->tau_d, 16, d->ms, 32, "finD", d->th3, HEDGE_TH_BYTES) != 0) goto out;
    memcpy(pt, d->id, HEDGE_ID_BYTES);
    memcpy(pt + HEDGE_ID_BYTES, d->tau_d, HEDGE_FIN_BYTES);
    if (hedge_comb_encrypt(m3 + XWING_CT_BYTES, &khs, iv, th2, HEDGE_TH_BYTES, pt, sizeof pt) != 0) goto out;
    r = 0;
out:
    hedge_wipe(ss, sizeof ss); hedge_wipe(&khs, sizeof khs); hedge_wipe(iv, sizeof iv);
    hedge_wipe(pt, sizeof pt);
    d->state = (r == 0) ? ST_D_SENT_M3 : ST_FAILED;
    if (r != 0) { hedge_wipe(d->ms, sizeof d->ms); }
    return r;
}

int hedge_dev_respond(hedge_device *d, const uint8_t kd[HEDGE_KD_BYTES],
                      const uint8_t m2[HEDGE_M2_BYTES], uint8_t m3[HEDGE_M3_BYTES])
{
    uint8_t eseed[XWING_ESEED_BYTES];
    int r;
    if (hedge_randombytes(eseed, sizeof eseed) != 0) return -1;
    r = hedge_dev_respond_derand(d, kd, m2, m3, eseed);
    hedge_wipe(eseed, sizeof eseed);
    return r;
}

int hedge_dev_finish(hedge_device *d, const uint8_t m4[HEDGE_M4_BYTES], hedge_session_keys *keys)
{
    uint8_t tau_g[16];
    int r = -1;
    if (d->state != ST_D_SENT_M3) goto out;
    if (derive_tau_g(tau_g, d->ms, d->th3, d->tau_d) != 0) goto out;
    {
        int eq = hedge_ct_equal(tau_g, m4, 16);
        HEDGE_DECLASSIFY(&eq, sizeof eq);             /* accept/reject is public */
        if (!eq) goto out;
    }
    if (derive_app(keys, d->ms, d->th3, d->tau_d) != 0) goto out;
    r = 0;
out:
    hedge_wipe(tau_g, sizeof tau_g);
    hedge_wipe(d->ms, sizeof d->ms);
    d->state = (r == 0) ? ST_DONE : ST_FAILED;
    return r;
}

/* ============================ Gateway ============================ */

int hedge_gw_respond(hedge_gateway *g, const uint8_t id[HEDGE_ID_BYTES],
                     const uint8_t m1[HEDGE_M1_BYTES], uint8_t m2[HEDGE_M2_BYTES])
{
    hedge_seg s[2] = { { m1, HEDGE_M1_BYTES }, { m2, HEDGE_M2_BYTES } };
    memset(g, 0, sizeof *g);
    memcpy(g->id, id, HEDGE_ID_BYTES);
    if (hedge_randombytes(m2, 16) != 0) goto fail;                       /* n_G */
    memcpy(m2 + 16, id, HEDGE_ID_BYTES);                                  /* ID_G */
    if (xwing_keygen(m2 + 16 + HEDGE_ID_BYTES, g->xw_sk) != 0) goto fail; /* fresh ek */
    if (hedge_hstar(g->th2, s, 2) != 0) goto fail;
    g->state = ST_G_SENT_M2;
    return 0;
fail:
    hedge_wipe(g, sizeof *g);
    g->state = ST_FAILED;
    return -1;
}

int hedge_gw_finish(hedge_gateway *g, hedge_lookup_fn lookup, void *arg,
                    const uint8_t m3[HEDGE_M3_BYTES], uint8_t m4[HEDGE_M4_BYTES],
                    hedge_session_keys *keys, uint8_t peer_id[HEDGE_ID_BYTES])
{
    uint8_t ss[32], iv[16], pt[HEDGE_ID_BYTES + HEDGE_FIN_BYTES], kd[HEDGE_KD_BYTES];
    uint8_t th3[HEDGE_TH_BYTES], ms[32], tau_d[16];
    hedge_comb_key khs;
    int r = -1;

    if (g->state != ST_G_SENT_M2) goto out;
    {
        int dr = xwing_decaps(ss, m3, g->xw_sk);
        hedge_wipe(g->xw_sk, sizeof g->xw_sk);                           /* erase dk now */
        if (dr != 0) goto out;
    }
    if (derive_hs(&khs, iv, ss, g->th2) != 0) goto out;
    if (hedge_comb_decrypt(pt, &khs, iv, g->th2, HEDGE_TH_BYTES,
                           m3 + XWING_CT_BYTES, HEDGE_C3_BYTES) != 0) goto out;
    if (lookup(pt, kd, arg) != 0) goto out;                              /* unknown device */
    if (derive_th3(th3, g->th2, m3, pt) != 0) goto out;
    if (derive_ms(ms, ss, kd, th3) != 0) goto out;
    if (hedge_kdf(tau_d, 16, ms, 32, "finD", th3, HEDGE_TH_BYTES) != 0) goto out;
    {
        int eq = hedge_ct_equal(tau_d, pt + HEDGE_ID_BYTES, 16);
        HEDGE_DECLASSIFY(&eq, sizeof eq);             /* accept/reject is public */
        if (!eq) goto out;
    }
    if (derive_tau_g(m4, ms, th3, tau_d) != 0) goto out;
    if (derive_app(keys, ms, th3, tau_d) != 0) goto out;
    memcpy(peer_id, pt, HEDGE_ID_BYTES);
    r = 0;
out:
    hedge_wipe(ss, sizeof ss); hedge_wipe(iv, sizeof iv); hedge_wipe(pt, sizeof pt);
    hedge_wipe(kd, sizeof kd); hedge_wipe(ms, sizeof ms); hedge_wipe(&khs, sizeof khs);
    hedge_wipe(th3, sizeof th3); hedge_wipe(tau_d, sizeof tau_d);
    hedge_wipe(g->xw_sk, sizeof g->xw_sk);
    if (r != 0) memset(m4, 0, HEDGE_M4_BYTES);
    g->state = (r == 0) ? ST_DONE : ST_FAILED;
    return r;
}
