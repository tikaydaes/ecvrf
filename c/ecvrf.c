/* RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI (suite 0x03) C11 implementation.
 * Uses OpenSSL BIGNUM for Edwards25519 arithmetic and EVP SHA-512.
 */

#include "ecvrf.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#define CHALLENGE_LEN 16

typedef struct {
    BIGNUM *x;
    BIGNUM *y;
    BIGNUM *z;
    BIGNUM *t;
} ed_point_t;

typedef struct {
    BIGNUM *p;          /* 2^255 - 19 */
    BIGNUM *q;          /* 2^252 + 27742317777372353535851937790883648493 */
    BIGNUM *d;          /* -121665 / 121666 mod p */
    BIGNUM *sqrt_m1;    /* 2^((p-1)/4) mod p */
    BIGNUM *p_minus_2;  /* p - 2 */
    BIGNUM *p_p3_div8;  /* (p + 3) / 8 */
    ed_point_t base;
} ed_params_t;

static int sha512_hash(const uint8_t *data, size_t len, uint8_t out[64])
{
    unsigned int out_len = 0;
    if (EVP_Digest(data, len, out, &out_len, EVP_sha512(), NULL) != 1 || out_len != 64) {
        return -1;
    }
    return 0;
}

static int point_init(ed_point_t *pt)
{
    pt->x = BN_new();
    pt->y = BN_new();
    pt->z = BN_new();
    pt->t = BN_new();
    if (!pt->x || !pt->y || !pt->z || !pt->t) {
        BN_free(pt->x);
        BN_free(pt->y);
        BN_free(pt->z);
        BN_free(pt->t);
        pt->x = pt->y = pt->z = pt->t = NULL;
        return -1;
    }
    return 0;
}

static void point_free(ed_point_t *pt)
{
    BN_free(pt->x);
    BN_free(pt->y);
    BN_free(pt->z);
    BN_free(pt->t);
    pt->x = pt->y = pt->z = pt->t = NULL;
}

static int point_set_identity(ed_point_t *pt)
{
    BN_zero(pt->x);
    BN_zero(pt->t);
    if (!BN_one(pt->y) || !BN_one(pt->z)) {
        return -1;
    }
    return 0;
}

static int point_copy(ed_point_t *dst, const ed_point_t *src)
{
    if (!BN_copy(dst->x, src->x) ||
        !BN_copy(dst->y, src->y) ||
        !BN_copy(dst->z, src->z) ||
        !BN_copy(dst->t, src->t)) {
        return -1;
    }
    return 0;
}

/* Compute x_recover(y) returning even x in [0, p-1], or -1 if not on curve. */
static int x_recover(const ed_params_t *ep, const BIGNUM *y, BIGNUM *x_out, BN_CTX *ctx)
{
    int ret = -1;
    BN_CTX_start(ctx);
    BIGNUM *yy = BN_CTX_get(ctx);
    BIGNUM *u = BN_CTX_get(ctx);
    BIGNUM *v = BN_CTX_get(ctx);
    BIGNUM *vi = BN_CTX_get(ctx);
    BIGNUM *xx = BN_CTX_get(ctx);
    BIGNUM *x = BN_CTX_get(ctx);
    BIGNUM *x2 = BN_CTX_get(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);
    if (!tmp) goto done;

    if (!BN_mod_sqr(yy, y, ep->p, ctx)) goto done;
    if (!BN_mod_sub(u, yy, BN_value_one(), ep->p, ctx)) goto done;
    if (!BN_mod_mul(tmp, ep->d, yy, ep->p, ctx)) goto done;
    if (!BN_mod_add(v, tmp, BN_value_one(), ep->p, ctx)) goto done;
    if (!BN_mod_exp(vi, v, ep->p_minus_2, ep->p, ctx)) goto done;
    if (!BN_mod_mul(xx, u, vi, ep->p, ctx)) goto done;

    if (!BN_mod_exp(x, xx, ep->p_p3_div8, ep->p, ctx)) goto done;
    if (!BN_mod_sqr(x2, x, ep->p, ctx)) goto done;
    if (BN_cmp(x2, xx) != 0) {
        if (!BN_mod_mul(x, x, ep->sqrt_m1, ep->p, ctx)) goto done;
        if (!BN_mod_sqr(x2, x, ep->p, ctx)) goto done;
        if (BN_cmp(x2, xx) != 0) goto done;
    }
    if (BN_is_odd(x)) {
        if (!BN_sub(x, ep->p, x)) goto done;
    }
    if (!BN_copy(x_out, x)) goto done;
    ret = 0;

done:
    BN_CTX_end(ctx);
    return ret;
}

static int params_init(ed_params_t *ep, BN_CTX *ctx)
{
    memset(ep, 0, sizeof(*ep));
    ep->p = BN_new();
    ep->q = BN_new();
    ep->d = BN_new();
    ep->sqrt_m1 = BN_new();
    ep->p_minus_2 = BN_new();
    ep->p_p3_div8 = BN_new();
    if (!ep->p || !ep->q || !ep->d || !ep->sqrt_m1 || !ep->p_minus_2 || !ep->p_p3_div8) {
        return -1;
    }
    if (point_init(&ep->base) != 0) {
        return -1;
    }

    /* p = 2^255 - 19 */
    if (!BN_hex2bn(&ep->p, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")) {
        return -1;
    }
    /* q = 2^252 + 27742317777372353535851937790883648493 */
    if (!BN_hex2bn(&ep->q, "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")) {
        return -1;
    }
    if (!BN_copy(ep->p_minus_2, ep->p) || !BN_sub_word(ep->p_minus_2, 2)) {
        return -1;
    }
    /* (p + 3) / 8 */
    if (!BN_copy(ep->p_p3_div8, ep->p) || !BN_add_word(ep->p_p3_div8, 3) || !BN_rshift(ep->p_p3_div8, ep->p_p3_div8, 3)) {
        return -1;
    }

    BN_CTX_start(ctx);
    BIGNUM *num = BN_CTX_get(ctx);
    BIGNUM *den = BN_CTX_get(ctx);
    BIGNUM *den_inv = BN_CTX_get(ctx);
    BIGNUM *exp_m1 = BN_CTX_get(ctx);
    BIGNUM *two = BN_CTX_get(ctx);
    BIGNUM *by = BN_CTX_get(ctx);
    BIGNUM *bx = BN_CTX_get(ctx);
    int ok = 0;

    if (bx) {
        /* d = -121665 / 121666 mod p */
        if (BN_copy(num, ep->p) && BN_sub_word(num, 121665) &&
            BN_set_word(den, 121666) &&
            BN_mod_exp(den_inv, den, ep->p_minus_2, ep->p, ctx) &&
            BN_mod_mul(ep->d, num, den_inv, ep->p, ctx) &&
            /* sqrt(-1) = 2^((p-1)/4) mod p */
            BN_copy(exp_m1, ep->p) && BN_sub_word(exp_m1, 1) && BN_rshift(exp_m1, exp_m1, 2) &&
            BN_set_word(two, 2) &&
            BN_mod_exp(ep->sqrt_m1, two, exp_m1, ep->p, ctx) &&
            /* B_y = 4 / 5 mod p */
            BN_set_word(num, 4) && BN_set_word(den, 5) &&
            BN_mod_exp(den_inv, den, ep->p_minus_2, ep->p, ctx) &&
            BN_mod_mul(by, num, den_inv, ep->p, ctx) &&
            x_recover(ep, by, bx, ctx) == 0 &&
            BN_copy(ep->base.x, bx) &&
            BN_copy(ep->base.y, by) &&
            BN_one(ep->base.z) &&
            BN_mod_mul(ep->base.t, bx, by, ep->p, ctx)) {
            ok = 1;
        }
    }
    BN_CTX_end(ctx);
    return ok ? 0 : -1;
}

static void params_free(ed_params_t *ep)
{
    BN_free(ep->p);
    BN_free(ep->q);
    BN_free(ep->d);
    BN_free(ep->sqrt_m1);
    BN_free(ep->p_minus_2);
    BN_free(ep->p_p3_div8);
    point_free(&ep->base);
}

static int point_add(const ed_params_t *ep, ed_point_t *out,
                     const ed_point_t *p1, const ed_point_t *p2, BN_CTX *ctx)
{
    int ret = -1;
    BN_CTX_start(ctx);
    BIGNUM *a = BN_CTX_get(ctx);
    BIGNUM *b = BN_CTX_get(ctx);
    BIGNUM *c = BN_CTX_get(ctx);
    BIGNUM *dd = BN_CTX_get(ctx);
    BIGNUM *e = BN_CTX_get(ctx);
    BIGNUM *f = BN_CTX_get(ctx);
    BIGNUM *g = BN_CTX_get(ctx);
    BIGNUM *h = BN_CTX_get(ctx);
    BIGNUM *t1 = BN_CTX_get(ctx);
    BIGNUM *t2 = BN_CTX_get(ctx);
    if (!t2) goto done;

    if (!BN_mod_sub(t1, p1->y, p1->x, ep->p, ctx)) goto done;
    if (!BN_mod_sub(t2, p2->y, p2->x, ep->p, ctx)) goto done;
    if (!BN_mod_mul(a, t1, t2, ep->p, ctx)) goto done;

    if (!BN_mod_add(t1, p1->y, p1->x, ep->p, ctx)) goto done;
    if (!BN_mod_add(t2, p2->y, p2->x, ep->p, ctx)) goto done;
    if (!BN_mod_mul(b, t1, t2, ep->p, ctx)) goto done;

    if (!BN_mod_mul(t1, p1->t, p2->t, ep->p, ctx)) goto done;
    if (!BN_mod_mul(t2, t1, ep->d, ep->p, ctx)) goto done;
    if (!BN_mod_add(c, t2, t2, ep->p, ctx)) goto done;

    if (!BN_mod_mul(t1, p1->z, p2->z, ep->p, ctx)) goto done;
    if (!BN_mod_add(dd, t1, t1, ep->p, ctx)) goto done;

    if (!BN_mod_sub(e, b, a, ep->p, ctx)) goto done;
    if (!BN_mod_sub(f, dd, c, ep->p, ctx)) goto done;
    if (!BN_mod_add(g, dd, c, ep->p, ctx)) goto done;
    if (!BN_mod_add(h, b, a, ep->p, ctx)) goto done;

    if (!BN_mod_mul(out->x, e, f, ep->p, ctx)) goto done;
    if (!BN_mod_mul(out->y, g, h, ep->p, ctx)) goto done;
    if (!BN_mod_mul(out->z, f, g, ep->p, ctx)) goto done;
    if (!BN_mod_mul(out->t, e, h, ep->p, ctx)) goto done;
    ret = 0;

done:
    BN_CTX_end(ctx);
    return ret;
}

static int point_mul_by_8(const ed_params_t *ep, ed_point_t *out,
                          const ed_point_t *pt, BN_CTX *ctx)
{
    ed_point_t tmp;
    if (point_init(&tmp) != 0) return -1;
    int ret = -1;
    if (point_add(ep, &tmp, pt, pt, ctx) == 0 &&
        point_add(ep, out, &tmp, &tmp, ctx) == 0 &&
        point_add(ep, out, out, out, ctx) == 0) {
        ret = 0;
    }
    point_free(&tmp);
    return ret;
}

static int point_mul_raw(const ed_params_t *ep, ed_point_t *out,
                         const ed_point_t *pt, const BIGNUM *k, BN_CTX *ctx)
{
    ed_point_t acc, addend;
    if (point_init(&acc) != 0) return -1;
    if (point_init(&addend) != 0) {
        point_free(&acc);
        return -1;
    }
    int ret = -1;
    if (point_set_identity(&acc) != 0 || point_copy(&addend, pt) != 0) {
        goto done;
    }
    int bits = BN_num_bits(k);
    for (int i = 0; i < bits; i++) {
        if (BN_is_bit_set(k, i)) {
            if (point_add(ep, &acc, &acc, &addend, ctx) != 0) goto done;
        }
        if (i + 1 < bits) {
            if (point_add(ep, &addend, &addend, &addend, ctx) != 0) goto done;
        }
    }
    if (point_copy(out, &acc) != 0) goto done;
    ret = 0;

done:
    point_free(&acc);
    point_free(&addend);
    return ret;
}

static int point_mul(const ed_params_t *ep, ed_point_t *out,
                     const ed_point_t *pt, const BIGNUM *k, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *kr = BN_CTX_get(ctx);
    int ret = -1;
    if (kr && BN_nnmod(kr, k, ep->q, ctx)) {
        ret = point_mul_raw(ep, out, pt, kr, ctx);
    }
    BN_CTX_end(ctx);
    return ret;
}

static int point_is_identity(const ed_params_t *ep, const ed_point_t *pt, BN_CTX *ctx)
{
    int res = 0;
    BN_CTX_start(ctx);
    BIGNUM *xm = BN_CTX_get(ctx);
    BIGNUM *diff = BN_CTX_get(ctx);
    if (diff &&
        BN_nnmod(xm, pt->x, ep->p, ctx) &&
        BN_mod_sub(diff, pt->y, pt->z, ep->p, ctx)) {
        res = BN_is_zero(xm) && BN_is_zero(diff);
    }
    BN_CTX_end(ctx);
    return res;
}

static int point_to_bytes(const ed_params_t *ep, const ed_point_t *pt,
                          uint8_t out[32], BN_CTX *ctx)
{
    int ret = -1;
    BN_CTX_start(ctx);
    BIGNUM *zi = BN_CTX_get(ctx);
    BIGNUM *ax = BN_CTX_get(ctx);
    BIGNUM *ay = BN_CTX_get(ctx);
    if (!ay) goto done;

    if (!BN_mod_exp(zi, pt->z, ep->p_minus_2, ep->p, ctx)) goto done;
    if (!BN_mod_mul(ax, pt->x, zi, ep->p, ctx)) goto done;
    if (!BN_mod_mul(ay, pt->y, zi, ep->p, ctx)) goto done;
    if (BN_bn2lebinpad(ay, out, 32) != 32) goto done;
    if (BN_is_odd(ax)) {
        out[31] |= 0x80;
    }
    ret = 0;

done:
    BN_CTX_end(ctx);
    return ret;
}

/* Canonical RFC 8032 decoding. Returns 0 on success, -1 if invalid/non-canonical. */
static int bytes_to_point(const ed_params_t *ep, const uint8_t in[32],
                          ed_point_t *out, BN_CTX *ctx)
{
    int ret = -1;
    uint8_t y_bytes[32];
    memcpy(y_bytes, in, 32);
    int sign = (y_bytes[31] >> 7) & 1;
    y_bytes[31] &= 0x7f;

    BN_CTX_start(ctx);
    BIGNUM *y = BN_CTX_get(ctx);
    BIGNUM *x = BN_CTX_get(ctx);
    if (!x) goto done;

    if (!BN_lebin2bn(y_bytes, 32, y)) goto done;
    if (BN_cmp(y, ep->p) >= 0) goto done;
    if (x_recover(ep, y, x, ctx) != 0) goto done;
    if (BN_is_zero(x) && sign == 1) goto done;
    if ((BN_is_odd(x) ? 1 : 0) != sign) {
        if (!BN_sub(x, ep->p, x)) goto done;
    }
    if (!BN_copy(out->x, x) ||
        !BN_copy(out->y, y) ||
        !BN_one(out->z) ||
        !BN_mod_mul(out->t, x, y, ep->p, ctx)) {
        goto done;
    }
    ret = 0;

done:
    BN_CTX_end(ctx);
    return ret;
}

static int validate_key(const ed_params_t *ep, const uint8_t *pk, size_t pk_len,
                        ed_point_t *y_out, BN_CTX *ctx)
{
    if (!pk || pk_len != ECVRF_PK_LEN) return -1;
    if (bytes_to_point(ep, pk, y_out, ctx) != 0) return -1;
    ed_point_t cof;
    if (point_init(&cof) != 0) return -1;
    int ret = -1;
    if (point_mul_by_8(ep, &cof, y_out, ctx) == 0 && !point_is_identity(ep, &cof, ctx)) {
        ret = 0;
    }
    point_free(&cof);
    return ret;
}

static int expand_sk(const uint8_t sk[32], BIGNUM *x_out, uint8_t prefix_out[32])
{
    uint8_t h[64];
    if (sha512_hash(sk, 32, h) != 0) return -1;
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    if (!BN_lebin2bn(h, 32, x_out)) {
        OPENSSL_cleanse(h, sizeof(h));
        return -1;
    }
    memcpy(prefix_out, h + 32, 32);
    OPENSSL_cleanse(h, sizeof(h));
    return 0;
}

static int encode_to_curve_tai(const ed_params_t *ep, const uint8_t pk[32],
                               const uint8_t *alpha, size_t alpha_len,
                               ed_point_t *h_out, BN_CTX *ctx)
{
    size_t buf_len = 2 + 32 + alpha_len + 2;
    uint8_t *buf = malloc(buf_len);
    if (!buf) return -1;

    buf[0] = ECVRF_SUITE_BYTE;
    buf[1] = 0x01;
    memcpy(buf + 2, pk, 32);
    if (alpha_len > 0) {
        memcpy(buf + 34, alpha, alpha_len);
    }
    buf[34 + alpha_len + 1] = 0x00;

    ed_point_t pt;
    if (point_init(&pt) != 0) {
        free(buf);
        return -1;
    }

    int ret = -1;
    uint8_t hash[64];
    for (int ctr = 0; ctr < 256; ctr++) {
        buf[34 + alpha_len] = (uint8_t)ctr;
        if (sha512_hash(buf, buf_len, hash) != 0) break;
        if (bytes_to_point(ep, hash, &pt, ctx) == 0) {
            if (point_mul_by_8(ep, h_out, &pt, ctx) == 0) {
                ret = 0;
            }
            break;
        }
    }

    point_free(&pt);
    free(buf);
    return ret;
}

static int challenge_generation(const ed_params_t *ep,
                                const ed_point_t *y, const ed_point_t *h,
                                const ed_point_t *gamma, const ed_point_t *u,
                                const ed_point_t *v,
                                uint8_t c_bytes[CHALLENGE_LEN], BIGNUM *c_out,
                                BN_CTX *ctx)
{
    uint8_t in[2 + 5 * 32 + 1];
    in[0] = ECVRF_SUITE_BYTE;
    in[1] = 0x02;
    if (point_to_bytes(ep, y, in + 2, ctx) != 0 ||
        point_to_bytes(ep, h, in + 34, ctx) != 0 ||
        point_to_bytes(ep, gamma, in + 66, ctx) != 0 ||
        point_to_bytes(ep, u, in + 98, ctx) != 0 ||
        point_to_bytes(ep, v, in + 130, ctx) != 0) {
        return -1;
    }
    in[162] = 0x00;

    uint8_t hash[64];
    if (sha512_hash(in, sizeof(in), hash) != 0) return -1;
    memcpy(c_bytes, hash, CHALLENGE_LEN);
    if (c_out && !BN_lebin2bn(c_bytes, CHALLENGE_LEN, c_out)) return -1;
    return 0;
}

static int gamma_to_hash(const ed_params_t *ep, const ed_point_t *gamma,
                         uint8_t beta_out[64], BN_CTX *ctx)
{
    ed_point_t cof;
    if (point_init(&cof) != 0) return -1;
    uint8_t in[2 + 32 + 1];
    in[0] = ECVRF_SUITE_BYTE;
    in[1] = 0x03;
    in[34] = 0x00;
    int ret = -1;
    if (point_mul_by_8(ep, &cof, gamma, ctx) == 0 &&
        point_to_bytes(ep, &cof, in + 2, ctx) == 0 &&
        sha512_hash(in, sizeof(in), beta_out) == 0) {
        ret = 0;
    }
    point_free(&cof);
    return ret;
}

static int decode_proof(const ed_params_t *ep, const uint8_t *pi, size_t pi_len,
                        ed_point_t *gamma, uint8_t c_bytes[CHALLENGE_LEN],
                        BIGNUM *c_out, BIGNUM *s_out, BN_CTX *ctx)
{
    if (!pi || pi_len != ECVRF_PROOF_LEN) return -1;
    if (bytes_to_point(ep, pi, gamma, ctx) != 0) return -1;
    memcpy(c_bytes, pi + 32, CHALLENGE_LEN);
    if (c_out && !BN_lebin2bn(c_bytes, CHALLENGE_LEN, c_out)) return -1;
    if (s_out) {
        if (!BN_lebin2bn(pi + 48, 32, s_out)) return -1;
        if (BN_cmp(s_out, ep->q) >= 0) return -1;
    } else {
        BIGNUM *tmp = BN_lebin2bn(pi + 48, 32, NULL);
        if (!tmp) return -1;
        int cmp = BN_cmp(tmp, ep->q);
        BN_free(tmp);
        if (cmp >= 0) return -1;
    }
    return 0;
}

int ecvrf_validate_pk(const uint8_t *pk, size_t pk_len)
{
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return 0;
    ed_params_t ep;
    ed_point_t y;
    int ok = 0;
    if (params_init(&ep, ctx) == 0) {
        if (point_init(&y) == 0) {
            if (validate_key(&ep, pk, pk_len, &y, ctx) == 0) {
                ok = 1;
            }
            point_free(&y);
        }
        params_free(&ep);
    }
    BN_CTX_free(ctx);
    return ok;
}

int ecvrf_derive_pk(const uint8_t sk[ECVRF_SK_LEN], uint8_t pk_out[ECVRF_PK_LEN])
{
    if (!sk || !pk_out) return -1;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return -1;
    ed_params_t ep;
    ed_point_t y;
    BIGNUM *x = BN_new();
    uint8_t prefix[32];
    int ret = -1;

    if (x && params_init(&ep, ctx) == 0) {
        if (point_init(&y) == 0) {
            if (expand_sk(sk, x, prefix) == 0 &&
                point_mul_raw(&ep, &y, &ep.base, x, ctx) == 0 &&
                point_to_bytes(&ep, &y, pk_out, ctx) == 0) {
                ret = 0;
            }
            point_free(&y);
        }
        params_free(&ep);
    }
    OPENSSL_cleanse(prefix, sizeof(prefix));
    BN_clear_free(x);
    BN_CTX_free(ctx);
    return ret;
}

int ecvrf_prove(const uint8_t sk[ECVRF_SK_LEN],
                const uint8_t *alpha, size_t alpha_len,
                uint8_t pi_out[ECVRF_PROOF_LEN])
{
    if (!sk || !pi_out || (alpha_len > 0 && !alpha)) return -1;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return -1;

    ed_params_t ep;
    ed_point_t y, h, gamma, u, v;
    BIGNUM *x = BN_new();
    BIGNUM *k = BN_new();
    BIGNUM *c = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *cx = BN_new();
    uint8_t prefix[32];
    uint8_t pk[32];
    uint8_t h_bytes[32];
    uint8_t nonce_in[64];
    uint8_t k_hash[64];
    uint8_t c_bytes[CHALLENGE_LEN];
    int ret = -1;

    memset(&y, 0, sizeof(y));
    memset(&h, 0, sizeof(h));
    memset(&gamma, 0, sizeof(gamma));
    memset(&u, 0, sizeof(u));
    memset(&v, 0, sizeof(v));

    if (!x || !k || !c || !s || !cx) goto cleanup_bn;
    if (params_init(&ep, ctx) != 0) goto cleanup_params;
    if (point_init(&y) != 0 || point_init(&h) != 0 || point_init(&gamma) != 0 ||
        point_init(&u) != 0 || point_init(&v) != 0) {
        goto cleanup_pts;
    }

    if (expand_sk(sk, x, prefix) != 0) goto cleanup_pts;
    if (point_mul_raw(&ep, &y, &ep.base, x, ctx) != 0) goto cleanup_pts;
    if (point_to_bytes(&ep, &y, pk, ctx) != 0) goto cleanup_pts;
    if (encode_to_curve_tai(&ep, pk, alpha, alpha_len, &h, ctx) != 0) goto cleanup_pts;
    if (point_mul_raw(&ep, &gamma, &h, x, ctx) != 0) goto cleanup_pts;

    if (point_to_bytes(&ep, &h, h_bytes, ctx) != 0) goto cleanup_pts;
    memcpy(nonce_in, prefix, 32);
    memcpy(nonce_in + 32, h_bytes, 32);
    if (sha512_hash(nonce_in, 64, k_hash) != 0) goto cleanup_pts;
    if (!BN_lebin2bn(k_hash, 64, k)) goto cleanup_pts;
    if (!BN_nnmod(k, k, ep.q, ctx)) goto cleanup_pts;

    if (point_mul(&ep, &u, &ep.base, k, ctx) != 0) goto cleanup_pts;
    if (point_mul(&ep, &v, &h, k, ctx) != 0) goto cleanup_pts;
    if (challenge_generation(&ep, &y, &h, &gamma, &u, &v, c_bytes, c, ctx) != 0) goto cleanup_pts;

    if (!BN_mod_mul(cx, c, x, ep.q, ctx)) goto cleanup_pts;
    if (!BN_mod_add(s, k, cx, ep.q, ctx)) goto cleanup_pts;

    if (point_to_bytes(&ep, &gamma, pi_out, ctx) != 0) goto cleanup_pts;
    memcpy(pi_out + 32, c_bytes, CHALLENGE_LEN);
    if (BN_bn2lebinpad(s, pi_out + 48, 32) != 32) goto cleanup_pts;

    ret = 0;

cleanup_pts:
    point_free(&y);
    point_free(&h);
    point_free(&gamma);
    point_free(&u);
    point_free(&v);
cleanup_params:
    params_free(&ep);
cleanup_bn:
    OPENSSL_cleanse(prefix, sizeof(prefix));
    OPENSSL_cleanse(nonce_in, sizeof(nonce_in));
    OPENSSL_cleanse(k_hash, sizeof(k_hash));
    BN_clear_free(x);
    BN_clear_free(k);
    BN_free(c);
    BN_free(s);
    BN_clear_free(cx);
    BN_CTX_free(ctx);
    return ret;
}

int ecvrf_verify(const uint8_t *pk, size_t pk_len,
                 const uint8_t *pi, size_t pi_len,
                 const uint8_t *alpha, size_t alpha_len,
                 uint8_t beta_out[ECVRF_BETA_LEN])
{
    if (!pk || !pi || !beta_out || (alpha_len > 0 && !alpha)) return 0;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return 0;

    ed_params_t ep;
    ed_point_t y, h, gamma, u, v, p1, p2;
    BIGNUM *c = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *neg_c = BN_new();
    uint8_t c_bytes[CHALLENGE_LEN];
    uint8_t c_prime_bytes[CHALLENGE_LEN];
    int valid = 0;

    memset(&y, 0, sizeof(y));
    memset(&h, 0, sizeof(h));
    memset(&gamma, 0, sizeof(gamma));
    memset(&u, 0, sizeof(u));
    memset(&v, 0, sizeof(v));
    memset(&p1, 0, sizeof(p1));
    memset(&p2, 0, sizeof(p2));

    if (!c || !s || !neg_c) goto cleanup_bn;
    if (params_init(&ep, ctx) != 0) goto cleanup_params;
    if (point_init(&y) != 0 || point_init(&h) != 0 || point_init(&gamma) != 0 ||
        point_init(&u) != 0 || point_init(&v) != 0 || point_init(&p1) != 0 ||
        point_init(&p2) != 0) {
        goto cleanup_pts;
    }

    if (validate_key(&ep, pk, pk_len, &y, ctx) != 0) goto cleanup_pts;
    if (decode_proof(&ep, pi, pi_len, &gamma, c_bytes, c, s, ctx) != 0) goto cleanup_pts;
    if (encode_to_curve_tai(&ep, pk, alpha, alpha_len, &h, ctx) != 0) goto cleanup_pts;

    if (!BN_mod_sub(neg_c, ep.q, c, ep.q, ctx)) goto cleanup_pts;

    /* U = s*B - c*Y */
    if (point_mul(&ep, &p1, &ep.base, s, ctx) != 0) goto cleanup_pts;
    if (point_mul(&ep, &p2, &y, neg_c, ctx) != 0) goto cleanup_pts;
    if (point_add(&ep, &u, &p1, &p2, ctx) != 0) goto cleanup_pts;

    /* V = s*H - c*Gamma */
    if (point_mul(&ep, &p1, &h, s, ctx) != 0) goto cleanup_pts;
    if (point_mul(&ep, &p2, &gamma, neg_c, ctx) != 0) goto cleanup_pts;
    if (point_add(&ep, &v, &p1, &p2, ctx) != 0) goto cleanup_pts;

    if (challenge_generation(&ep, &y, &h, &gamma, &u, &v, c_prime_bytes, NULL, ctx) != 0) {
        goto cleanup_pts;
    }
    if (CRYPTO_memcmp(c_bytes, c_prime_bytes, CHALLENGE_LEN) != 0) goto cleanup_pts;
    if (gamma_to_hash(&ep, &gamma, beta_out, ctx) != 0) goto cleanup_pts;

    valid = 1;

cleanup_pts:
    point_free(&y);
    point_free(&h);
    point_free(&gamma);
    point_free(&u);
    point_free(&v);
    point_free(&p1);
    point_free(&p2);
cleanup_params:
    params_free(&ep);
cleanup_bn:
    BN_free(c);
    BN_free(s);
    BN_free(neg_c);
    BN_CTX_free(ctx);
    return valid;
}

int ecvrf_proof_to_hash(const uint8_t *pi, size_t pi_len,
                        uint8_t beta_out[ECVRF_BETA_LEN])
{
    if (!pi || !beta_out) return -1;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return -1;
    ed_params_t ep;
    ed_point_t gamma;
    uint8_t c_bytes[CHALLENGE_LEN];
    int ret = -1;

    if (params_init(&ep, ctx) == 0) {
        if (point_init(&gamma) == 0) {
            if (decode_proof(&ep, pi, pi_len, &gamma, c_bytes, NULL, NULL, ctx) == 0 &&
                gamma_to_hash(&ep, &gamma, beta_out, ctx) == 0) {
                ret = 0;
            }
            point_free(&gamma);
        }
        params_free(&ep);
    }
    BN_CTX_free(ctx);
    return ret;
}
