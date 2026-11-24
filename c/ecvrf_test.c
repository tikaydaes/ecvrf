/* Test runner for ECVRF-EDWARDS25519-SHA512-TAI C implementation. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ecvrf.h"
#include "vectors_data.h"

static int g_pass;
static int g_fail;

static void pass(void) { g_pass++; }
static void fail_msg(const char *test, const char *detail)
{
    g_fail++;
    fprintf(stderr, "FAIL [%s]: %s\n", test, detail);
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static uint8_t *hex_decode(const char *hex, size_t *out_len)
{
    size_t n = strlen(hex) / 2;
    uint8_t *buf = malloc(n > 0 ? n : 1);
    for (size_t i = 0; i < n; i++) {
        buf[i] = (uint8_t)((hex_val(hex[2 * i]) << 4) | hex_val(hex[2 * i + 1]));
    }
    *out_len = n;
    return buf;
}

int main(void)
{
    if (strcmp(VECTORS_SUITE, "ECVRF-EDWARDS25519-SHA512-TAI") != 0) {
        fail_msg("suite", VECTORS_SUITE);
        return 1;
    }

    for (size_t i = 0; i < NUM_TEST_VECTORS; i++) {
        const test_vector_t *v = &TEST_VECTORS[i];
        size_t sk_len, pk_len, alpha_len, pi_len, beta_len;
        uint8_t *sk = hex_decode(v->sk, &sk_len);
        uint8_t *want_pk = hex_decode(v->pk, &pk_len);
        uint8_t *alpha = hex_decode(v->alpha, &alpha_len);
        uint8_t *want_pi = hex_decode(v->pi, &pi_len);
        uint8_t *want_beta = hex_decode(v->beta, &beta_len);

        uint8_t got_pk[ECVRF_PK_LEN];
        if (ecvrf_derive_pk(sk, got_pk) != 0 || memcmp(got_pk, want_pk, ECVRF_PK_LEN) != 0) {
            fail_msg(v->label, "derive_pk mismatch");
        } else {
            pass();
        }

        if (!ecvrf_validate_pk(got_pk, ECVRF_PK_LEN)) {
            fail_msg(v->label, "validate_pk rejected valid key");
        } else {
            pass();
        }

        uint8_t got_pi[ECVRF_PROOF_LEN];
        if (ecvrf_prove(sk, alpha, alpha_len, got_pi) != 0 ||
            memcmp(got_pi, want_pi, ECVRF_PROOF_LEN) != 0) {
            fail_msg(v->label, "prove mismatch");
        } else {
            pass();
        }

        uint8_t got_beta[ECVRF_BETA_LEN];
        if (ecvrf_proof_to_hash(want_pi, pi_len, got_beta) != 0 ||
            memcmp(got_beta, want_beta, ECVRF_BETA_LEN) != 0) {
            fail_msg(v->label, "proof_to_hash mismatch");
        } else {
            pass();
        }

        memset(got_beta, 0, sizeof(got_beta));
        if (!ecvrf_verify(want_pk, pk_len, want_pi, pi_len, alpha, alpha_len, got_beta) ||
            memcmp(got_beta, want_beta, ECVRF_BETA_LEN) != 0) {
            fail_msg(v->label, "verify failed or beta mismatch");
        } else {
            pass();
        }

        free(sk);
        free(want_pk);
        free(alpha);
        free(want_pi);
        free(want_beta);
    }

    for (size_t i = 0; i < NUM_NEG_VECTORS; i++) {
        const neg_vector_t *v = &NEG_VECTORS[i];
        size_t pk_len, alpha_len, pi_len;
        uint8_t *pk = hex_decode(v->pk, &pk_len);
        uint8_t *alpha = hex_decode(v->alpha, &alpha_len);
        uint8_t *pi = hex_decode(v->pi, &pi_len);
        uint8_t beta[ECVRF_BETA_LEN];

        int valid = ecvrf_verify(pk, pk_len, pi, pi_len, alpha, alpha_len, beta);
        if (valid != v->expected_verify) {
            fail_msg(v->description, "unexpected verify result");
        } else {
            pass();
        }

        free(pk);
        free(alpha);
        free(pi);
    }

    printf("C tests: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
