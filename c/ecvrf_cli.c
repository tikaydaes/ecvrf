/* CLI wrapper for ECVRF-EDWARDS25519-SHA512-TAI C implementation. */
#include "ecvrf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_char(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *hex, uint8_t **out, size_t *out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    size_t byte_len = hex_len / 2;
    uint8_t *buf = malloc(byte_len > 0 ? byte_len : 1);
    if (!buf) return -1;
    for (size_t i = 0; i < byte_len; i++) {
        int hi = hex_char(hex[2 * i]);
        int lo = hex_char(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            free(buf);
            return -1;
        }
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    *out = buf;
    *out_len = byte_len;
    return 0;
}

static void print_hex(const uint8_t *data, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        putchar(hex[data[i] >> 4]);
        putchar(hex[data[i] & 0x0f]);
    }
    putchar('\n');
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: ecvrf_cli prove <sk_hex> <alpha_hex> | verify <pk_hex> <pi_hex> <alpha_hex> | derive-pk <sk_hex>\n");
        return 2;
    }

    if (strcmp(argv[1], "prove") == 0) {
        if (argc < 4) return 2;
        uint8_t *sk = NULL, *alpha = NULL;
        size_t sk_len = 0, alpha_len = 0;
        if (hex_decode(argv[2], &sk, &sk_len) != 0 || sk_len != ECVRF_SK_LEN ||
            hex_decode(argv[3], &alpha, &alpha_len) != 0) {
            free(sk);
            free(alpha);
            return 2;
        }
        uint8_t pi[ECVRF_PROOF_LEN];
        int rc = ecvrf_prove(sk, alpha, alpha_len, pi);
        free(sk);
        free(alpha);
        if (rc != 0) return 1;
        print_hex(pi, ECVRF_PROOF_LEN);
        return 0;
    } else if (strcmp(argv[1], "verify") == 0) {
        if (argc < 5) return 2;
        uint8_t *pk = NULL, *pi = NULL, *alpha = NULL;
        size_t pk_len = 0, pi_len = 0, alpha_len = 0;
        if (hex_decode(argv[2], &pk, &pk_len) != 0 ||
            hex_decode(argv[3], &pi, &pi_len) != 0 ||
            hex_decode(argv[4], &alpha, &alpha_len) != 0) {
            free(pk);
            free(pi);
            free(alpha);
            return 2;
        }
        uint8_t beta[ECVRF_BETA_LEN];
        int valid = ecvrf_verify(pk, pk_len, pi, pi_len, alpha, alpha_len, beta);
        free(pk);
        free(pi);
        free(alpha);
        if (!valid) return 1;
        print_hex(beta, ECVRF_BETA_LEN);
        return 0;
    } else if (strcmp(argv[1], "derive-pk") == 0) {
        if (argc < 3) return 2;
        uint8_t *sk = NULL;
        size_t sk_len = 0;
        if (hex_decode(argv[2], &sk, &sk_len) != 0 || sk_len != ECVRF_SK_LEN) {
            free(sk);
            return 2;
        }
        uint8_t pk[ECVRF_PK_LEN];
        int rc = ecvrf_derive_pk(sk, pk);
        free(sk);
        if (rc != 0) return 1;
        print_hex(pk, ECVRF_PK_LEN);
        return 0;
    }

    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 2;
}
