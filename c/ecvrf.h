#ifndef ECVRF_EDWARDS25519_SHA512_TAI_H
#define ECVRF_EDWARDS25519_SHA512_TAI_H

#include <stddef.h>
#include <stdint.h>

#define ECVRF_SUITE_BYTE 0x03
#define ECVRF_SK_LEN     32
#define ECVRF_PK_LEN     32
#define ECVRF_PROOF_LEN  80
#define ECVRF_BETA_LEN   64

/* Generate an 80-byte VRF proof (Gamma || c || s). Returns 0 on success, -1 on error. */
int ecvrf_prove(const uint8_t sk[ECVRF_SK_LEN],
                const uint8_t *alpha, size_t alpha_len,
                uint8_t pi_out[ECVRF_PROOF_LEN]);

/* Verify a VRF proof. Returns 1 if valid (fills beta_out), 0 if invalid. */
int ecvrf_verify(const uint8_t *pk, size_t pk_len,
                 const uint8_t *pi, size_t pi_len,
                 const uint8_t *alpha, size_t alpha_len,
                 uint8_t beta_out[ECVRF_BETA_LEN]);

/* Extract 64-byte VRF output (beta) from a proof. Returns 0 on success, -1 on error. */
int ecvrf_proof_to_hash(const uint8_t *pi, size_t pi_len,
                        uint8_t beta_out[ECVRF_BETA_LEN]);

/* Derive 32-byte Ed25519 public key from 32-byte seed. Returns 0 on success, -1 on error. */
int ecvrf_derive_pk(const uint8_t sk[ECVRF_SK_LEN], uint8_t pk_out[ECVRF_PK_LEN]);

/* Validate a 32-byte Ed25519 public key (canonical & non-small-order). Returns 1 if valid, 0 otherwise. */
int ecvrf_validate_pk(const uint8_t *pk, size_t pk_len);

#endif
