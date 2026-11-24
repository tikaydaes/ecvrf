//! RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI (suite byte `0x03`).
//!
//! Uses `curve25519-dalek` for constant-time Edwards25519 scalar multiplication
//! and `sha2` for SHA-512. Strictly enforces canonical RFC 8032 point decoding
//! and rejects small-order public keys per RFC 9381 Section 5.6.1.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha512};
use thiserror::Error;

pub const SUITE_BYTE: u8 = 0x03;
pub const SECRET_KEY_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 32;
pub const PROOF_LEN: usize = 80;
pub const BETA_LEN: usize = 64;
const CHALLENGE_LEN: usize = 16;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EcvrfError {
    #[error("secret key must be 32 bytes")]
    InvalidSecretKey,
    #[error("invalid or small-order public key")]
    InvalidPublicKey,
    #[error("proof must be 80 bytes")]
    InvalidProofLength,
    #[error("invalid or non-canonical curve point")]
    InvalidPoint,
    #[error("proof scalar s >= group order")]
    InvalidScalar,
    #[error("encode_to_curve failed after 256 iterations")]
    EncodeToCurveFailed,
    #[error("proof verification failed")]
    VerificationFailed,
}

/// Checks that the 255-bit little-endian y-coordinate is strictly less than p = 2^255 - 19.
fn is_canonical_y(bytes: &[u8; 32]) -> bool {
    if (bytes[31] & 0x7f) != 0x7f {
        return true;
    }
    for &b in &bytes[1..31] {
        if b != 0xff {
            return true;
        }
    }
    bytes[0] < 0xed
}

/// Strictly decodes a 32-byte canonical RFC 8032 Edwards25519 point.
/// Rejects y >= p and non-canonical x == 0 with sign bit 1.
fn decode_point(bytes: &[u8]) -> Result<EdwardsPoint, EcvrfError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| EcvrfError::InvalidPoint)?;
    if !is_canonical_y(&arr) {
        return Err(EcvrfError::InvalidPoint);
    }
    let pt = CompressedEdwardsY(arr)
        .decompress()
        .ok_or(EcvrfError::InvalidPoint)?;
    if pt.compress().to_bytes() != arr {
        return Err(EcvrfError::InvalidPoint);
    }
    Ok(pt)
}

fn expand_secret_key(sk: &[u8]) -> Result<(Scalar, [u8; 32]), EcvrfError> {
    if sk.len() != SECRET_KEY_LEN {
        return Err(EcvrfError::InvalidSecretKey);
    }
    let hash: [u8; 64] = Sha512::digest(sk).into();
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&hash[..32]);
    x_bytes[0] &= 248;
    x_bytes[31] &= 127;
    x_bytes[31] |= 64;
    let x = Scalar::from_bytes_mod_order(x_bytes);

    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&hash[32..]);
    Ok((x, prefix))
}

/// RFC 9381 Section 5.6.1: decode pk and reject small-order torsion keys.
fn validate_key(pk: &[u8]) -> Result<EdwardsPoint, EcvrfError> {
    let y = decode_point(pk).map_err(|_| EcvrfError::InvalidPublicKey)?;
    if y.mul_by_cofactor().is_identity() {
        return Err(EcvrfError::InvalidPublicKey);
    }
    Ok(y)
}

/// Reports whether `pk` is a valid canonical non-small-order 32-byte Ed25519 public key.
pub fn is_public_key(pk: &[u8]) -> bool {
    validate_key(pk).is_ok()
}

/// RFC 9381 Section 5.4.1.1: try_and_increment with cofactor clearing (H = 8 * pt).
fn encode_to_curve_tai(pk: &[u8], alpha: &[u8]) -> Result<EdwardsPoint, EcvrfError> {
    for ctr in 0u8..=255 {
        let mut hasher = Sha512::new();
        hasher.update([SUITE_BYTE, 0x01]);
        hasher.update(pk);
        hasher.update(alpha);
        hasher.update([ctr, 0x00]);
        let hash: [u8; 64] = hasher.finalize().into();
        if let Ok(pt) = decode_point(&hash[..32]) {
            return Ok(pt.mul_by_cofactor());
        }
    }
    Err(EcvrfError::EncodeToCurveFailed)
}

/// RFC 9381 Section 5.4.2.2: deterministic nonce via SHA-512.
fn nonce_generation(prefix: &[u8; 32], h: &EdwardsPoint) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(prefix);
    hasher.update(h.compress().as_bytes());
    let k_string: [u8; 64] = hasher.finalize().into();
    Scalar::from_bytes_mod_order_wide(&k_string)
}

/// RFC 9381 Section 5.4.3: 5-point challenge truncated to 16 bytes.
fn challenge_generation(
    y: &EdwardsPoint,
    h: &EdwardsPoint,
    gamma: &EdwardsPoint,
    u: &EdwardsPoint,
    v: &EdwardsPoint,
) -> (Scalar, [u8; CHALLENGE_LEN]) {
    let mut hasher = Sha512::new();
    hasher.update([SUITE_BYTE, 0x02]);
    hasher.update(y.compress().as_bytes());
    hasher.update(h.compress().as_bytes());
    hasher.update(gamma.compress().as_bytes());
    hasher.update(u.compress().as_bytes());
    hasher.update(v.compress().as_bytes());
    hasher.update([0x00]);
    let hash: [u8; 64] = hasher.finalize().into();

    let mut c_bytes = [0u8; CHALLENGE_LEN];
    c_bytes.copy_from_slice(&hash[..CHALLENGE_LEN]);
    let mut c_padded = [0u8; 32];
    c_padded[..CHALLENGE_LEN].copy_from_slice(&c_bytes);
    let c = Scalar::from_bytes_mod_order(c_padded);
    (c, c_bytes)
}

/// RFC 9381 Section 5.2: SHA-512(0x03 || 0x03 || encode(8 * Gamma) || 0x00).
fn gamma_to_hash(gamma: &EdwardsPoint) -> [u8; BETA_LEN] {
    let cofactor_gamma = gamma.mul_by_cofactor();
    let mut hasher = Sha512::new();
    hasher.update([SUITE_BYTE, 0x03]);
    hasher.update(cofactor_gamma.compress().as_bytes());
    hasher.update([0x00]);
    hasher.finalize().into()
}

fn decode_proof(pi: &[u8]) -> Result<(EdwardsPoint, Scalar, [u8; CHALLENGE_LEN], Scalar), EcvrfError> {
    if pi.len() != PROOF_LEN {
        return Err(EcvrfError::InvalidProofLength);
    }
    let gamma = decode_point(&pi[..32])?;

    let mut c_bytes = [0u8; CHALLENGE_LEN];
    c_bytes.copy_from_slice(&pi[32..48]);
    let mut c_padded = [0u8; 32];
    c_padded[..CHALLENGE_LEN].copy_from_slice(&c_bytes);
    let c = Scalar::from_bytes_mod_order(c_padded);

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&pi[48..80]);
    let s_opt: Option<Scalar> = Scalar::from_canonical_bytes(s_bytes).into();
    let s = s_opt.ok_or(EcvrfError::InvalidScalar)?;

    Ok((gamma, c, c_bytes, s))
}

/// Derives the 32-byte Ed25519 public key from a 32-byte seed `sk`.
pub fn derive_public_key(sk: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN], EcvrfError> {
    let (x, _) = expand_secret_key(sk)?;
    let y = EdwardsPoint::mul_base(&x);
    Ok(y.compress().to_bytes())
}

/// RFC 9381 Section 5.1: generates an 80-byte proof `Gamma (32) || c (16) || s (32)`.
pub fn prove(sk: &[u8], alpha: &[u8]) -> Result<[u8; PROOF_LEN], EcvrfError> {
    let (x, prefix) = expand_secret_key(sk)?;
    let y = EdwardsPoint::mul_base(&x);
    let pk = y.compress().to_bytes();

    let h = encode_to_curve_tai(&pk, alpha)?;
    let gamma = h * x;
    let k = nonce_generation(&prefix, &h);
    let u = EdwardsPoint::mul_base(&k);
    let v = h * k;
    let (c, c_bytes) = challenge_generation(&y, &h, &gamma, &u, &v);
    let s = k + c * x;

    let mut pi = [0u8; PROOF_LEN];
    pi[..32].copy_from_slice(gamma.compress().as_bytes());
    pi[32..48].copy_from_slice(&c_bytes);
    pi[48..80].copy_from_slice(s.as_bytes());
    Ok(pi)
}

/// RFC 9381 Section 5.2: extracts the 64-byte VRF output beta without verifying the proof.
pub fn proof_to_hash(pi: &[u8]) -> Result<[u8; BETA_LEN], EcvrfError> {
    let (gamma, _, _, _) = decode_proof(pi)?;
    Ok(gamma_to_hash(&gamma))
}

/// RFC 9381 Section 5.3: verifies `pi` for `pk` and `alpha`, returning 64-byte beta on success.
pub fn verify(pk: &[u8], pi: &[u8], alpha: &[u8]) -> Result<[u8; BETA_LEN], EcvrfError> {
    let y = validate_key(pk)?;
    let (gamma, c, c_bytes, s) = decode_proof(pi)?;
    let h = encode_to_curve_tai(pk, alpha)?;

    let u = ED25519_BASEPOINT_POINT * s - y * c;
    let v = h * s - gamma * c;
    let (_, c_prime_bytes) = challenge_generation(&y, &h, &gamma, &u, &v);

    if c_bytes != c_prime_bytes {
        return Err(EcvrfError::VerificationFailed);
    }
    Ok(gamma_to_hash(&gamma))
}
