//! RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI (suite `0x03`) verify-only Solana
//! on-chain program.
//!
//! Instruction data layout: `pk (32) || pi (80) || alpha (variable)` (>= 112 bytes).
//! On success, sets the 64-byte VRF output `beta` as Solana return data.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha512};

pub const SUITE_BYTE: u8 = 0x03;
pub const PUBLIC_KEY_LEN: usize = 32;
pub const PROOF_LEN: usize = 80;
pub const BETA_LEN: usize = 64;
const CHALLENGE_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcvrfError {
    InvalidPublicKey,
    InvalidProofLength,
    InvalidPoint,
    InvalidScalar,
    EncodeToCurveFailed,
    VerificationFailed,
}

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

fn validate_key(pk: &[u8]) -> Result<EdwardsPoint, EcvrfError> {
    let y = decode_point(pk).map_err(|_| EcvrfError::InvalidPublicKey)?;
    if y.mul_by_cofactor().is_identity() {
        return Err(EcvrfError::InvalidPublicKey);
    }
    Ok(y)
}

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

fn challenge_generation(
    y: &EdwardsPoint,
    h: &EdwardsPoint,
    gamma: &EdwardsPoint,
    u: &EdwardsPoint,
    v: &EdwardsPoint,
) -> [u8; CHALLENGE_LEN] {
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
    c_bytes
}

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

/// Verify an RFC 9381 Section 5.3 ECVRF-EDWARDS25519-SHA512-TAI proof.
pub fn verify(pk: &[u8], pi: &[u8], alpha: &[u8]) -> Result<[u8; BETA_LEN], EcvrfError> {
    let y = validate_key(pk)?;
    let (gamma, c, c_bytes, s) = decode_proof(pi)?;
    let h = encode_to_curve_tai(pk, alpha)?;

    let u = ED25519_BASEPOINT_POINT * s - y * c;
    let v = h * s - gamma * c;
    let c_prime = challenge_generation(&y, &h, &gamma, &u, &v);

    if c_bytes == c_prime {
        Ok(gamma_to_hash(&gamma))
    } else {
        Err(EcvrfError::VerificationFailed)
    }
}

/// Extract 64-byte VRF output (beta) from a proof without full verification.
pub fn proof_to_hash(pi: &[u8]) -> Result<[u8; BETA_LEN], EcvrfError> {
    let (gamma, _, _, _) = decode_proof(pi)?;
    Ok(gamma_to_hash(&gamma))
}

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    use solana_program::{
        account_info::AccountInfo, entrypoint, entrypoint::ProgramResult,
        program::set_return_data, program_error::ProgramError, pubkey::Pubkey,
    };

    entrypoint!(process_instruction);

    fn process_instruction(
        _program_id: &Pubkey,
        _accounts: &[AccountInfo],
        data: &[u8],
    ) -> ProgramResult {
        if data.len() < crate::PUBLIC_KEY_LEN + crate::PROOF_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        let pk = &data[..crate::PUBLIC_KEY_LEN];
        let pi = &data[crate::PUBLIC_KEY_LEN..crate::PUBLIC_KEY_LEN + crate::PROOF_LEN];
        let alpha = &data[crate::PUBLIC_KEY_LEN + crate::PROOF_LEN..];

        let beta = crate::verify(pk, pi, alpha).map_err(|_| ProgramError::InvalidArgument)?;

        set_return_data(&beta);
        Ok(())
    }
}
