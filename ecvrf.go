// Package ecvrf implements ECVRF-EDWARDS25519-SHA512-TAI per RFC 9381 Section 5.5
// (suite byte 0x03).
//
// Proving is constant-time in the secret key and deterministic nonce using
// filippo.io/edwards25519. Verification validates public keys against
// small-order torsion points (RFC 9381 Section 5.6.1).
package ecvrf

import (
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

const (
	SuiteByte    byte = 0x03
	SecretKeyLen      = 32
	PublicKeyLen      = 32
	ProofLen          = 80
	BetaLen           = 64
	challengeLen      = 16
	scalarLen         = 32
	pointLen          = 32
)

var (
	ErrInvalidProofLen = errors.New("ecvrf: proof must be 80 bytes")
	ErrInvalidPoint    = errors.New("ecvrf: invalid curve point")
	ErrEncodeToCurve   = errors.New("ecvrf: encode_to_curve failed after 256 iterations")
	ErrInvalidSK       = errors.New("ecvrf: invalid secret key")
	ErrInvalidPK       = errors.New("ecvrf: invalid or small-order public key")
	ErrScalarOverflow  = errors.New("ecvrf: scalar >= group order")
)

func expandSecretKey(sk []byte) (*edwards25519.Scalar, []byte, error) {
	if len(sk) != SecretKeyLen {
		return nil, nil, fmt.Errorf("%w: must be %d bytes, got %d", ErrInvalidSK, SecretKeyLen, len(sk))
	}
	h := sha512.Sum512(sk)
	x, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidSK, err)
	}
	return x, h[32:], nil
}

// ValidatePublicKey decodes pk as a canonical Edwards25519 point and rejects
// small-order (torsion) public keys per RFC 9381 Section 5.6.1.
func ValidatePublicKey(pk []byte) error {
	_, err := validateKey(pk)
	return err
}

func validateKey(pk []byte) (*edwards25519.Point, error) {
	if len(pk) != PublicKeyLen {
		return nil, fmt.Errorf("%w: must be %d bytes, got %d", ErrInvalidPK, PublicKeyLen, len(pk))
	}
	y, err := new(edwards25519.Point).SetBytes(pk)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPK, err)
	}
	cofactorY := new(edwards25519.Point).MultByCofactor(y)
	if cofactorY.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, ErrInvalidPK
	}
	return y, nil
}

// encodeToCurveTAI implements RFC 9381 Section 5.4.1.1 try_and_increment with
// cofactor clearing (H = 8 * pt).
func encodeToCurveTAI(pk, alpha []byte) (*edwards25519.Point, int, error) {
	buf := make([]byte, 0, 2+len(pk)+len(alpha)+2)
	buf = append(buf, SuiteByte, 0x01)
	buf = append(buf, pk...)
	buf = append(buf, alpha...)
	buf = append(buf, 0x00, 0x00)
	ctrIdx := len(buf) - 2

	for ctr := 0; ctr <= 255; ctr++ {
		buf[ctrIdx] = byte(ctr)
		hash := sha512.Sum512(buf)
		pt, err := new(edwards25519.Point).SetBytes(hash[:pointLen])
		if err != nil {
			continue
		}
		h := new(edwards25519.Point).MultByCofactor(pt)
		return h, ctr, nil
	}
	return nil, 0, ErrEncodeToCurve
}

// nonceGeneration implements RFC 9381 Section 5.4.2.2 (RFC 8032 style SHA-512).
func nonceGeneration(prefix []byte, h *edwards25519.Point) (*edwards25519.Scalar, error) {
	in := make([]byte, 0, len(prefix)+pointLen)
	in = append(in, prefix...)
	in = append(in, h.Bytes()...)
	kString := sha512.Sum512(in)
	return edwards25519.NewScalar().SetUniformBytes(kString[:])
}

// challengeGeneration implements RFC 9381 Section 5.4.3 over (Y, H, Gamma, U, V).
func challengeGeneration(y, h, gamma, u, v *edwards25519.Point) (*edwards25519.Scalar, [challengeLen]byte, error) {
	in := make([]byte, 0, 2+5*pointLen+1)
	in = append(in, SuiteByte, 0x02)
	in = append(in, y.Bytes()...)
	in = append(in, h.Bytes()...)
	in = append(in, gamma.Bytes()...)
	in = append(in, u.Bytes()...)
	in = append(in, v.Bytes()...)
	in = append(in, 0x00)

	hash := sha512.Sum512(in)
	var cShort [challengeLen]byte
	copy(cShort[:], hash[:challengeLen])

	var cFull [scalarLen]byte
	copy(cFull[:challengeLen], cShort[:])
	c, err := edwards25519.NewScalar().SetCanonicalBytes(cFull[:])
	return c, cShort, err
}

// proofToHash implements RFC 9381 Section 5.2 with cofactor multiplication (8 * Gamma).
func proofToHash(gamma *edwards25519.Point) [BetaLen]byte {
	cofactorGamma := new(edwards25519.Point).MultByCofactor(gamma)
	in := make([]byte, 0, 2+pointLen+1)
	in = append(in, SuiteByte, 0x03)
	in = append(in, cofactorGamma.Bytes()...)
	in = append(in, 0x00)
	return sha512.Sum512(in)
}

func decodeProof(pi []byte) (*edwards25519.Point, *edwards25519.Scalar, [challengeLen]byte, *edwards25519.Scalar, error) {
	var cShort [challengeLen]byte
	if len(pi) != ProofLen {
		return nil, nil, cShort, nil, fmt.Errorf("%w: got %d bytes", ErrInvalidProofLen, len(pi))
	}
	gamma, err := new(edwards25519.Point).SetBytes(pi[:pointLen])
	if err != nil {
		return nil, nil, cShort, nil, fmt.Errorf("%w: gamma: %v", ErrInvalidPoint, err)
	}
	copy(cShort[:], pi[pointLen:pointLen+challengeLen])
	var cFull [scalarLen]byte
	copy(cFull[:challengeLen], cShort[:])
	c, err := edwards25519.NewScalar().SetCanonicalBytes(cFull[:])
	if err != nil {
		return nil, nil, cShort, nil, err
	}
	s, err := edwards25519.NewScalar().SetCanonicalBytes(pi[pointLen+challengeLen:])
	if err != nil {
		return nil, nil, cShort, nil, ErrScalarOverflow
	}
	return gamma, c, cShort, s, nil
}

// DerivePublicKey returns the 32-byte Ed25519 public key for a 32-byte seed sk.
func DerivePublicKey(sk []byte) ([]byte, error) {
	x, _, err := expandSecretKey(sk)
	if err != nil {
		return nil, err
	}
	y := new(edwards25519.Point).ScalarBaseMult(x)
	return y.Bytes(), nil
}

// Prove generates an 80-byte VRF proof: Gamma(32) || c(16) || s(32).
func Prove(sk, alpha []byte) ([]byte, error) {
	x, prefix, err := expandSecretKey(sk)
	if err != nil {
		return nil, err
	}
	y := new(edwards25519.Point).ScalarBaseMult(x)
	pk := y.Bytes()

	h, _, err := encodeToCurveTAI(pk, alpha)
	if err != nil {
		return nil, err
	}

	gamma := new(edwards25519.Point).ScalarMult(x, h)
	k, err := nonceGeneration(prefix, h)
	if err != nil {
		return nil, err
	}

	u := new(edwards25519.Point).ScalarBaseMult(k)
	v := new(edwards25519.Point).ScalarMult(k, h)

	c, cShort, err := challengeGeneration(y, h, gamma, u, v)
	if err != nil {
		return nil, err
	}

	// s = (c * x + k) mod q
	s := edwards25519.NewScalar().MultiplyAdd(c, x, k)

	pi := make([]byte, 0, ProofLen)
	pi = append(pi, gamma.Bytes()...)
	pi = append(pi, cShort[:]...)
	pi = append(pi, s.Bytes()...)
	return pi, nil
}

// Verify checks an 80-byte VRF proof and returns (valid, beta).
// Beta is 64 bytes when valid, nil otherwise.
func Verify(pk, pi, alpha []byte) (bool, []byte) {
	y, err := validateKey(pk)
	if err != nil {
		return false, nil
	}
	gamma, c, cShort, s, err := decodeProof(pi)
	if err != nil {
		return false, nil
	}
	h, _, err := encodeToCurveTAI(pk, alpha)
	if err != nil {
		return false, nil
	}

	negC := edwards25519.NewScalar().Negate(c)
	// U = s*B - c*Y
	u := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(negC, y, s)
	// V = s*H - c*Gamma
	sH := new(edwards25519.Point).ScalarMult(s, h)
	negCGamma := new(edwards25519.Point).ScalarMult(negC, gamma)
	v := new(edwards25519.Point).Add(sH, negCGamma)

	_, cPrimeShort, err := challengeGeneration(y, h, gamma, u, v)
	if err != nil {
		return false, nil
	}
	if subtle.ConstantTimeCompare(cShort[:], cPrimeShort[:]) != 1 {
		return false, nil
	}
	beta := proofToHash(gamma)
	return true, beta[:]
}

// ProofToHash extracts the 64-byte VRF output beta from an 80-byte proof
// without verifying it.
func ProofToHash(pi []byte) ([]byte, error) {
	gamma, _, _, _, err := decodeProof(pi)
	if err != nil {
		return nil, err
	}
	beta := proofToHash(gamma)
	return beta[:], nil
}
