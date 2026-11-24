package ecvrf

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vectorFile struct {
	Suite           string           `json:"suite"`
	Spec            string           `json:"spec"`
	Vectors         []positiveVector `json:"vectors"`
	NegativeVectors []negativeVector `json:"negative_vectors"`
}

type positiveVector struct {
	Label string `json:"label"`
	SK    string `json:"sk"`
	PK    string `json:"pk"`
	Alpha string `json:"alpha"`
	Pi    string `json:"pi"`
	Beta  string `json:"beta"`
}

type negativeVector struct {
	Description    string `json:"description"`
	PK             string `json:"pk"`
	Alpha          string `json:"alpha"`
	Pi             string `json:"pi"`
	ExpectedVerify bool   `json:"expected_verify"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	data, err := os.ReadFile("vectors/vectors.json")
	if err != nil {
		t.Fatalf("read vectors.json: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse vectors.json: %v", err)
	}
	if vf.Suite != "ECVRF-EDWARDS25519-SHA512-TAI" {
		t.Fatalf("unexpected suite %q", vf.Suite)
	}
	return vf
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}
	return b
}

func TestProve(t *testing.T) {
	vf := loadVectors(t)
	for _, vec := range vf.Vectors {
		t.Run(vec.Label, func(t *testing.T) {
			pi, err := Prove(mustHex(t, vec.SK), mustHex(t, vec.Alpha))
			if err != nil {
				t.Fatalf("Prove: %v", err)
			}
			if got := hex.EncodeToString(pi); got != vec.Pi {
				t.Errorf("pi mismatch\n  got:  %s\n  want: %s", got, vec.Pi)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	vf := loadVectors(t)
	for _, vec := range vf.Vectors {
		t.Run(vec.Label, func(t *testing.T) {
			valid, beta := Verify(mustHex(t, vec.PK), mustHex(t, vec.Pi), mustHex(t, vec.Alpha))
			if !valid {
				t.Fatal("Verify rejected valid proof")
			}
			if got := hex.EncodeToString(beta); got != vec.Beta {
				t.Errorf("beta mismatch\n  got:  %s\n  want: %s", got, vec.Beta)
			}
		})
	}
}

func TestProofToHash(t *testing.T) {
	vf := loadVectors(t)
	for _, vec := range vf.Vectors {
		t.Run(vec.Label, func(t *testing.T) {
			beta, err := ProofToHash(mustHex(t, vec.Pi))
			if err != nil {
				t.Fatalf("ProofToHash: %v", err)
			}
			if got := hex.EncodeToString(beta); got != vec.Beta {
				t.Errorf("beta mismatch\n  got:  %s\n  want: %s", got, vec.Beta)
			}
		})
	}
}

func TestNegativeVerify(t *testing.T) {
	vf := loadVectors(t)
	for _, vec := range vf.NegativeVectors {
		t.Run(vec.Description, func(t *testing.T) {
			valid, _ := Verify(mustHex(t, vec.PK), mustHex(t, vec.Pi), mustHex(t, vec.Alpha))
			if valid != vec.ExpectedVerify {
				t.Errorf("Verify = %v, want %v", valid, vec.ExpectedVerify)
			}
		})
	}
}

func TestDerivePublicKey(t *testing.T) {
	vf := loadVectors(t)
	for _, vec := range vf.Vectors {
		t.Run(vec.Label, func(t *testing.T) {
			pk, err := DerivePublicKey(mustHex(t, vec.SK))
			if err != nil {
				t.Fatalf("DerivePublicKey: %v", err)
			}
			if got := hex.EncodeToString(pk); got != vec.PK {
				t.Errorf("pk mismatch\n  got:  %s\n  want: %s", got, vec.PK)
			}
		})
	}
}

func TestProveRejectsInvalidSKLen(t *testing.T) {
	for _, n := range []int{0, 31, 33} {
		if _, err := Prove(make([]byte, n), []byte("test")); err == nil {
			t.Errorf("Prove accepted %d-byte sk", n)
		}
	}
}
