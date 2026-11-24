use ecvrf::{derive_public_key, is_public_key, proof_to_hash, prove, verify};
use serde::Deserialize;

#[derive(Deserialize)]
struct TestVectors {
    suite: String,
    spec: String,
    vectors: Vec<PositiveVector>,
    negative_vectors: Vec<NegativeVector>,
}

#[derive(Deserialize)]
struct PositiveVector {
    label: String,
    sk: String,
    pk: String,
    alpha: String,
    pi: String,
    beta: String,
}

#[derive(Deserialize)]
struct NegativeVector {
    description: String,
    pk: String,
    alpha: String,
    pi: String,
    expected_verify: bool,
}

fn load_vectors() -> TestVectors {
    let content =
        std::fs::read_to_string("../vectors/vectors.json").expect("failed to read vectors.json");
    serde_json::from_str(&content).expect("failed to parse vectors.json")
}

#[test]
fn positive_vectors_pk_derivation() {
    let tv = load_vectors();
    assert_eq!(tv.suite, "ECVRF-EDWARDS25519-SHA512-TAI");
    assert_eq!(tv.spec, "RFC 9381");

    for (i, v) in tv.vectors.iter().enumerate() {
        let sk = hex::decode(&v.sk).unwrap();
        let pk = derive_public_key(&sk)
            .unwrap_or_else(|e| panic!("vector {i} '{}': derive_public_key failed: {e}", v.label));
        assert_eq!(hex::encode(pk), v.pk, "vector {i} '{}': pk mismatch", v.label);
        assert!(is_public_key(&pk), "vector {i} '{}': is_public_key false", v.label);
    }
}

#[test]
fn positive_vectors_prove() {
    let tv = load_vectors();
    for (i, v) in tv.vectors.iter().enumerate() {
        let sk = hex::decode(&v.sk).unwrap();
        let alpha = hex::decode(&v.alpha).unwrap();
        let pi = prove(&sk, &alpha)
            .unwrap_or_else(|e| panic!("vector {i} '{}': prove failed: {e}", v.label));
        assert_eq!(hex::encode(pi), v.pi, "vector {i} '{}': pi mismatch", v.label);
    }
}

#[test]
fn positive_vectors_verify() {
    let tv = load_vectors();
    for (i, v) in tv.vectors.iter().enumerate() {
        let pk = hex::decode(&v.pk).unwrap();
        let alpha = hex::decode(&v.alpha).unwrap();
        let pi = hex::decode(&v.pi).unwrap();
        let beta = verify(&pk, &pi, &alpha)
            .unwrap_or_else(|e| panic!("vector {i} '{}': verify failed: {e}", v.label));
        assert_eq!(
            hex::encode(beta),
            v.beta,
            "vector {i} '{}': beta mismatch",
            v.label
        );
    }
}

#[test]
fn positive_vectors_proof_to_hash() {
    let tv = load_vectors();
    for (i, v) in tv.vectors.iter().enumerate() {
        let pi = hex::decode(&v.pi).unwrap();
        let beta = proof_to_hash(&pi)
            .unwrap_or_else(|e| panic!("vector {i} '{}': proof_to_hash failed: {e}", v.label));
        assert_eq!(
            hex::encode(beta),
            v.beta,
            "vector {i} '{}': beta mismatch",
            v.label
        );
    }
}

#[test]
fn negative_vectors() {
    let tv = load_vectors();
    for (i, v) in tv.negative_vectors.iter().enumerate() {
        let pk = hex::decode(&v.pk).unwrap();
        let alpha = hex::decode(&v.alpha).unwrap();
        let pi = hex::decode(&v.pi).unwrap();
        let ok = verify(&pk, &pi, &alpha).is_ok();
        assert_eq!(
            ok, v.expected_verify,
            "negative vector {i} '{}': expected {}, got {ok}",
            v.description, v.expected_verify
        );
    }
}

#[test]
fn prove_rejects_wrong_sk_length() {
    assert!(prove(&[0u8; 0], b"test").is_err());
    assert!(prove(&[0u8; 31], b"test").is_err());
    assert!(prove(&[0u8; 33], b"test").is_err());
}
