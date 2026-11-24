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
fn positive_vectors_verify() {
    let file = load_vectors();
    assert_eq!(file.suite, "ECVRF-EDWARDS25519-SHA512-TAI");
    assert_eq!(file.spec, "RFC 9381");

    for (i, vec) in file.vectors.iter().enumerate() {
        let pk = hex::decode(&vec.pk).unwrap();
        let pi = hex::decode(&vec.pi).unwrap();
        let alpha = hex::decode(&vec.alpha).unwrap();
        let expected_beta = hex::decode(&vec.beta).unwrap();

        let beta = ecvrf_solana::verify(&pk, &pi, &alpha)
            .unwrap_or_else(|e| panic!("vector {i} '{}': verify failed: {:?}", vec.label, e));

        assert_eq!(
            beta.to_vec(),
            expected_beta,
            "vector {i} '{}': beta mismatch",
            vec.label
        );
    }
}

#[test]
fn negative_vectors_rejected() {
    let file = load_vectors();

    for (i, vec) in file.negative_vectors.iter().enumerate() {
        let pk = hex::decode(&vec.pk).unwrap();
        let pi = hex::decode(&vec.pi).unwrap();
        let alpha = hex::decode(&vec.alpha).unwrap();

        let ok = ecvrf_solana::verify(&pk, &pi, &alpha).is_ok();
        assert_eq!(
            ok, vec.expected_verify,
            "negative vector {i} '{}': expected {}, got {ok}",
            vec.description, vec.expected_verify
        );
    }
}

#[test]
fn proof_to_hash_matches() {
    let file = load_vectors();

    for (i, vec) in file.vectors.iter().enumerate() {
        let pi = hex::decode(&vec.pi).unwrap();
        let expected_beta = hex::decode(&vec.beta).unwrap();

        let beta = ecvrf_solana::proof_to_hash(&pi)
            .unwrap_or_else(|e| panic!("vector {i} '{}': proof_to_hash failed: {:?}", vec.label, e));

        assert_eq!(
            beta.to_vec(),
            expected_beta,
            "vector {i} '{}': proof_to_hash beta mismatch",
            vec.label
        );
    }
}
