use super::SecretRecord;
use crate::ReasonCode;
use sha2::Digest;
use zeroize::Zeroizing;

const NAMESPACE: &str = "coela.crowsi.credentials";

#[test]
fn binary_record_round_trip_preserves_secret_and_opaque_revision() {
    let record = record(b"private");
    let encoded = record.encode().expect("valid encoding");
    let decoded = SecretRecord::decode(&encoded, NAMESPACE).expect("valid decoding");
    assert_eq!(decoded.credential_id, "github.app.pem");
    assert_eq!(decoded.revision, record.revision);
    assert!(decoded.revision.starts_with("rev1:"));
    assert_eq!(&*decoded.secret, b"private");
}

#[test]
fn same_secret_receives_a_fresh_opaque_revision() {
    let first = record(b"private");
    let second = record(b"private");
    assert_ne!(first.revision, second.revision);
    assert!(
        !first
            .revision
            .contains(&hex::encode(sha2::Sha256::digest(b"private")))
    );
}

#[test]
fn record_is_bound_to_the_exact_namespace() {
    let encoded = record(b"private").encode().expect("valid encoding");
    assert_eq!(
        failure(SecretRecord::decode(&encoded, "other.credentials")),
        ReasonCode::IntegrityRejected
    );
}

#[test]
fn binary_record_rejects_tampered_secret() {
    let mut encoded = record(b"private").encode().expect("valid encoding");
    let secret_at = encoded.len() - 32 - b"private".len();
    encoded[secret_at] ^= 1;
    assert_eq!(
        failure(SecretRecord::decode(&encoded, NAMESPACE)),
        ReasonCode::IntegrityRejected
    );
}

#[test]
fn record_rejects_empty_and_oversized_secret() {
    assert!(SecretRecord::new(NAMESPACE, "id".into(), Zeroizing::new(Vec::new())).is_err());
    assert!(
        SecretRecord::new(
            NAMESPACE,
            "id".into(),
            Zeroizing::new(vec![0; crate::MAX_SECRET_BYTES + 1])
        )
        .is_err()
    );
}

fn record(secret: &[u8]) -> SecretRecord {
    SecretRecord::new(
        NAMESPACE,
        "github.app.pem".into(),
        Zeroizing::new(secret.to_vec()),
    )
    .expect("valid record")
}

fn failure(result: crate::Result<SecretRecord>) -> ReasonCode {
    match result {
        Ok(_) => panic!("record must fail"),
        Err(error) => error.reason(),
    }
}
