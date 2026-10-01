use std::sync::{
    Arc, Barrier,
    atomic::{AtomicUsize, Ordering},
};

use crowsi_windows_custody_provider::{
    DurableOperationNonceLedger, FileNonceLedger, MAX_OPERATION_INPUT_BYTES,
    OperationLedgerBinding, OperationOnlyAction, OperationOnlyCredentialClass as Class, ReasonCode,
    decode_operation_request,
};
use tempfile::tempdir;

use super::{digest, ed25519, failure, support};

pub fn op_06() {
    let root = tempdir().expect("temporary root");
    let path = root.path().join("nonces");
    let ledger = Arc::new(FileNonceLedger::open(&path).expect("ledger"));
    let barrier = Arc::new(Barrier::new(8));
    let calls = Arc::new(AtomicUsize::new(0));
    let threads = (0..8)
        .map(|_| {
            let ledger = Arc::clone(&ledger);
            let barrier = Arc::clone(&barrier);
            let calls = Arc::clone(&calls);
            std::thread::spawn(move || {
                barrier.wait();
                ledger.invoke_exact(&ledger_binding(), 800, &mut || Ok(()), &mut || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(b"exact-response".to_vec())
                })
            })
        })
        .collect::<Vec<_>>();
    let results = threads
        .into_iter()
        .map(|thread| thread.join().expect("thread"))
        .collect::<Vec<_>>();
    assert!(results.iter().all(Result::is_ok));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let reopened = FileNonceLedger::open(path).expect("reopened ledger");
    assert_eq!(
        reopened
            .completed_exact(&ledger_binding(), 800)
            .expect("completed"),
        Some(b"exact-response".to_vec())
    );
    let mut changed = ledger_binding();
    changed.full_request_digest_sha256 = "9".repeat(64);
    assert_eq!(
        failure(reopened.completed_exact(&changed, 800)),
        ReasonCode::OperationOnlyAuthorizationReplayed
    );
}

fn ledger_binding() -> OperationLedgerBinding {
    OperationLedgerBinding {
        full_request_digest_sha256: "1".repeat(64),
        nonce_digest_sha256: "2".repeat(64),
        request_id_digest_sha256: "3".repeat(64),
        credential_id: "operation-key-1".into(),
        expected_revision: super::support::revision(),
        credential_class: Class::Ed25519SigningKey,
        authorization_expires_at_epoch_s: 860,
    }
}

pub fn op_07() {
    let value = support::request(Class::Ed25519SigningKey, ed25519());
    assert_eq!(
        value.schema,
        "crowsi://platform-custody/operation-request/v3"
    );
    assert_eq!(
        value.pa_authorization.schema,
        "crowsi://platform-custody/operation-authorization/v3"
    );
    let wire = serde_json::to_vec(&value).expect("request JSON");
    assert!(decode_operation_request(&wire).is_ok());
    let mut unknown = serde_json::to_value(&value).expect("request value");
    unknown["unreviewed"] = serde_json::json!(true);
    let mut legacy = serde_json::to_value(&value).expect("legacy request value");
    legacy["schema"] = serde_json::json!("crowsi://platform-custody/operation-request/v2");
    legacy["pa_authorization"]["schema"] =
        serde_json::json!("crowsi://platform-custody/operation-authorization/v2");
    legacy["pa_authorization"]["binding"]["account_id"] =
        serde_json::json!("legacy-global-account");
    legacy["pa_authorization"]["binding"]["revocation_epoch"] = serde_json::json!(7);
    let invalid = [
        b"{".to_vec(),
        vec![b'x'; MAX_OPERATION_INPUT_BYTES + 1],
        [wire, b"x".to_vec()].concat(),
        serde_json::to_vec(&unknown).expect("unknown-field request"),
        serde_json::to_vec(&legacy).expect("legacy request"),
    ];
    for body in invalid {
        assert_eq!(
            failure(decode_operation_request(&body)),
            ReasonCode::OperationOnlyInputRejected
        );
    }
    let mut tampered = value;
    if let OperationOnlyAction::Sign { digest_sha256, .. } = &mut tampered.action {
        *digest_sha256 = digest();
    }
    let mut harness = support::Harness::new(Class::Ed25519SigningKey);
    assert_eq!(
        failure(harness.dispatcher.execute(&tampered, &support::context())),
        ReasonCode::OperationOnlyInputTampered
    );
}
