use crowsi_windows_custody_provider::{
    FileNonceLedger, OperationLedgerFailpoint, OperationOnlyDispatcher,
    ProductionOperationDispatcher, ReasonCode, arm_operation_ledger_failpoint,
};
use ed25519_dalek::SigningKey;
use tempfile::tempdir;

use super::super::{production_operation_support::Fixture, support};

pub fn response_cache_gap() {
    let root = tempdir().expect("temporary root");
    let path = root.path().join("ledger");
    let fixture = Fixture::new();
    let request = fixture.request("device-a", 7, "response-gap");
    let body = serde_json::to_vec(&request).expect("request bytes");
    let backend = support::Backend::new();
    let mut first = ProductionOperationDispatcher::open(backend.clone(), &fixture.trust(), &path)
        .expect("dispatcher");
    arm_operation_ledger_failpoint(Some(OperationLedgerFailpoint::AfterCompleteBeforeReturn));
    assert_eq!(
        support::failure(first.execute_body_bytes(&body)),
        ReasonCode::OperationOnlyResultUnknown
    );
    assert_eq!(backend.call_count(), 1);

    let rotated = Fixture {
        pa: SigningKey::from_bytes(&[9; 32]),
        status: SigningKey::from_bytes(&[11; 32]),
    };
    let mut restarted =
        ProductionOperationDispatcher::open(backend.clone(), &rotated.trust(), &path)
            .expect("rotated dispatcher");
    let replay = restarted
        .execute_body_bytes(&body)
        .expect("completed cache before rotated trust");
    drop(restarted);
    let repeated = ProductionOperationDispatcher::open(backend.clone(), &rotated.trust(), &path)
        .expect("second restart")
        .execute_body_bytes(&body)
        .expect("exact completed response");
    assert_eq!(repeated, replay);
    assert_eq!(backend.call_count(), 1);
}

pub fn prepared_retry_and_drift() {
    retry_after_expiry();
    reject_drift_before_reinvoke();
}

fn retry_after_expiry() {
    let root = tempdir().expect("temporary root");
    let path = root.path().join("prepared");
    let fixture = Fixture::new();
    let request = fixture.request("device-a", 7, "prepared-expiry");
    let now = request.pa_authorization.issued_at_epoch_s + 1;
    let backend = support::Backend::new();
    let mut first = OperationOnlyDispatcher::new(
        backend.clone(),
        support::AcceptVerifier,
        FileNonceLedger::open(&path).expect("ledger"),
    );
    arm_operation_ledger_failpoint(Some(OperationLedgerFailpoint::AfterPrepare));
    assert_eq!(
        support::failure(first.execute(&request, &support::context(&request, now))),
        ReasonCode::OperationOnlyResultUnknown
    );
    assert_eq!(backend.call_count(), 0);
    let expired = support::context(&request, now + 100);
    let mut retry = OperationOnlyDispatcher::new(
        backend.clone(),
        support::RejectVerifier,
        FileNonceLedger::open(&path).expect("reopened ledger"),
    );
    retry
        .execute(&request, &expired)
        .expect("Prepared retry skips expired live authorization");
    assert_eq!(backend.call_count(), 1);
}

fn reject_drift_before_reinvoke() {
    let root = tempdir().expect("temporary root");
    let path = root.path().join("drift");
    let fixture = Fixture::new();
    let request = fixture.request("device-a", 7, "prepared-drift");
    let now = request.pa_authorization.issued_at_epoch_s + 1;
    let backend = support::Backend::new();
    let mut first = OperationOnlyDispatcher::new(
        backend.clone(),
        support::AcceptVerifier,
        FileNonceLedger::open(&path).expect("ledger"),
    );
    arm_operation_ledger_failpoint(Some(OperationLedgerFailpoint::AfterInvokeBeforeComplete));
    assert_eq!(
        support::failure(first.execute(&request, &support::context(&request, now))),
        ReasonCode::OperationOnlyResultUnknown
    );
    assert_eq!(backend.call_count(), 1);
    *backend.revision.lock().expect("revision lock") = "drifted".into();
    let mut retry = OperationOnlyDispatcher::new(
        backend.clone(),
        support::RejectVerifier,
        FileNonceLedger::open(&path).expect("reopened ledger"),
    );
    assert_eq!(
        support::failure(retry.execute(&request, &support::context(&request, now + 100))),
        ReasonCode::CredentialChanged
    );
    assert_eq!(backend.call_count(), 1);
    *backend.revision.lock().expect("revision lock") = support::revision();
    retry
        .execute(&request, &support::context(&request, now + 100))
        .expect("exact deterministic Prepared retry");
    assert_eq!(backend.call_count(), 2);
}
