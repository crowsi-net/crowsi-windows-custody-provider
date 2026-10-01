use crowsi_windows_custody_provider::{
    FileNonceLedger, OperationOnlyDispatcher, ReasonCode, operation_request_digest,
};
use tempfile::tempdir;

use super::super::{production_operation_support, production_operation_support::Fixture, support};

pub fn full_request_binding() {
    let root = tempdir().expect("temporary root");
    let path = root.path().join("ledger");
    let fixture = Fixture::new();
    let mut request = fixture.request("device-a", 7, "full-binding");
    let now = request.pa_authorization.issued_at_epoch_s + 1;
    let backend = support::Backend::new();
    let mut dispatcher = OperationOnlyDispatcher::new(
        backend.clone(),
        support::AcceptVerifier,
        FileNonceLedger::open(&path).expect("ledger"),
    );
    dispatcher
        .execute(&request, &support::context(&request, now))
        .expect("initial operation");
    assert_eq!(backend.call_count(), 1);

    request.pa_authorization.signature_hex = "01".repeat(64);
    assert_eq!(
        support::failure(dispatcher.execute(&request, &support::context(&request, now))),
        ReasonCode::OperationOnlyAuthorizationReplayed
    );
    assert_eq!(backend.call_count(), 1);

    let mut changed_id = fixture.request("device-a", 7, "full-binding");
    changed_id.request_id = "changed-request-id".into();
    changed_id.pa_authorization.binding.request_digest_sha256 =
        operation_request_digest(&changed_id).expect("changed digest");
    production_operation_support::resign_authorization(&mut changed_id, &fixture.pa);
    assert_eq!(
        support::failure(dispatcher.execute(&changed_id, &support::context(&changed_id, now))),
        ReasonCode::OperationOnlyAuthorizationReplayed
    );
    assert_eq!(backend.call_count(), 1);

    let mut changed_nonce = fixture.request("device-a", 7, "full-binding");
    changed_nonce.pa_authorization.binding.nonce = "changed-nonce".into();
    production_operation_support::resign_authorization(&mut changed_nonce, &fixture.pa);
    assert_eq!(
        support::failure(
            dispatcher.execute(&changed_nonce, &support::context(&changed_nonce, now),)
        ),
        ReasonCode::OperationOnlyAuthorizationReplayed
    );
    assert_eq!(backend.call_count(), 1);
}

pub fn completed_precedes_live_state() {
    let root = tempdir().expect("temporary root");
    let path = root.path().join("ledger");
    let fixture = Fixture::new();
    let request = fixture.request("device-a", 7, "completed-live-state");
    let now = request.pa_authorization.issued_at_epoch_s + 1;
    let backend = support::Backend::new();
    let mut first = OperationOnlyDispatcher::new(
        backend.clone(),
        support::AcceptVerifier,
        FileNonceLedger::open(&path).expect("ledger"),
    );
    let response = first
        .execute(&request, &support::context(&request, now))
        .expect("initial operation");
    let expired = support::context(&request, now + 100);
    let mut restarted = OperationOnlyDispatcher::new(
        backend.clone(),
        support::RejectVerifier,
        FileNonceLedger::open(&path).expect("reopened ledger"),
    );
    assert_eq!(
        restarted
            .execute(&request, &expired)
            .expect("completed before live verification"),
        response
    );
    assert_eq!(backend.call_count(), 1);
}
