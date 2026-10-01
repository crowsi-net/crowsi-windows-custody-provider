mod production_operation_backend;
mod production_operation_support;
mod production_operation_wiring;

use crowsi_windows_custody_provider::{
    Operation, OperationOnlyCredentialClass, ProductionOperationDispatcher, ReasonCode,
    reject_operation_only_get, reject_registered_generic_operation,
};
use ed25519_dalek::Signer;
use tempfile::tempdir;

use production_operation_backend::Backend;
use production_operation_support::Fixture;

fn reason<T: std::fmt::Debug>(value: crowsi_windows_custody_provider::Result<T>) -> ReasonCode {
    value.expect_err("request must fail").reason()
}

#[test] // OP-08
fn production_command_verifies_pa_and_current_identity_itself() {
    let root = tempdir().expect("temporary root");
    let fixture = Fixture::new();
    let mut command =
        ProductionOperationDispatcher::open(Backend, &fixture.trust(), root.path().join("nonces"))
            .expect("production dispatcher");
    let request = fixture.request("device-a", 7, "nonce-op-08");
    let body = serde_json::to_vec(&request).expect("request JSON");
    let response = command.execute_body(&body).expect("authorized operation");
    assert!(!response.contains_secret_values && !response.secret_follows);

    let mut unsigned = fixture.request("device-a", 7, "nonce-op-08-pa-bad");
    unsigned.pa_authorization.signature_hex = "00".repeat(64);
    assert_eq!(
        reason(command.execute_body(&serde_json::to_vec(&unsigned).expect("JSON"))),
        ReasonCode::OperationOnlyAuthorizationRequired
    );
    let mut untrusted_status = fixture.request("device-a", 7, "nonce-op-08-status-bad");
    untrusted_status.current_device_status.signature = "00".repeat(64);
    assert_eq!(
        reason(command.execute_body(&serde_json::to_vec(&untrusted_status).expect("JSON"))),
        ReasonCode::OperationOnlyAuthorizationRequired
    );

    let mut stale = fixture.request("device-a", 7, "nonce-op-08-stale");
    stale.current_device_status.revocation_epochs.device += 1;
    let status_bytes = ihat_identity_assertion_contracts::canonical_current_status_payload(
        &stale.current_device_status,
    );
    stale.current_device_status.signature =
        hex::encode(fixture.status.sign(&status_bytes).to_bytes());
    assert_eq!(
        reason(command.execute_body(&serde_json::to_vec(&stale).expect("JSON"))),
        ReasonCode::OperationOnlyAuthorizationBindingRejected
    );
}

#[test] // OP-09
fn production_nonce_survives_restart_and_legacy_is_rejected() {
    let root = tempdir().expect("temporary root");
    let fixture = Fixture::new();
    let path = root.path().join("nonces");
    let request = fixture.request("device-a", 7, "nonce-op-09");
    let body = serde_json::to_vec(&request).expect("request JSON");
    let first = ProductionOperationDispatcher::open(Backend, &fixture.trust(), &path)
        .expect("dispatcher")
        .execute_body(&body)
        .expect("first execution");
    let mut restarted = ProductionOperationDispatcher::open(Backend, &fixture.trust(), &path)
        .expect("restarted dispatcher");
    assert_eq!(
        restarted.execute_body(&body).expect("exact cached retry"),
        first
    );
    let mut legacy = serde_json::to_value(request).expect("JSON value");
    legacy["schema"] = serde_json::json!("crowsi://platform-custody/operation-request/v1");
    assert_eq!(
        reason(restarted.execute_body(&serde_json::to_vec(&legacy).expect("JSON"))),
        ReasonCode::OperationOnlyInputRejected
    );
}

#[test] // OP-10
fn device_a_revocation_does_not_change_device_b_authorization() {
    let root = tempdir().expect("temporary root");
    let fixture = Fixture::new();
    let mut command =
        ProductionOperationDispatcher::open(Backend, &fixture.trust(), root.path().join("nonces"))
            .expect("dispatcher");
    let mut revoked_a = fixture.request("device-a", 7, "nonce-a");
    revoked_a.current_device_status.revocation_epochs.device = 8;
    let bytes = ihat_identity_assertion_contracts::canonical_current_status_payload(
        &revoked_a.current_device_status,
    );
    revoked_a.current_device_status.signature = hex::encode(fixture.status.sign(&bytes).to_bytes());
    assert_eq!(
        reason(command.execute_body(&serde_json::to_vec(&revoked_a).expect("JSON"))),
        ReasonCode::OperationOnlyAuthorizationBindingRejected
    );
    let b = fixture.request("device-b", 2, "nonce-b");
    command
        .execute_body(&serde_json::to_vec(&b).expect("JSON"))
        .expect("device B remains authorized");
}

#[test] // OP-11
fn every_operation_only_class_denies_generic_export() {
    for class in [
        OperationOnlyCredentialClass::RsaSigningKey,
        OperationOnlyCredentialClass::Ed25519SigningKey,
        OperationOnlyCredentialClass::ProviderOperation,
    ] {
        assert_eq!(
            reason(reject_operation_only_get(class)),
            ReasonCode::OperationOnlyExportRejected
        );
        let get = Operation::Get {
            credential_id: "operation-key-1".into(),
            expected_revision: production_operation_support::revision(),
        };
        assert_eq!(
            reason(reject_registered_generic_operation(&get, Some(class))),
            ReasonCode::OperationOnlyExportRejected
        );
    }
}
