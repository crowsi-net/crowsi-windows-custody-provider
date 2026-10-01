use crowsi_windows_custody_provider::{
    FileNonceLedger, OPERATION_AUTHORIZATION_SCHEMA, OPERATION_REQUEST_SCHEMA, OperationBinding,
    OperationContext, OperationOnlyAction, OperationOnlyCredentialClass, OperationOnlyDispatcher,
    OperationOnlyRequest, PaOperationAuthorization, WindowsOperationBackend,
    authorization_signing_bytes, operation_request_digest,
};
use ihat_identity_assertion_contracts::{
    CurrentDeviceStatusV1, DevicePostureV1, RevocationEpochsV1,
};
use std::sync::{Arc, atomic::AtomicUsize};
use tempfile::{TempDir, tempdir};

use super::{FakeStore, FakeVerifier, FakeWindowsPort};

pub const NOW: u64 = 1_800_000_000;

pub struct Harness {
    pub dispatcher: OperationOnlyDispatcher<
        WindowsOperationBackend<FakeStore, FakeWindowsPort>,
        FakeVerifier,
        FileNonceLedger,
    >,
    pub calls: Arc<AtomicUsize>,
    _root: TempDir,
}

impl Harness {
    pub fn new(class: OperationOnlyCredentialClass) -> Self {
        let root = tempdir().expect("temporary ledger root");
        let ledger_path = root.path().join("nonces");
        let ledger = FileNonceLedger::open(ledger_path).expect("nonce ledger");
        let store = FakeStore::new(class);
        let (port, calls) = FakeWindowsPort::new();
        let backend = WindowsOperationBackend::new(store, port);
        Self {
            dispatcher: OperationOnlyDispatcher::new(backend, FakeVerifier, ledger),
            calls,
            _root: root,
        }
    }
}

pub fn revision() -> String {
    format!("rev1:{}", "a".repeat(64))
}

pub fn context() -> OperationContext {
    OperationContext {
        service_id: "service:crowsi".into(),
        pairwise_subject: "pairwise:crowsi:owner-1".into(),
        device_id: "device-local-a".into(),
        device_proof_key_ref: "device-key:local-a".into(),
        session_ref: "sref_windows_operation_session_a".into(),
        device_posture: "compliant".into(),
        device_posture_revision: 4,
        subject_revocation_epoch: 3,
        service_revocation_epoch: 5,
        device_revocation_epoch: 7,
        session_revocation_epoch: 11,
        workload_id: "workload:crowsi-windows-custody".into(),
        audience: "crowsi-windows-custody-provider".into(),
        now_epoch_s: NOW,
    }
}

pub fn request(
    class: OperationOnlyCredentialClass,
    action: OperationOnlyAction,
) -> OperationOnlyRequest {
    let context = context();
    request_for_context(class, action, &context)
}

pub fn request_for_context(
    class: OperationOnlyCredentialClass,
    action: OperationOnlyAction,
    context: &OperationContext,
) -> OperationOnlyRequest {
    let mut value = OperationOnlyRequest {
        schema: OPERATION_REQUEST_SCHEMA.into(),
        request_id: "request-operation-1".into(),
        credential_id: "operation-key-1".into(),
        expected_revision: revision(),
        credential_class: class,
        action,
        current_device_status: status(context),
        pa_authorization: PaOperationAuthorization {
            schema: OPERATION_AUTHORIZATION_SCHEMA.into(),
            issuer: "crowsi-policy-administrator".into(),
            key_id: "pa-operation-key:fixture".into(),
            binding: OperationBinding {
                service_id: context.service_id.clone(),
                pairwise_subject: context.pairwise_subject.clone(),
                device_id: context.device_id.clone(),
                device_proof_key_ref: context.device_proof_key_ref.clone(),
                session_ref: context.session_ref.clone(),
                device_posture: context.device_posture.clone(),
                device_posture_revision: context.device_posture_revision,
                subject_revocation_epoch: context.subject_revocation_epoch,
                service_revocation_epoch: context.service_revocation_epoch,
                device_revocation_epoch: context.device_revocation_epoch,
                session_revocation_epoch: context.session_revocation_epoch,
                workload_id: context.workload_id.clone(),
                audience: context.audience.clone(),
                action: String::new(),
                request_digest_sha256: format!("sha256:{}", "0".repeat(64)),
                nonce: "nonce-operation-1".into(),
            },
            issued_at_epoch_s: NOW - 1,
            expires_at_epoch_s: NOW + 30,
            signature_hex: "0".repeat(128),
        },
    };
    value.pa_authorization.binding.action = action_binding(&value.action);
    value.pa_authorization.binding.request_digest_sha256 =
        operation_request_digest(&value).expect("request digest");
    resign(&mut value);
    value
}

include!("fixture_authorization.rs");
