use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use crowsi_windows_custody_provider::{
    OperationContext, OperationCredentialMetadata, OperationLedgerBinding, OperationOnlyAction,
    OperationOnlyBackend, OperationOnlyCredentialClass, OperationOnlyRequest, OperationOnlyResult,
    PaAuthorizationVerifier, PaOperationAuthorization, Result,
};

#[derive(Clone)]
pub struct Backend {
    pub calls: Arc<AtomicUsize>,
    pub revision: Arc<Mutex<String>>,
}

impl Backend {
    pub fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            revision: Arc::new(Mutex::new(revision())),
        }
    }

    pub fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl OperationOnlyBackend for Backend {
    fn metadata(&self, credential_id: &str) -> Result<OperationCredentialMetadata> {
        Ok(OperationCredentialMetadata {
            credential_id: credential_id.into(),
            revision: self.revision.lock().expect("revision lock").clone(),
            credential_class: OperationOnlyCredentialClass::Ed25519SigningKey,
        })
    }

    fn invoke(&mut self, _: &str, action: &OperationOnlyAction) -> Result<OperationOnlyResult> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let OperationOnlyAction::Sign { algorithm, .. } = action else {
            unreachable!("fixture signs only")
        };
        Ok(OperationOnlyResult::Signature {
            algorithm: *algorithm,
            value_hex: "ab".repeat(64),
        })
    }
}

pub struct RejectVerifier;

impl PaAuthorizationVerifier for RejectVerifier {
    fn verify(&self, _: &PaOperationAuthorization, _: &[u8]) -> bool {
        false
    }
}

pub struct AcceptVerifier;

impl PaAuthorizationVerifier for AcceptVerifier {
    fn verify(&self, _: &PaOperationAuthorization, _: &[u8]) -> bool {
        true
    }
}

pub fn context(request: &OperationOnlyRequest, now_epoch_s: u64) -> OperationContext {
    let binding = &request.pa_authorization.binding;
    OperationContext {
        service_id: binding.service_id.clone(),
        pairwise_subject: binding.pairwise_subject.clone(),
        device_id: binding.device_id.clone(),
        device_proof_key_ref: binding.device_proof_key_ref.clone(),
        session_ref: binding.session_ref.clone(),
        device_posture: binding.device_posture.clone(),
        device_posture_revision: binding.device_posture_revision,
        subject_revocation_epoch: binding.subject_revocation_epoch,
        service_revocation_epoch: binding.service_revocation_epoch,
        device_revocation_epoch: binding.device_revocation_epoch,
        session_revocation_epoch: binding.session_revocation_epoch,
        workload_id: binding.workload_id.clone(),
        audience: binding.audience.clone(),
        now_epoch_s,
    }
}

pub fn revision() -> String {
    format!("rev1:{}", "a".repeat(64))
}

pub fn binding(index: usize, now: u64) -> OperationLedgerBinding {
    let digit = format!("{index:064x}");
    OperationLedgerBinding {
        full_request_digest_sha256: digest("1", &digit),
        nonce_digest_sha256: digest("2", &digit),
        request_id_digest_sha256: digest("3", &digit),
        credential_id: "operation-key-1".into(),
        expected_revision: revision(),
        credential_class: OperationOnlyCredentialClass::Ed25519SigningKey,
        authorization_expires_at_epoch_s: now + 60,
    }
}

fn digest(prefix: &str, value: &str) -> String {
    let index = usize::from_str_radix(value, 16).expect("fixture index");
    format!("{prefix}{index:063x}")
}

pub fn failure<T: std::fmt::Debug>(
    value: Result<T>,
) -> crowsi_windows_custody_provider::ReasonCode {
    value.expect_err("operation must fail").reason()
}
