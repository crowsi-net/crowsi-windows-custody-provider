use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use ihat_identity_assertion_contracts::{CurrentDeviceStatusV1, verify_current_status_at};

use crate::{ReasonCode, Result};

use super::{
    FileNonceLedger, OPERATION_AUTHORIZATION_AUDIENCE, OPERATION_SERVICE_ID, OperationContext,
    OperationOnlyBackend, OperationOnlyDispatcher, OperationOnlyResponse, OperationTrust,
    PinnedPaVerifier, PinnedStatusVerifier, decode_operation_request,
};

pub struct ProductionOperationDispatcher<B> {
    dispatcher: OperationOnlyDispatcher<B, PinnedPaVerifier, FileNonceLedger>,
    status_verifier: PinnedStatusVerifier,
    status_issuer: String,
}

impl<B: OperationOnlyBackend> ProductionOperationDispatcher<B> {
    /// Creates the production command boundary with pinned PA and identity-status keys.
    ///
    /// # Errors
    ///
    /// Rejects invalid trust input or unavailable durable nonce storage.
    pub fn open(backend: B, trust: &[u8], nonce_path: impl AsRef<Path>) -> Result<Self> {
        let trust = OperationTrust::decode(trust)?;
        let status_verifier = trust.status_verifier()?;
        let pa_verifier = trust.pa_verifier()?;
        let ledger = FileNonceLedger::open(nonce_path)?;
        Ok(Self {
            dispatcher: OperationOnlyDispatcher::new(backend, pa_verifier, ledger),
            status_verifier,
            status_issuer: trust.status_issuer,
        })
    }

    /// Strictly decodes, independently verifies, and executes one operation-only command.
    ///
    /// # Errors
    ///
    /// Rejects malformed, stale, untrusted, mismatched, replayed, or failed requests.
    pub fn execute_body(&mut self, body: &[u8]) -> Result<OperationOnlyResponse> {
        let request = decode_operation_request(body)?;
        let bytes = self.execute_request_bytes(&request, system_time()?)?;
        super::response_cache::decode_exact(&bytes, &request)
    }

    /// Returns the exact durable canonical response bytes used by production stdout.
    ///
    /// # Errors
    ///
    /// Rejects malformed, stale, untrusted, mismatched, replayed, or failed requests.
    pub fn execute_body_bytes(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        let request = decode_operation_request(body)?;
        self.execute_request_bytes(&request, system_time()?)
    }

    fn execute_request_bytes(
        &mut self,
        request: &super::OperationOnlyRequest,
        now_epoch_s: u64,
    ) -> Result<Vec<u8>> {
        let verifier = &self.status_verifier;
        let issuer = &self.status_issuer;
        self.dispatcher
            .execute_bytes_with_accept(request, now_epoch_s, || {
                verified_context(request, verifier, issuer, now_epoch_s)
            })
    }
}

fn system_time() -> Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ReasonCode::OperationOnlyAuthorizationExpired)?
        .as_secs();
    Ok(now)
}

fn verified_context(
    request: &super::OperationOnlyRequest,
    verifier: &PinnedStatusVerifier,
    issuer: &str,
    now_epoch_s: u64,
) -> Result<OperationContext> {
    let status = &request.current_device_status;
    verify_current_status_at(
        status,
        verifier,
        issuer,
        OPERATION_AUTHORIZATION_AUDIENCE,
        now_epoch_s,
    )
    .map_err(|_| ReasonCode::OperationOnlyAuthorizationRequired)?;
    if !status_matches_authorization(status, &request.pa_authorization.binding)
        || request.pa_authorization.issued_at_epoch_s < status.issued_at_epoch_s
        || request.pa_authorization.expires_at_epoch_s > status.expires_at_epoch_s
    {
        return Err(ReasonCode::OperationOnlyAuthorizationBindingRejected.into());
    }
    context(status, now_epoch_s)
}

fn context(value: &CurrentDeviceStatusV1, now_epoch_s: u64) -> Result<OperationContext> {
    if value.service_id != OPERATION_SERVICE_ID || value.device_posture.state != "compliant" {
        return Err(ReasonCode::OperationOnlyAuthorizationBindingRejected.into());
    }
    Ok(OperationContext {
        service_id: value.service_id.clone(),
        pairwise_subject: value.pairwise_subject.clone(),
        device_id: value.device_id.clone(),
        device_proof_key_ref: value.device_proof_key_ref.clone(),
        session_ref: value.session_ref.clone(),
        device_posture: value.device_posture.state.clone(),
        device_posture_revision: value.device_posture.revision,
        subject_revocation_epoch: value.revocation_epochs.subject,
        service_revocation_epoch: value.revocation_epochs.service,
        device_revocation_epoch: value.revocation_epochs.device,
        session_revocation_epoch: value.revocation_epochs.session,
        workload_id: super::OPERATION_WORKLOAD_ID.into(),
        audience: value.audience.clone(),
        now_epoch_s,
    })
}

fn status_matches_authorization(
    status: &CurrentDeviceStatusV1,
    binding: &super::OperationBinding,
) -> bool {
    binding.service_id == status.service_id
        && binding.pairwise_subject == status.pairwise_subject
        && binding.device_id == status.device_id
        && binding.device_proof_key_ref == status.device_proof_key_ref
        && binding.session_ref == status.session_ref
        && binding.device_posture == status.device_posture.state
        && binding.device_posture_revision == status.device_posture.revision
        && binding.subject_revocation_epoch == status.revocation_epochs.subject
        && binding.service_revocation_epoch == status.revocation_epochs.service
        && binding.device_revocation_epoch == status.revocation_epochs.device
        && binding.session_revocation_epoch == status.revocation_epochs.session
        && binding.audience == status.audience
        && binding.nonce == status.nonce
}
