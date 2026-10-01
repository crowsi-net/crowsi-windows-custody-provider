use serde::Serialize;

use crate::{ReasonCode, Result};

use super::{
    OPERATION_AUTHORIZATION_AUDIENCE, OPERATION_AUTHORIZATION_ISSUER,
    OPERATION_AUTHORIZATION_SCHEMA, OPERATION_SERVICE_ID, OPERATION_WORKLOAD_ID, OperationBinding,
    OperationContext, OperationOnlyRequest, PaAuthorizationVerifier, PaOperationAuthorization,
    operation_request_digest,
};

const MAX_AUTHORIZATION_TTL_SECONDS: u64 = 60;

/// Produces the exact bytes covered by the PA signature.
///
/// # Errors
///
/// Rejects a value that cannot be encoded into the closed JSON contract.
pub fn authorization_signing_bytes(value: &PaOperationAuthorization) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Signed<'a> {
        schema: &'a str,
        issuer: &'a str,
        key_id: &'a str,
        binding: &'a super::OperationBinding,
        issued_at_epoch_s: u64,
        expires_at_epoch_s: u64,
    }
    serde_json::to_vec(&Signed {
        schema: &value.schema,
        issuer: &value.issuer,
        key_id: &value.key_id,
        binding: &value.binding,
        issued_at_epoch_s: value.issued_at_epoch_s,
        expires_at_epoch_s: value.expires_at_epoch_s,
    })
    .map_err(|_| ReasonCode::OperationOnlyAuthorizationRequired.into())
}

pub(crate) fn verify<V: PaAuthorizationVerifier>(
    request: &OperationOnlyRequest,
    context: &OperationContext,
    verifier: &V,
) -> Result<String> {
    let authorization = &request.pa_authorization;
    if authorization.schema != OPERATION_AUTHORIZATION_SCHEMA
        || authorization.issuer != OPERATION_AUTHORIZATION_ISSUER
    {
        return Err(ReasonCode::OperationOnlyAuthorizationBindingRejected.into());
    }
    let bytes = authorization_signing_bytes(authorization)?;
    if !verifier.verify(authorization, &bytes) {
        return Err(ReasonCode::OperationOnlyAuthorizationRequired.into());
    }
    let binding = &authorization.binding;
    let digest = operation_request_digest(request)?;
    if binding.request_digest_sha256 != digest {
        return Err(ReasonCode::OperationOnlyInputTampered.into());
    }
    if !exact_binding(binding, context, request) {
        return Err(ReasonCode::OperationOnlyAuthorizationBindingRejected.into());
    }
    let ttl = authorization
        .expires_at_epoch_s
        .checked_sub(authorization.issued_at_epoch_s);
    if authorization.issued_at_epoch_s > context.now_epoch_s
        || authorization.expires_at_epoch_s <= context.now_epoch_s
        || ttl.is_none_or(|value| value == 0 || value > MAX_AUTHORIZATION_TTL_SECONDS)
    {
        return Err(ReasonCode::OperationOnlyAuthorizationExpired.into());
    }
    Ok(digest)
}

fn exact_binding(
    value: &OperationBinding,
    current: &OperationContext,
    request: &OperationOnlyRequest,
) -> bool {
    value.service_id == OPERATION_SERVICE_ID
        && current.service_id == OPERATION_SERVICE_ID
        && value.service_id == current.service_id
        && value.pairwise_subject == current.pairwise_subject
        && value.device_id == current.device_id
        && value.device_proof_key_ref == current.device_proof_key_ref
        && value.session_ref == current.session_ref
        && value.device_posture == "compliant"
        && current.device_posture == "compliant"
        && value.device_posture_revision == current.device_posture_revision
        && value.subject_revocation_epoch == current.subject_revocation_epoch
        && value.service_revocation_epoch == current.service_revocation_epoch
        && value.device_revocation_epoch == current.device_revocation_epoch
        && value.session_revocation_epoch == current.session_revocation_epoch
        && value.workload_id == OPERATION_WORKLOAD_ID
        && current.workload_id == OPERATION_WORKLOAD_ID
        && value.workload_id == current.workload_id
        && value.audience == OPERATION_AUTHORIZATION_AUDIENCE
        && current.audience == OPERATION_AUTHORIZATION_AUDIENCE
        && value.audience == current.audience
        && value.action == super::matrix::action_binding(&request.action)
}
