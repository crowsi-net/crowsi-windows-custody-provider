use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ReasonCode, Result};

use super::{
    OPERATION_REQUEST_SCHEMA, OperationOnlyAction, OperationOnlyCredentialClass,
    OperationOnlyRequest,
};

pub const MAX_OPERATION_INPUT_BYTES: usize = 16 * 1024;

/// Decodes one closed, bounded operation-only request.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, trailing, unknown-field, or invalid input.
pub fn decode_operation_request(body: &[u8]) -> Result<OperationOnlyRequest> {
    if body.is_empty() || body.len() > MAX_OPERATION_INPUT_BYTES {
        return Err(ReasonCode::OperationOnlyInputRejected.into());
    }
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let request = OperationOnlyRequest::deserialize(&mut decoder)
        .map_err(|_| ReasonCode::OperationOnlyInputRejected)?;
    decoder
        .end()
        .map_err(|_| ReasonCode::OperationOnlyInputRejected)?;
    validate_request(&request)?;
    Ok(request)
}

/// Derives the authorization-bound digest without including the authorization itself.
///
/// # Errors
///
/// Rejects an intent that cannot be encoded into the canonical JSON shape.
pub fn operation_request_digest(request: &OperationOnlyRequest) -> Result<String> {
    #[derive(Serialize)]
    struct Intent<'a> {
        schema: &'a str,
        request_id: &'a str,
        credential_id: &'a str,
        expected_revision: &'a str,
        credential_class: OperationOnlyCredentialClass,
        action: &'a OperationOnlyAction,
    }
    let intent = Intent {
        schema: &request.schema,
        request_id: &request.request_id,
        credential_id: &request.credential_id,
        expected_revision: &request.expected_revision,
        credential_class: request.credential_class,
        action: &request.action,
    };
    let bytes = serde_json::to_vec(&intent).map_err(|_| ReasonCode::OperationOnlyInputRejected)?;
    let mut digest = Sha256::new();
    digest.update(b"crowsi-windows-operation-request-v3\0");
    digest.update(bytes);
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

pub(crate) fn validate_request(value: &OperationOnlyRequest) -> Result<()> {
    let valid = value.schema == OPERATION_REQUEST_SCHEMA
        && identifier(&value.request_id, 128)
        && identifier(&value.credential_id, 128)
        && crate::protocol::revision(&value.expected_revision)
        && valid_action(&value.action)
        && valid_authorization(value);
    valid
        .then_some(())
        .ok_or(ReasonCode::OperationOnlyInputRejected.into())
}

fn valid_action(action: &OperationOnlyAction) -> bool {
    match action {
        OperationOnlyAction::Sign { digest_sha256, .. } => digest(digest_sha256),
        OperationOnlyAction::ProviderOperation {
            provider,
            operation,
            input_digest_sha256,
        } => identifier(provider, 64) && identifier(operation, 64) && digest(input_digest_sha256),
    }
}

fn digest(value: &str) -> bool {
    value.len() == 71 && value.starts_with("sha256:") && bounded_hex(&value[7..], 64, 64)
}

fn valid_authorization(value: &OperationOnlyRequest) -> bool {
    let authorization = &value.pa_authorization;
    let binding = &authorization.binding;
    authorization.schema == super::OPERATION_AUTHORIZATION_SCHEMA
        && identifier(&authorization.issuer, 128)
        && identifier(&authorization.key_id, 128)
        && identifier(&binding.service_id, 128)
        && identifier(&binding.pairwise_subject, 128)
        && identifier(&binding.device_id, 128)
        && identifier(&binding.device_proof_key_ref, 240)
        && identifier(&binding.session_ref, 128)
        && identifier(&binding.device_posture, 32)
        && binding.device_posture_revision > 0
        && identifier(&binding.workload_id, 128)
        && identifier(&binding.audience, 128)
        && identifier(&binding.action, 192)
        && digest(&binding.request_digest_sha256)
        && identifier(&binding.nonce, 128)
        && bounded_hex(&authorization.signature_hex, 128, 128)
}

fn bounded_hex(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn identifier(value: &str, maximum: usize) -> bool {
    crate::protocol::identifier(value, maximum)
}
