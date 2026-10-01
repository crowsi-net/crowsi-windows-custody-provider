use serde::Deserialize as _;

use crate::{ReasonCode, Result};

use super::{OPERATION_RESPONSE_SCHEMA, OperationOnlyRequest, OperationOnlyResponse};

pub(super) fn encode(response: &OperationOnlyResponse) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(response).map_err(|_| ReasonCode::OperationOnlyResultUnknown)?;
    if bytes.is_empty() || bytes.len() > crate::MAX_CONTROL_BYTES {
        return Err(ReasonCode::OperationOnlyResultUnknown.into());
    }
    Ok(bytes)
}

pub(super) fn decode_exact(
    bytes: &[u8],
    request: &OperationOnlyRequest,
) -> Result<OperationOnlyResponse> {
    if bytes.is_empty() || bytes.len() > crate::MAX_CONTROL_BYTES {
        return Err(ReasonCode::IntegrityRejected.into());
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let response = OperationOnlyResponse::deserialize(&mut decoder)
        .map_err(|_| ReasonCode::IntegrityRejected)?;
    decoder.end().map_err(|_| ReasonCode::IntegrityRejected)?;
    let canonical = serde_json::to_vec(&response).map_err(|_| ReasonCode::IntegrityRejected)?;
    if canonical != bytes
        || response.schema != OPERATION_RESPONSE_SCHEMA
        || response.request_id != request.request_id
        || response.credential_id != request.credential_id
        || response.revision != request.expected_revision
        || response.contains_secret_values
        || response.secret_follows
        || !super::matrix::valid_result(&request.action, &response.result)
    {
        return Err(ReasonCode::IntegrityRejected.into());
    }
    Ok(response)
}
