use crate::protocol::{MAX_SECRET_BYTES, identifier, revision};
use crate::{
    Metadata, Operation, PROTOCOL, PROVIDER_KIND, RESPONSE_SCHEMA, ReasonCode, ResponseState,
    Result,
};

use super::ClientResponse;

pub(super) fn secret_shape(operation: &Operation, secret: Option<&[u8]>) -> Result<()> {
    let valid = matches!(operation, Operation::Put { .. }) == secret.is_some()
        && secret.is_none_or(|value| !value.is_empty() && value.len() <= MAX_SECRET_BYTES);
    valid
        .then_some(())
        .ok_or(ReasonCode::ContractRejected.into())
}

pub(super) fn response(output: &ClientResponse, id: &str, operation: &Operation) -> Result<()> {
    let response = &output.response;
    let valid = response.schema == RESPONSE_SCHEMA
        && response.protocol == PROTOCOL
        && response.request_id == id
        && !response.contains_secret_values
        && match &response.result {
            ResponseState::Ready {
                operation: reported,
                metadata,
                secret_follows,
            } => {
                reported == operation_name(operation)
                    && ready_shape(operation, metadata.as_ref(), *secret_follows)
                    && *secret_follows == output.has_secret()
            }
            ResponseState::Error { .. } => !output.has_secret(),
        };
    valid
        .then_some(())
        .ok_or(ReasonCode::ContractRejected.into())
}

fn ready_shape(operation: &Operation, metadata: Option<&Metadata>, secret: bool) -> bool {
    match operation {
        Operation::Doctor => metadata.is_none() && !secret,
        Operation::Put { credential_id, .. } | Operation::Metadata { credential_id } => {
            metadata.is_some_and(|value| valid_metadata(value, credential_id)) && !secret
        }
        Operation::Get {
            credential_id,
            expected_revision,
        } => {
            metadata.is_some_and(|value| {
                valid_metadata(value, credential_id) && value.revision == *expected_revision
            }) && secret
        }
        Operation::Delete {
            credential_id,
            expected_revision,
        } => {
            metadata.is_some_and(|value| {
                valid_metadata(value, credential_id) && value.revision == *expected_revision
            }) && !secret
        }
    }
}

fn valid_metadata(metadata: &Metadata, expected_id: &str) -> bool {
    metadata.provider_kind == PROVIDER_KIND
        && metadata.credential_id == expected_id
        && identifier(&metadata.credential_id, 128)
        && revision(&metadata.revision)
}

fn operation_name(operation: &Operation) -> &'static str {
    match operation {
        Operation::Doctor => "doctor",
        Operation::Put { .. } => "put",
        Operation::Metadata { .. } => "metadata",
        Operation::Get { .. } => "get",
        Operation::Delete { .. } => "delete",
    }
}
