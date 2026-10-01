use serde::{Serialize, de::DeserializeOwned};

use crate::{ReasonCode, Result};

use super::{MAX_CONTROL_BYTES, PROTOCOL, REQUEST_SCHEMA, Request};

/// Decodes one bounded control document with the target type's closed field contract.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, or unknown-field JSON.
pub fn decode_control<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    if body.is_empty() || body.len() > MAX_CONTROL_BYTES {
        return Err(ReasonCode::ContractRejected.into());
    }
    serde_json::from_slice(body).map_err(|_| ReasonCode::ContractRejected.into())
}

/// Encodes one control document while enforcing the wire-size ceiling.
///
/// # Errors
///
/// Rejects serialization failures and empty or oversized output.
pub fn encode_control<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| ReasonCode::ContractRejected)?;
    if bytes.is_empty() || bytes.len() > MAX_CONTROL_BYTES {
        return Err(ReasonCode::ContractRejected.into());
    }
    Ok(bytes)
}

pub(crate) fn validate_request(request: &Request) -> Result<()> {
    let valid = request.schema == REQUEST_SCHEMA
        && request.protocol == PROTOCOL
        && namespace(&request.namespace)
        && identifier(&request.request_id, 128)
        && match &request.operation {
            super::Operation::Doctor => true,
            super::Operation::Put {
                credential_id,
                expected_revision,
            } => {
                identifier(credential_id, 128) && expected_revision.as_deref().is_none_or(revision)
            }
            super::Operation::Metadata { credential_id } => identifier(credential_id, 128),
            super::Operation::Get {
                credential_id,
                expected_revision,
            }
            | super::Operation::Delete {
                credential_id,
                expected_revision,
            } => identifier(credential_id, 128) && revision(expected_revision),
        };
    valid
        .then_some(())
        .ok_or(ReasonCode::ContractRejected.into())
}

pub(crate) fn namespace(value: &str) -> bool {
    (3..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

pub(crate) fn identifier(value: &str, maximum: usize) -> bool {
    (1..=maximum).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
}

pub(crate) fn revision(value: &str) -> bool {
    value.len() == 69
        && value.starts_with("rev1:")
        && value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::revision;

    #[test]
    fn revision_accepts_only_opaque_v1_tokens() {
        assert!(revision(&format!("rev1:{}", "a".repeat(64))));
        assert!(!revision(&format!("sha256:{}", "a".repeat(64))));
        assert!(!revision(&format!("rev1:{}", "A".repeat(64))));
    }
}
