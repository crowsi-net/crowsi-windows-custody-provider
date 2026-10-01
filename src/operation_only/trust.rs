use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ihat_identity_assertion_contracts::AssertionVerifier;
use serde::Deserialize;

use crate::{ReasonCode, Result};

use super::{PaAuthorizationVerifier, PaOperationAuthorization};

pub const OPERATION_TRUST_SCHEMA: &str = "crowsi://platform-custody/operation-trust/v1";
const MAX_TRUST_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OperationTrust {
    pub schema: String,
    pub pa_key_id: String,
    pub pa_public_key_hex: String,
    pub status_issuer: String,
    pub status_key_id: String,
    pub status_public_key_hex: String,
}

impl OperationTrust {
    /// Decodes a closed trust-anchor document.
    ///
    /// # Errors
    ///
    /// Rejects malformed, weak, unknown, or non-v1 trust input.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_TRUST_BYTES {
            return Err(ReasonCode::OperationOnlyAuthorizationRequired.into());
        }
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        let value = Self::deserialize(&mut decoder)
            .map_err(|_| ReasonCode::OperationOnlyAuthorizationRequired)?;
        decoder
            .end()
            .map_err(|_| ReasonCode::OperationOnlyAuthorizationRequired)?;
        if value.schema != OPERATION_TRUST_SCHEMA
            || !identifier(&value.pa_key_id)
            || !identifier(&value.status_key_id)
            || !identifier(&value.status_issuer)
            || parse_key(&value.pa_public_key_hex).is_none()
            || parse_key(&value.status_public_key_hex).is_none()
        {
            return Err(ReasonCode::OperationOnlyAuthorizationRequired.into());
        }
        Ok(value)
    }

    pub(crate) fn pa_verifier(&self) -> Result<PinnedPaVerifier> {
        Ok(PinnedPaVerifier {
            key_id: self.pa_key_id.clone(),
            key: parse_key(&self.pa_public_key_hex)
                .ok_or(ReasonCode::OperationOnlyAuthorizationRequired)?,
        })
    }

    pub(crate) fn status_verifier(&self) -> Result<PinnedStatusVerifier> {
        Ok(PinnedStatusVerifier {
            key_id: self.status_key_id.clone(),
            key: parse_key(&self.status_public_key_hex)
                .ok_or(ReasonCode::OperationOnlyAuthorizationRequired)?,
        })
    }
}

pub(crate) struct PinnedPaVerifier {
    key_id: String,
    key: VerifyingKey,
}

impl PaAuthorizationVerifier for PinnedPaVerifier {
    fn verify(&self, value: &PaOperationAuthorization, bytes: &[u8]) -> bool {
        value.key_id == self.key_id && verify(&self.key, bytes, &value.signature_hex)
    }
}

pub(crate) struct PinnedStatusVerifier {
    key_id: String,
    key: VerifyingKey,
}

impl AssertionVerifier for PinnedStatusVerifier {
    fn verify(&self, key_id: &str, bytes: &[u8], signature: &str) -> bool {
        key_id == self.key_id && verify(&self.key, bytes, signature)
    }
}

fn verify(key: &VerifyingKey, bytes: &[u8], signature: &str) -> bool {
    hex::decode(signature)
        .ok()
        .and_then(|raw| Signature::from_slice(&raw).ok())
        .is_some_and(|signature| key.verify(bytes, &signature).is_ok())
}

fn parse_key(value: &str) -> Option<VerifyingKey> {
    let raw: [u8; 32] = hex::decode(value).ok()?.try_into().ok()?;
    if raw == [0; 32] {
        return None;
    }
    VerifyingKey::from_bytes(&raw).ok()
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}
