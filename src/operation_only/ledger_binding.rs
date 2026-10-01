use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ReasonCode, Result};

use super::{OperationOnlyCredentialClass, OperationOnlyRequest};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationLedgerBinding {
    pub full_request_digest_sha256: String,
    pub nonce_digest_sha256: String,
    pub request_id_digest_sha256: String,
    pub credential_id: String,
    pub expected_revision: String,
    pub credential_class: OperationOnlyCredentialClass,
    pub authorization_expires_at_epoch_s: u64,
}

pub(super) fn from_request(request: &OperationOnlyRequest) -> Result<OperationLedgerBinding> {
    let canonical =
        serde_json::to_vec(request).map_err(|_| ReasonCode::OperationOnlyInputRejected)?;
    Ok(OperationLedgerBinding {
        full_request_digest_sha256: digest(
            b"crowsi-windows-operation-full-request-v1\0",
            &canonical,
        ),
        nonce_digest_sha256: digest(
            b"crowsi-windows-operation-nonce-index-v1\0",
            request.pa_authorization.binding.nonce.as_bytes(),
        ),
        request_id_digest_sha256: digest(
            b"crowsi-windows-operation-request-id-index-v1\0",
            request.request_id.as_bytes(),
        ),
        credential_id: request.credential_id.clone(),
        expected_revision: request.expected_revision.clone(),
        credential_class: request.credential_class,
        authorization_expires_at_epoch_s: request.pa_authorization.expires_at_epoch_s,
    })
}

fn digest(domain: &[u8], value: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
    hex::encode(digest.finalize())
}
