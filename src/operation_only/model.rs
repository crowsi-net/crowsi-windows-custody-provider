use ihat_identity_assertion_contracts::CurrentDeviceStatusV1;
use serde::{Deserialize, Serialize};

pub const OPERATION_REQUEST_SCHEMA: &str = "crowsi://platform-custody/operation-request/v3";
pub const OPERATION_AUTHORIZATION_SCHEMA: &str =
    "crowsi://platform-custody/operation-authorization/v3";
pub const OPERATION_RESPONSE_SCHEMA: &str = "crowsi://platform-custody/operation-response/v3";
pub const OPERATION_AUTHORIZATION_ISSUER: &str = "crowsi-policy-administrator";
pub const OPERATION_AUTHORIZATION_AUDIENCE: &str = "crowsi-windows-custody-provider";
pub const OPERATION_SERVICE_ID: &str = "service:crowsi";
pub const OPERATION_WORKLOAD_ID: &str = "workload:crowsi-windows-custody";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationOnlyCredentialClass {
    RsaSigningKey,
    Ed25519SigningKey,
    ProviderOperation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningAlgorithm {
    RsaPkcs1Sha256,
    Ed25519,
}

impl SigningAlgorithm {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RsaPkcs1Sha256 => "rsa-pkcs1-sha256",
            Self::Ed25519 => "ed25519",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OperationOnlyAction {
    Sign {
        algorithm: SigningAlgorithm,
        digest_sha256: String,
    },
    ProviderOperation {
        provider: String,
        operation: String,
        input_digest_sha256: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationBinding {
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub device_proof_key_ref: String,
    pub session_ref: String,
    pub device_posture: String,
    pub device_posture_revision: u64,
    pub subject_revocation_epoch: u64,
    pub service_revocation_epoch: u64,
    pub device_revocation_epoch: u64,
    pub session_revocation_epoch: u64,
    pub workload_id: String,
    pub audience: String,
    pub action: String,
    pub request_digest_sha256: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaOperationAuthorization {
    pub schema: String,
    pub issuer: String,
    pub key_id: String,
    pub binding: OperationBinding,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationOnlyRequest {
    pub schema: String,
    pub request_id: String,
    pub credential_id: String,
    pub expected_revision: String,
    pub credential_class: OperationOnlyCredentialClass,
    pub action: OperationOnlyAction,
    pub current_device_status: CurrentDeviceStatusV1,
    pub pa_authorization: PaOperationAuthorization,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationContext {
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub device_proof_key_ref: String,
    pub session_ref: String,
    pub device_posture: String,
    pub device_posture_revision: u64,
    pub subject_revocation_epoch: u64,
    pub service_revocation_epoch: u64,
    pub device_revocation_epoch: u64,
    pub session_revocation_epoch: u64,
    pub workload_id: String,
    pub audience: String,
    pub now_epoch_s: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationCredentialMetadata {
    pub credential_id: String,
    pub revision: String,
    pub credential_class: OperationOnlyCredentialClass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OperationOnlyResult {
    Signature {
        algorithm: SigningAlgorithm,
        value_hex: String,
    },
    ProviderResult {
        provider: String,
        operation: String,
        value_hex: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationOnlyResponse {
    pub schema: String,
    pub request_id: String,
    pub credential_id: String,
    pub revision: String,
    pub result: OperationOnlyResult,
    pub contains_secret_values: bool,
    pub secret_follows: bool,
}
