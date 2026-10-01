use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, CustodyError>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReasonCode {
    #[serde(rename = "windows-custody-backend-unavailable")]
    BackendUnavailable,
    #[serde(rename = "windows-custody-contract-rejected")]
    ContractRejected,
    #[serde(rename = "windows-custody-credential-changed")]
    CredentialChanged,
    #[serde(rename = "windows-custody-credential-not-found")]
    CredentialNotFound,
    #[serde(rename = "windows-custody-helper-identity-rejected")]
    HelperIdentityRejected,
    #[serde(rename = "windows-custody-integrity-rejected")]
    IntegrityRejected,
    #[serde(rename = "windows-custody-operation-only-action-rejected")]
    OperationOnlyActionRejected,
    #[serde(rename = "windows-custody-operation-only-authorization-binding-rejected")]
    OperationOnlyAuthorizationBindingRejected,
    #[serde(rename = "windows-custody-operation-only-authorization-expired")]
    OperationOnlyAuthorizationExpired,
    #[serde(rename = "windows-custody-operation-only-authorization-replayed")]
    OperationOnlyAuthorizationReplayed,
    #[serde(rename = "windows-custody-operation-only-authorization-required")]
    OperationOnlyAuthorizationRequired,
    #[serde(rename = "windows-custody-operation-only-export-rejected")]
    OperationOnlyExportRejected,
    #[serde(rename = "windows-custody-operation-only-input-rejected")]
    OperationOnlyInputRejected,
    #[serde(rename = "windows-custody-operation-only-input-tampered")]
    OperationOnlyInputTampered,
    #[serde(rename = "windows-custody-operation-only-result-unknown")]
    OperationOnlyResultUnknown,
    #[serde(rename = "windows-custody-storage-unavailable")]
    StorageUnavailable,
    #[serde(rename = "windows-custody-transport-timeout")]
    TransportTimeout,
    #[serde(rename = "windows-custody-transport-unavailable")]
    TransportUnavailable,
}

impl ReasonCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BackendUnavailable => "windows-custody-backend-unavailable",
            Self::ContractRejected => "windows-custody-contract-rejected",
            Self::CredentialChanged => "windows-custody-credential-changed",
            Self::CredentialNotFound => "windows-custody-credential-not-found",
            Self::HelperIdentityRejected => "windows-custody-helper-identity-rejected",
            Self::IntegrityRejected => "windows-custody-integrity-rejected",
            Self::OperationOnlyActionRejected => "windows-custody-operation-only-action-rejected",
            Self::OperationOnlyAuthorizationBindingRejected => {
                "windows-custody-operation-only-authorization-binding-rejected"
            }
            Self::OperationOnlyAuthorizationExpired => {
                "windows-custody-operation-only-authorization-expired"
            }
            Self::OperationOnlyAuthorizationReplayed => {
                "windows-custody-operation-only-authorization-replayed"
            }
            Self::OperationOnlyAuthorizationRequired => {
                "windows-custody-operation-only-authorization-required"
            }
            Self::OperationOnlyExportRejected => "windows-custody-operation-only-export-rejected",
            Self::OperationOnlyInputRejected => "windows-custody-operation-only-input-rejected",
            Self::OperationOnlyInputTampered => "windows-custody-operation-only-input-tampered",
            Self::OperationOnlyResultUnknown => "windows-custody-operation-only-result-unknown",
            Self::StorageUnavailable => "windows-custody-storage-unavailable",
            Self::TransportTimeout => "windows-custody-transport-timeout",
            Self::TransportUnavailable => "windows-custody-transport-unavailable",
        }
    }
}

#[derive(Debug, Error)]
pub enum CustodyError {
    #[error("{}", .0.as_str())]
    Denied(ReasonCode),
}

impl CustodyError {
    #[must_use]
    pub const fn reason(&self) -> ReasonCode {
        match self {
            Self::Denied(reason) => *reason,
        }
    }
}

impl From<ReasonCode> for CustodyError {
    fn from(value: ReasonCode) -> Self {
        Self::Denied(value)
    }
}
