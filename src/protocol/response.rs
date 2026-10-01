use serde::{Deserialize, Serialize};

use crate::ReasonCode;

#[cfg(windows)]
use super::{PROTOCOL, PROVIDER_KIND, RESPONSE_SCHEMA};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub credential_id: String,
    pub revision: String,
    pub provider_kind: String,
}

impl Metadata {
    #[cfg(windows)]
    pub(crate) fn new(credential_id: String, revision: String) -> Self {
        Self {
            credential_id,
            revision,
            provider_kind: PROVIDER_KIND.into(),
        }
    }

    #[must_use]
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub schema: String,
    pub protocol: String,
    pub request_id: String,
    pub result: ResponseState,
    pub contains_secret_values: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ResponseState {
    Ready {
        operation: String,
        metadata: Option<Metadata>,
        secret_follows: bool,
    },
    Error {
        reason_code: ReasonCode,
    },
}

impl Response {
    #[cfg(windows)]
    pub(crate) fn ready(
        id: String,
        operation: &str,
        metadata: Option<Metadata>,
        secret: bool,
    ) -> Self {
        Self::new(
            id,
            ResponseState::Ready {
                operation: operation.into(),
                metadata,
                secret_follows: secret,
            },
        )
    }

    #[cfg(windows)]
    pub(crate) fn error(id: String, reason_code: ReasonCode) -> Self {
        Self::new(id, ResponseState::Error { reason_code })
    }

    #[cfg(windows)]
    fn new(request_id: String, result: ResponseState) -> Self {
        Self {
            schema: RESPONSE_SCHEMA.into(),
            protocol: PROTOCOL.into(),
            request_id,
            result,
            contains_secret_values: false,
        }
    }

    #[must_use]
    pub fn metadata(&self) -> Option<&Metadata> {
        match &self.result {
            ResponseState::Ready { metadata, .. } => metadata.as_ref(),
            ResponseState::Error { .. } => None,
        }
    }

    #[must_use]
    pub fn reason_code(&self) -> Option<ReasonCode> {
        match &self.result {
            ResponseState::Error { reason_code } => Some(*reason_code),
            ResponseState::Ready { .. } => None,
        }
    }
}
