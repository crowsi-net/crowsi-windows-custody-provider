use serde::{Deserialize, Serialize};

use super::{PROTOCOL, REQUEST_SCHEMA};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub protocol: String,
    pub namespace: String,
    pub request_id: String,
    pub operation: Operation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Operation {
    Doctor,
    Put {
        credential_id: String,
        expected_revision: Option<String>,
    },
    Metadata {
        credential_id: String,
    },
    Get {
        credential_id: String,
        expected_revision: String,
    },
    Delete {
        credential_id: String,
        expected_revision: String,
    },
}

impl Request {
    #[must_use]
    pub fn new(
        namespace: impl Into<String>,
        request_id: impl Into<String>,
        operation: Operation,
    ) -> Self {
        Self {
            schema: REQUEST_SCHEMA.into(),
            protocol: PROTOCOL.into(),
            namespace: namespace.into(),
            request_id: request_id.into(),
            operation,
        }
    }
}
