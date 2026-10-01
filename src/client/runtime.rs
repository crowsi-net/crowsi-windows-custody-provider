use std::{path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{
    CustodyClient, HelperIdentity, PROTOCOL, PROVIDER_KIND, RUNTIME_SCHEMA, ReasonCode, Result,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    schema: String,
    kind: String,
    namespace: String,
    helper_path: PathBuf,
    helper_sha256: String,
    protocol_version: String,
}

impl RuntimeConfig {
    /// Creates and immediately verifies the canonical runtime fields and helper image.
    ///
    /// # Errors
    ///
    /// Rejects an invalid namespace, helper path, or helper digest.
    pub fn new(namespace: String, helper_path: PathBuf, helper_sha256: String) -> Result<Self> {
        let value = Self {
            schema: RUNTIME_SCHEMA.into(),
            kind: PROVIDER_KIND.into(),
            namespace,
            helper_path,
            helper_sha256,
            protocol_version: PROTOCOL.into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Parses the single canonical runtime document and validates its pinned helper immediately.
    ///
    /// # Errors
    ///
    /// Rejects oversized, unknown, malformed, mismatched, or stale runtime configuration.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 16 * 1024 {
            return Err(ReasonCode::ContractRejected.into());
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| ReasonCode::ContractRejected)?;
        value.validate()?;
        Ok(value)
    }

    /// Revalidates the helper bytes and produces a closed WSL client.
    ///
    /// # Errors
    ///
    /// Rejects a changed runtime, helper image, namespace, or invalid consumer timeout.
    pub fn into_client(self, timeout: Duration) -> Result<CustodyClient> {
        self.validate()?;
        let helper = HelperIdentity::new(self.helper_path, self.helper_sha256)?;
        CustodyClient::new(helper, self.namespace, timeout)
    }

    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    #[must_use]
    pub fn helper_path(&self) -> &std::path::Path {
        &self.helper_path
    }

    #[must_use]
    pub fn helper_sha256(&self) -> &str {
        &self.helper_sha256
    }

    #[must_use]
    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }

    fn validate(&self) -> Result<()> {
        if self.schema != RUNTIME_SCHEMA
            || self.kind != PROVIDER_KIND
            || self.protocol_version != PROTOCOL
            || !crate::protocol::namespace(&self.namespace)
        {
            return Err(ReasonCode::ContractRejected.into());
        }
        HelperIdentity::new(self.helper_path.clone(), self.helper_sha256.clone()).map(|_| ())
    }
}
