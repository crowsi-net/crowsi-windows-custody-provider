use crate::{ClientResponse, Operation, Request, Result};

use super::CustodyClient;

impl CustodyClient {
    /// Probes `CurrentUser` DPAPI without persisting a credential.
    ///
    /// # Errors
    ///
    /// Propagates contract, helper, transport, or provider failures.
    pub fn doctor(&self, request_id: impl Into<String>) -> Result<ClientResponse> {
        self.execute(
            &Request::new(&self.namespace, request_id, Operation::Doctor),
            None,
        )
    }

    /// Reads validated metadata without returning secret material.
    ///
    /// # Errors
    ///
    /// Propagates contract, helper, transport, integrity, or not-found failures.
    pub fn metadata(
        &self,
        request_id: impl Into<String>,
        credential_id: impl Into<String>,
    ) -> Result<ClientResponse> {
        self.execute(
            &Request::new(
                &self.namespace,
                request_id,
                Operation::Metadata {
                    credential_id: credential_id.into(),
                },
            ),
            None,
        )
    }

    /// Retrieves one exact revision through the explicit owner-local export boundary.
    ///
    /// # Errors
    ///
    /// Rejects stale revisions and all provider or transport failures.
    pub fn get(
        &self,
        request_id: impl Into<String>,
        credential_id: impl Into<String>,
        expected_revision: impl Into<String>,
    ) -> Result<ClientResponse> {
        self.execute(
            &Request::new(
                &self.namespace,
                request_id,
                Operation::Get {
                    credential_id: credential_id.into(),
                    expected_revision: expected_revision.into(),
                },
            ),
            None,
        )
    }

    /// Creates or revision-conditionally replaces one credential.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, stale, or unavailable custody operations.
    pub fn put(
        &self,
        request_id: impl Into<String>,
        credential_id: impl Into<String>,
        expected_revision: Option<String>,
        secret: &[u8],
    ) -> Result<ClientResponse> {
        self.execute(
            &Request::new(
                &self.namespace,
                request_id,
                Operation::Put {
                    credential_id: credential_id.into(),
                    expected_revision,
                },
            ),
            Some(secret),
        )
    }

    /// Deletes only the exact currently stored revision.
    ///
    /// # Errors
    ///
    /// Rejects stale revisions and all provider or transport failures.
    pub fn delete(
        &self,
        request_id: impl Into<String>,
        credential_id: impl Into<String>,
        expected_revision: impl Into<String>,
    ) -> Result<ClientResponse> {
        self.execute(
            &Request::new(
                &self.namespace,
                request_id,
                Operation::Delete {
                    credential_id: credential_id.into(),
                    expected_revision: expected_revision.into(),
                },
            ),
            None,
        )
    }
}
