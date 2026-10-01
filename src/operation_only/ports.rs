use crate::Result;

use super::{
    OperationCredentialMetadata, OperationLedgerBinding, OperationOnlyAction, OperationOnlyResult,
    PaOperationAuthorization, SigningAlgorithm,
};

pub trait OperationOnlyStore {
    /// Returns public metadata for one operation-only credential.
    ///
    /// # Errors
    ///
    /// Rejects missing, changed, or unavailable store state.
    fn metadata(&self, credential_id: &str) -> Result<OperationCredentialMetadata>;
}

pub trait WindowsOperationPort {
    /// Signs one exact digest without returning private key material.
    ///
    /// # Errors
    ///
    /// Rejects an unavailable or mismatched Windows key operation.
    fn sign(
        &mut self,
        metadata: &OperationCredentialMetadata,
        algorithm: SigningAlgorithm,
        digest_sha256: &str,
    ) -> Result<String>;

    /// Performs one provider-specific operation named by the closed request.
    ///
    /// # Errors
    ///
    /// Rejects unavailable, mismatched, or unknown provider operations.
    fn provider_operation(
        &mut self,
        metadata: &OperationCredentialMetadata,
        provider: &str,
        operation: &str,
        input_digest_sha256: &str,
    ) -> Result<String>;
}

pub trait OperationOnlyBackend {
    /// Returns the metadata independently checked by the dispatcher.
    ///
    /// # Errors
    ///
    /// Rejects missing or unavailable backend state.
    fn metadata(&self, credential_id: &str) -> Result<OperationCredentialMetadata>;

    /// Invokes one already-authorized operation.
    ///
    /// # Errors
    ///
    /// Rejects unavailable or ambiguous backend results.
    fn invoke(
        &mut self,
        credential_id: &str,
        action: &OperationOnlyAction,
    ) -> Result<OperationOnlyResult>;
}

pub trait PaAuthorizationVerifier {
    fn verify(&self, authorization: &PaOperationAuthorization, signing_bytes: &[u8]) -> bool;
}

pub trait DurableOperationNonceLedger {
    /// Returns exact completed bytes before consulting live authorization state.
    ///
    /// # Errors
    ///
    /// Rejects replay, clock rollback, corruption, or unavailable durable storage.
    fn completed_exact(
        &self,
        binding: &OperationLedgerBinding,
        now_epoch_s: u64,
    ) -> Result<Option<Vec<u8>>>;

    /// Accepts a new request, durably prepares it, invokes under the exclusive lock,
    /// and atomically caches exact response bytes. Exact Prepared retries skip
    /// `accept_absent` and invoke again only through `invoke_prepared`.
    ///
    /// # Errors
    ///
    /// Rejects replay, drift, quota exhaustion, clock rollback, or storage failure.
    fn invoke_exact(
        &self,
        binding: &OperationLedgerBinding,
        now_epoch_s: u64,
        accept_absent: &mut dyn FnMut() -> Result<()>,
        invoke_prepared: &mut dyn FnMut() -> Result<Vec<u8>>,
    ) -> Result<Vec<u8>>;
}
