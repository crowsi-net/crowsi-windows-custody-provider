use crate::Result;

use super::{
    OperationCredentialMetadata, OperationOnlyAction, OperationOnlyBackend, OperationOnlyResult,
    OperationOnlyStore, WindowsOperationPort,
};

pub struct WindowsOperationBackend<S, P> {
    store: S,
    port: P,
}

impl<S, P> WindowsOperationBackend<S, P> {
    pub const fn new(store: S, port: P) -> Self {
        Self { store, port }
    }

    pub fn into_parts(self) -> (S, P) {
        (self.store, self.port)
    }
}

impl<S, P> OperationOnlyBackend for WindowsOperationBackend<S, P>
where
    S: OperationOnlyStore,
    P: WindowsOperationPort,
{
    fn metadata(&self, credential_id: &str) -> Result<OperationCredentialMetadata> {
        self.store.metadata(credential_id)
    }

    fn invoke(
        &mut self,
        credential_id: &str,
        action: &OperationOnlyAction,
    ) -> Result<OperationOnlyResult> {
        let metadata = self.store.metadata(credential_id)?;
        Ok(match action {
            OperationOnlyAction::Sign {
                algorithm,
                digest_sha256,
            } => OperationOnlyResult::Signature {
                algorithm: *algorithm,
                value_hex: self.port.sign(&metadata, *algorithm, digest_sha256)?,
            },
            OperationOnlyAction::ProviderOperation {
                provider,
                operation,
                input_digest_sha256,
            } => OperationOnlyResult::ProviderResult {
                provider: provider.clone(),
                operation: operation.clone(),
                value_hex: self.port.provider_operation(
                    &metadata,
                    provider,
                    operation,
                    input_digest_sha256,
                )?,
            },
        })
    }
}
