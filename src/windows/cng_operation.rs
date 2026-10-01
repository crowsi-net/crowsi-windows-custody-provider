use crate::{
    OperationCredentialMetadata, OperationOnlyAction, OperationOnlyBackend, OperationOnlyResult,
    ReasonCode, Result,
};

use super::{cng_registry, cng_registry::CngEntry, cng_sign};

pub(super) struct WindowsCngOperationBackend {
    entries: Vec<CngEntry>,
}

impl WindowsCngOperationBackend {
    pub(super) fn open() -> Result<Self> {
        Ok(Self {
            entries: cng_registry::load()?,
        })
    }

    fn entry(&self, credential_id: &str) -> Result<&CngEntry> {
        self.entries
            .iter()
            .find(|item| item.credential_id == credential_id)
            .ok_or(ReasonCode::CredentialNotFound.into())
    }
}

impl OperationOnlyBackend for WindowsCngOperationBackend {
    fn metadata(&self, credential_id: &str) -> Result<OperationCredentialMetadata> {
        let entry = self.entry(credential_id)?;
        Ok(OperationCredentialMetadata {
            credential_id: entry.credential_id.clone(),
            revision: entry.revision.clone(),
            credential_class: entry.credential_class,
        })
    }

    fn invoke(
        &mut self,
        credential_id: &str,
        action: &OperationOnlyAction,
    ) -> Result<OperationOnlyResult> {
        let entry = self.entry(credential_id)?;
        match action {
            OperationOnlyAction::Sign {
                algorithm,
                digest_sha256,
            } => Ok(OperationOnlyResult::Signature {
                algorithm: *algorithm,
                value_hex: cng_sign::sign(entry, *algorithm, digest_sha256)?,
            }),
            OperationOnlyAction::ProviderOperation {
                provider,
                operation,
                input_digest_sha256,
            } if provider == "github" && operation == "sign-app-jwt" => {
                Ok(OperationOnlyResult::ProviderResult {
                    provider: provider.clone(),
                    operation: operation.clone(),
                    value_hex: cng_sign::sign_rsa(entry, input_digest_sha256)?,
                })
            }
            OperationOnlyAction::ProviderOperation { .. } => {
                Err(ReasonCode::OperationOnlyActionRejected.into())
            }
        }
    }
}
