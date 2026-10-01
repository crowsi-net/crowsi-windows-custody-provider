use crowsi_windows_custody_provider::{
    OperationCredentialMetadata, OperationOnlyAction, OperationOnlyBackend,
    OperationOnlyCredentialClass, OperationOnlyResult, Result,
};

pub struct Backend;

impl OperationOnlyBackend for Backend {
    fn metadata(&self, credential_id: &str) -> Result<OperationCredentialMetadata> {
        Ok(OperationCredentialMetadata {
            credential_id: credential_id.into(),
            revision: super::production_operation_support::revision(),
            credential_class: OperationOnlyCredentialClass::Ed25519SigningKey,
        })
    }

    fn invoke(&mut self, _: &str, action: &OperationOnlyAction) -> Result<OperationOnlyResult> {
        let OperationOnlyAction::Sign { algorithm, .. } = action else {
            unreachable!("fixture uses signing only")
        };
        Ok(OperationOnlyResult::Signature {
            algorithm: *algorithm,
            value_hex: "ab".repeat(64),
        })
    }
}
