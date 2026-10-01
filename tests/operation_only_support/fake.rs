use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use crowsi_windows_custody_provider::{
    OperationCredentialMetadata, OperationOnlyCredentialClass, OperationOnlyStore,
    PaAuthorizationVerifier, PaOperationAuthorization, Result, SigningAlgorithm,
    WindowsOperationPort,
};
use sha2::{Digest, Sha256};

pub struct FakeStore(pub OperationCredentialMetadata);

impl FakeStore {
    pub fn new(class: OperationOnlyCredentialClass) -> Self {
        Self(OperationCredentialMetadata {
            credential_id: "operation-key-1".into(),
            revision: super::revision(),
            credential_class: class,
        })
    }
}

impl OperationOnlyStore for FakeStore {
    fn metadata(&self, _: &str) -> Result<OperationCredentialMetadata> {
        Ok(self.0.clone())
    }
}

pub struct FakeWindowsPort(pub Arc<AtomicUsize>);

impl FakeWindowsPort {
    pub fn new() -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (Self(Arc::clone(&calls)), calls)
    }
}

impl WindowsOperationPort for FakeWindowsPort {
    fn sign(
        &mut self,
        _: &OperationCredentialMetadata,
        _: SigningAlgorithm,
        _: &str,
    ) -> Result<String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok("ab".repeat(64))
    }

    fn provider_operation(
        &mut self,
        _: &OperationCredentialMetadata,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok("cd".repeat(32))
    }
}

pub struct FakeVerifier;

impl FakeVerifier {
    pub fn signature(bytes: &[u8]) -> String {
        let digest = hex::encode(Sha256::digest(bytes));
        format!("{digest}{digest}")
    }
}

impl PaAuthorizationVerifier for FakeVerifier {
    fn verify(&self, value: &PaOperationAuthorization, bytes: &[u8]) -> bool {
        value.signature_hex == Self::signature(bytes)
    }
}
