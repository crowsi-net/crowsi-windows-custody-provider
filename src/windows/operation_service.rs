use std::path::PathBuf;

use crate::{ProductionOperationDispatcher, Result};

use super::{cng_operation::WindowsCngOperationBackend, cng_registry};

pub(super) fn execute(body: &[u8]) -> Result<Vec<u8>> {
    let root = cng_registry::operation_root()?;
    let trust = cng_registry::read_bounded(&root.join("operation-trust-v1.json"))?;
    let backend = WindowsCngOperationBackend::open()?;
    let mut dispatcher = ProductionOperationDispatcher::open(backend, &trust, nonce_path(&root))?;
    dispatcher.execute_body_bytes(body)
}

fn nonce_path(root: &std::path::Path) -> PathBuf {
    root.join("consumed-operation-nonces-v1")
}
