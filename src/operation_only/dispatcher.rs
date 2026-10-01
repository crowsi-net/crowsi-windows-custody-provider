use std::cell::RefCell;

use crate::{ReasonCode, Result};

use super::{
    DurableOperationNonceLedger, OPERATION_RESPONSE_SCHEMA, OperationContext,
    OperationCredentialMetadata, OperationOnlyBackend, OperationOnlyRequest, OperationOnlyResponse,
    PaAuthorizationVerifier,
};

pub struct OperationOnlyDispatcher<B, V, L> {
    backend: B,
    verifier: V,
    ledger: L,
}

impl<B, V, L> OperationOnlyDispatcher<B, V, L>
where
    B: OperationOnlyBackend,
    V: PaAuthorizationVerifier,
    L: DurableOperationNonceLedger,
{
    pub const fn new(backend: B, verifier: V, ledger: L) -> Self {
        Self {
            backend,
            verifier,
            ledger,
        }
    }

    /// Authorizes and performs one operation without exporting key material.
    ///
    /// # Errors
    ///
    /// Rejects invalid input, authorization, replay, metadata drift, or backend failure.
    pub fn execute(
        &mut self,
        request: &OperationOnlyRequest,
        context: &OperationContext,
    ) -> Result<OperationOnlyResponse> {
        let bytes =
            self.execute_bytes_with_accept(request, context.now_epoch_s, || Ok(context.clone()))?;
        super::response_cache::decode_exact(&bytes, request)
    }

    pub(crate) fn execute_bytes_with_accept<F>(
        &mut self,
        request: &OperationOnlyRequest,
        now_epoch_s: u64,
        mut accept_live: F,
    ) -> Result<Vec<u8>>
    where
        F: FnMut() -> Result<OperationContext>,
    {
        super::validation::validate_request(request)?;
        if !super::matrix::valid_matrix(request.credential_class, &request.action) {
            return Err(ReasonCode::OperationOnlyActionRejected.into());
        }
        let binding = super::ledger_binding::from_request(request)?;
        if let Some(bytes) = self.ledger.completed_exact(&binding, now_epoch_s)? {
            super::response_cache::decode_exact(&bytes, request)?;
            return Ok(bytes);
        }
        let backend = RefCell::new(&mut self.backend);
        let verifier = &self.verifier;
        let mut accept = || {
            let context = accept_live()?;
            super::authorization::verify(request, &context, verifier)?;
            checked_metadata(&**backend.borrow(), request).map(|_| ())
        };
        let mut invoke = || {
            let mut backend = backend.borrow_mut();
            let metadata = checked_metadata(&**backend, request)?;
            let result = backend.invoke(&request.credential_id, &request.action)?;
            if !super::matrix::valid_result(&request.action, &result) {
                return Err(ReasonCode::OperationOnlyResultUnknown.into());
            }
            super::response_cache::encode(&OperationOnlyResponse {
                schema: OPERATION_RESPONSE_SCHEMA.into(),
                request_id: request.request_id.clone(),
                credential_id: metadata.credential_id,
                revision: metadata.revision,
                result,
                contains_secret_values: false,
                secret_follows: false,
            })
        };
        let bytes = self
            .ledger
            .invoke_exact(&binding, now_epoch_s, &mut accept, &mut invoke)?;
        super::response_cache::decode_exact(&bytes, request)?;
        Ok(bytes)
    }

    pub fn into_parts(self) -> (B, V, L) {
        (self.backend, self.verifier, self.ledger)
    }
}

fn checked_metadata<B: OperationOnlyBackend>(
    backend: &B,
    request: &OperationOnlyRequest,
) -> Result<OperationCredentialMetadata> {
    let metadata = backend.metadata(&request.credential_id)?;
    if metadata.credential_id != request.credential_id
        || metadata.revision != request.expected_revision
    {
        return Err(ReasonCode::CredentialChanged.into());
    }
    if metadata.credential_class != request.credential_class {
        return Err(ReasonCode::OperationOnlyActionRejected.into());
    }
    Ok(metadata)
}
