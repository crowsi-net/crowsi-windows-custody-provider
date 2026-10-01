use crate::{ReasonCode, Result};

use super::OperationOnlyCredentialClass;
use crate::Operation;

/// Rejects generic export for every operation-only credential class.
///
/// # Errors
///
/// Always returns `OperationOnlyExportRejected`.
pub fn reject_operation_only_get(_: OperationOnlyCredentialClass) -> Result<()> {
    Err(ReasonCode::OperationOnlyExportRejected.into())
}

/// Applies the production generic-protocol gate to registry-classified credentials.
///
/// # Errors
///
/// Rejects mutation or export of every operation-only credential class.
pub fn reject_registered_generic_operation(
    operation: &Operation,
    registered: Option<OperationOnlyCredentialClass>,
) -> Result<()> {
    let exposes_or_mutates = matches!(
        operation,
        Operation::Put { .. } | Operation::Get { .. } | Operation::Delete { .. }
    );
    if registered.is_some() && exposes_or_mutates {
        return Err(ReasonCode::OperationOnlyExportRejected.into());
    }
    Ok(())
}
