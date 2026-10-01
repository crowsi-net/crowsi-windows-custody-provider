use std::{path::Path, sync::Arc};

use crate::{ReasonCode, Result};

use super::{DurableOperationNonceLedger, OperationLedgerBinding};

#[derive(Clone, Debug)]
pub struct FileNonceLedger {
    root: Arc<super::ledger_root::LedgerRoot>,
}

impl FileNonceLedger {
    /// Opens or creates one owner-private durable operation ledger.
    ///
    /// # Errors
    ///
    /// Rejects legacy, linked, non-directory, rollback, or unavailable storage.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let root = super::ledger_io::open_root(path.as_ref())?;
        Ok(Self { root })
    }

    fn inspect(
        &self,
        binding: &OperationLedgerBinding,
        now: u64,
    ) -> Result<super::ledger_store::LedgerMatch> {
        super::ledger_io::with_locked(&self.root, |store| {
            store.observe_and_prune(now)?;
            store.classify(binding)
        })
    }
}

impl DurableOperationNonceLedger for FileNonceLedger {
    fn completed_exact(
        &self,
        binding: &OperationLedgerBinding,
        now_epoch_s: u64,
    ) -> Result<Option<Vec<u8>>> {
        match self.inspect(binding, now_epoch_s)? {
            super::ledger_store::LedgerMatch::Absent
            | super::ledger_store::LedgerMatch::Prepared => Ok(None),
            super::ledger_store::LedgerMatch::Completed(bytes) => Ok(Some(bytes)),
            super::ledger_store::LedgerMatch::Cancelled => {
                Err(ReasonCode::OperationOnlyAuthorizationReplayed.into())
            }
        }
    }

    fn invoke_exact(
        &self,
        binding: &OperationLedgerBinding,
        now_epoch_s: u64,
        accept_absent: &mut dyn FnMut() -> Result<()>,
        invoke_prepared: &mut dyn FnMut() -> Result<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        super::ledger_io::with_locked(&self.root, |store| {
            store.observe_and_prune(now_epoch_s)?;
            match store.classify(binding)? {
                super::ledger_store::LedgerMatch::Completed(bytes) => return Ok(bytes),
                super::ledger_store::LedgerMatch::Cancelled => {
                    return Err(ReasonCode::OperationOnlyAuthorizationReplayed.into());
                }
                super::ledger_store::LedgerMatch::Absent => {
                    super::ledger_transition::prepare(store, binding, now_epoch_s, accept_absent)?;
                }
                super::ledger_store::LedgerMatch::Prepared => {}
            }
            super::ledger_failpoint::trip(super::OperationLedgerFailpoint::AfterPrepare)?;
            let bytes = invoke_prepared()?;
            super::ledger_failpoint::trip(
                super::OperationLedgerFailpoint::AfterInvokeBeforeComplete,
            )?;
            super::ledger_transition::complete(store, binding, now_epoch_s, &bytes)?;
            super::ledger_failpoint::trip(
                super::OperationLedgerFailpoint::AfterCompleteBeforeReturn,
            )?;
            Ok(bytes)
        })
    }
}
