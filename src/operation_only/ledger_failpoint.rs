use std::cell::Cell;

use crate::{ReasonCode, Result};

thread_local! {
    static ARMED: Cell<u8> = const { Cell::new(0) };
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OperationLedgerFailpoint {
    AfterPrepare = 1,
    AfterInvokeBeforeComplete = 2,
    AfterCompleteBeforeReturn = 3,
    AfterStateReplaceBeforeAnchor = 4,
}

#[doc(hidden)]
pub fn arm_operation_ledger_failpoint(value: Option<OperationLedgerFailpoint>) {
    ARMED.with(|armed| armed.set(value.map_or(0, |stage| stage as u8)));
}

pub(super) fn trip(stage: OperationLedgerFailpoint) -> Result<()> {
    ARMED.with(|armed| {
        if armed.get() != stage as u8 {
            return Ok(());
        }
        armed.set(0);
        Err(ReasonCode::OperationOnlyResultUnknown.into())
    })
}
