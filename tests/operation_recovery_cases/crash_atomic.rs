use std::sync::atomic::{AtomicUsize, Ordering};

use crowsi_windows_custody_provider::{
    DurableOperationNonceLedger, FileNonceLedger, OperationLedgerFailpoint, ReasonCode,
    arm_operation_ledger_failpoint,
};
use tempfile::tempdir;

use super::super::support;

pub fn run() {
    let root = tempdir().expect("temporary root");
    let path = root.path().join("ledger");
    let ledger = FileNonceLedger::open(&path).expect("ledger");
    let binding = support::binding(77, 800);
    arm_operation_ledger_failpoint(Some(OperationLedgerFailpoint::AfterPrepare));
    assert_eq!(
        support::failure(
            ledger.invoke_exact(&binding, 800, &mut || Ok(()), &mut || panic!(
                "prepare failpoint precedes backend"
            ),)
        ),
        ReasonCode::OperationOnlyResultUnknown
    );
    let calls = AtomicUsize::new(0);
    arm_operation_ledger_failpoint(Some(
        OperationLedgerFailpoint::AfterStateReplaceBeforeAnchor,
    ));
    assert_eq!(
        support::failure(ledger.invoke_exact(
            &binding,
            800,
            &mut || panic!("Prepared retry skips acceptance"),
            &mut || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(b"atomic-response".to_vec())
            },
        )),
        ReasonCode::OperationOnlyResultUnknown
    );
    drop(ledger);
    assert_eq!(
        FileNonceLedger::open(path)
            .expect("forward-recovered ledger")
            .completed_exact(&binding, 800)
            .expect("completed cache"),
        Some(b"atomic-response".to_vec())
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
