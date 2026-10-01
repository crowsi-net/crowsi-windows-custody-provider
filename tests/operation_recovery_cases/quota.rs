use std::sync::atomic::{AtomicUsize, Ordering};

use crowsi_windows_custody_provider::{
    DurableOperationNonceLedger, FileNonceLedger, OperationLedgerFailpoint, ReasonCode,
    arm_operation_ledger_failpoint,
};
use tempfile::tempdir;

use super::super::support;

const NOW: u64 = 800;

pub fn clock_and_capacity() {
    clock_rollback();
    response_reservations_do_not_oversubscribe();
    reservation_boundary_completes();
}

fn clock_rollback() {
    let root = tempdir().expect("temporary root");
    let path = root.path().join("clock");
    let ledger = FileNonceLedger::open(&path).expect("ledger");
    let binding = support::binding(1, NOW);
    ledger
        .invoke_exact(&binding, NOW, &mut || Ok(()), &mut || Ok(b"ok".to_vec()))
        .expect("completed operation");
    let reopened = FileNonceLedger::open(path).expect("reopened ledger");
    assert_eq!(
        support::failure(reopened.completed_exact(&binding, 120)),
        ReasonCode::OperationOnlyAuthorizationReplayed
    );
}

fn response_reservations_do_not_oversubscribe() {
    let root = tempdir().expect("temporary root");
    let ledger = FileNonceLedger::open(root.path().join("capacity")).expect("ledger");
    for index in 0..128 {
        arm_operation_ledger_failpoint(Some(OperationLedgerFailpoint::AfterPrepare));
        assert_eq!(
            support::failure(ledger.invoke_exact(
                &support::binding(index, NOW),
                NOW,
                &mut || Ok(()),
                &mut || panic!("AfterPrepare must precede backend"),
            )),
            ReasonCode::OperationOnlyResultUnknown
        );
    }
    let accepted = AtomicUsize::new(0);
    let invoked = AtomicUsize::new(0);
    assert_eq!(
        support::failure(ledger.invoke_exact(
            &support::binding(129, NOW),
            NOW,
            &mut || {
                accepted.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            &mut || {
                invoked.fetch_add(1, Ordering::SeqCst);
                Ok(b"must-not-run".to_vec())
            },
        )),
        ReasonCode::StorageUnavailable
    );
    assert_eq!(
        (
            accepted.load(Ordering::SeqCst),
            invoked.load(Ordering::SeqCst)
        ),
        (0, 0)
    );
}

fn reservation_boundary_completes() {
    let root = tempdir().expect("temporary root");
    let path = root.path().join("boundary");
    let ledger = FileNonceLedger::open(&path).expect("ledger");
    for index in 0..127 {
        arm_operation_ledger_failpoint(Some(OperationLedgerFailpoint::AfterPrepare));
        let _ = ledger.invoke_exact(
            &support::binding(index, NOW),
            NOW,
            &mut || Ok(()),
            &mut || panic!("not invoked"),
        );
    }
    let boundary = support::binding(127, NOW);
    assert_eq!(
        ledger
            .invoke_exact(&boundary, NOW, &mut || Ok(()), &mut || Ok(b"ok".to_vec()))
            .expect("reserved boundary completes"),
        b"ok"
    );
    assert_eq!(
        FileNonceLedger::open(path)
            .expect("restart")
            .completed_exact(&boundary, NOW)
            .expect("cache"),
        Some(b"ok".to_vec())
    );
}

pub fn retention_releases_quota() {
    super::quota_retention::retention_releases_quota();
}

pub fn invalid_retention_boundary() {
    super::quota_retention::invalid_retention_boundary();
}
