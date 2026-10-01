use std::sync::atomic::{AtomicUsize, Ordering};

use crowsi_windows_custody_provider::{
    DurableOperationNonceLedger, FileNonceLedger, OperationLedgerFailpoint, ReasonCode,
    arm_operation_ledger_failpoint,
};
use tempfile::tempdir;

use super::super::support;

const NOW: u64 = 800;
const WEEK: u64 = 7 * 24 * 60 * 60;
const MONTH: u64 = 30 * 24 * 60 * 60;

pub fn retention_releases_quota() {
    let root = tempdir().expect("temporary root");
    let path = root.path().join("retention");
    let ledger = FileNonceLedger::open(&path).expect("ledger");
    for index in 0..128 {
        arm_operation_ledger_failpoint(Some(OperationLedgerFailpoint::AfterPrepare));
        let _ = ledger.invoke_exact(
            &support::binding(index, NOW),
            NOW,
            &mut || Ok(()),
            &mut || panic!("not invoked"),
        );
    }
    let cancel_at = NOW + 60 + WEEK;
    let _ = ledger.completed_exact(&support::binding(0, NOW), cancel_at);
    drop(ledger);
    let remove_at = cancel_at + MONTH;
    let fresh = support::binding(999, remove_at);
    let reopened = FileNonceLedger::open(path).expect("restart");
    assert_eq!(
        reopened
            .invoke_exact(&fresh, remove_at, &mut || Ok(()), &mut || Ok(
                b"fresh".to_vec()
            ),)
            .expect("quota released after tombstone retention"),
        b"fresh"
    );
}

pub fn invalid_retention_boundary() {
    let root = tempdir().expect("temporary root");
    let ledger = FileNonceLedger::open(root.path().join("retention")).expect("ledger");
    for (index, expiry) in [NOW, u64::MAX].into_iter().enumerate() {
        let mut binding = support::binding(index + 2_000, NOW);
        binding.authorization_expires_at_epoch_s = expiry;
        let accepted = AtomicUsize::new(0);
        assert_eq!(
            support::failure(ledger.invoke_exact(
                &binding,
                NOW,
                &mut || {
                    accepted.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                &mut || panic!("invalid retention must not invoke"),
            )),
            ReasonCode::OperationOnlyAuthorizationExpired
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 0);
    }
}
