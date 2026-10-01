use std::{fs, os::unix::fs::PermissionsExt as _, path::Path};

use crowsi_windows_custody_provider::{DurableOperationNonceLedger, FileNonceLedger, ReasonCode};
use tempfile::tempdir;

use super::super::super::support;

pub fn run() {
    substitute_root();
    substitute_parent();
}

fn substitute_root() {
    let root = tempdir().expect("temporary root");
    let path = root.path().join("ledger");
    let ledger = completed(&path, 1);
    let moved = root.path().join("moved-ledger");
    fs::rename(&path, &moved).expect("rename pinned root");
    copy_ledger(&moved, &path);
    assert_eq!(
        support::failure(ledger.completed_exact(&support::binding(1, 800), 800)),
        ReasonCode::IntegrityRejected
    );
}

fn substitute_parent() {
    let root = tempdir().expect("temporary root");
    let parent = root.path().join("parent");
    fs::create_dir(&parent).expect("parent");
    let path = parent.join("ledger");
    let ledger = completed(&path, 2);
    let moved = root.path().join("moved-parent");
    fs::rename(&parent, &moved).expect("rename parent");
    fs::create_dir(&parent).expect("replacement parent");
    copy_ledger(&moved.join("ledger"), &path);
    assert!(matches!(
        support::failure(ledger.completed_exact(&support::binding(2, 800), 800)),
        ReasonCode::IntegrityRejected | ReasonCode::StorageUnavailable
    ));
}

fn completed(path: &Path, index: usize) -> FileNonceLedger {
    let ledger = FileNonceLedger::open(path).expect("ledger");
    ledger
        .invoke_exact(
            &support::binding(index, 800),
            800,
            &mut || Ok(()),
            &mut || Ok(b"exact".to_vec()),
        )
        .expect("completed");
    ledger
}

fn copy_ledger(source: &Path, target: &Path) {
    fs::create_dir(target).expect("replacement ledger");
    fs::set_permissions(target, fs::Permissions::from_mode(0o700)).expect("root mode");
    for entry in fs::read_dir(source).expect("source ledger") {
        let entry = entry.expect("entry");
        let target_file = target.join(entry.file_name());
        fs::copy(entry.path(), &target_file).expect("copy old ledger snapshot");
        fs::set_permissions(target_file, fs::Permissions::from_mode(0o600)).expect("file mode");
    }
}
