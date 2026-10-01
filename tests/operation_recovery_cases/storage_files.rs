use std::{
    fs,
    os::unix::fs::{PermissionsExt as _, symlink},
    process::Command,
};

use crowsi_windows_custody_provider::{FileNonceLedger, ReasonCode};
use tempfile::tempdir;

use super::super::super::support;

pub fn run() {
    rejects_symlink_root();
    rejects_hardlink();
    rejects_fifo();
    rejects_oversize_and_malformed();
    recovers_crash_temp();
    rejects_legacy_nonce_file();
}

fn rejects_symlink_root() {
    let root = tempdir().expect("temporary root");
    let target = root.path().join("target");
    fs::create_dir(&target).expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).expect("mode");
    let link = root.path().join("link");
    symlink(&target, &link).expect("symlink");
    assert_eq!(
        support::failure(FileNonceLedger::open(link)),
        ReasonCode::StorageUnavailable
    );
}

fn rejects_hardlink() {
    let root = tempdir().expect("temporary root");
    let path = root.path().join("hardlink");
    drop(FileNonceLedger::open(&path).expect("ledger"));
    fs::hard_link(
        path.join("ledger-v2.json"),
        path.join(".ledger-v2.state.tmp"),
    )
    .expect("hard link");
    assert_eq!(
        support::failure(FileNonceLedger::open(path)),
        ReasonCode::StorageUnavailable
    );
}

fn rejects_fifo() {
    let root = tempdir().expect("temporary root");
    let path = root.path().join("fifo");
    drop(FileNonceLedger::open(&path).expect("ledger"));
    fs::remove_file(path.join("ledger-v2.json")).expect("remove state");
    assert!(
        Command::new("mkfifo")
            .arg(path.join("ledger-v2.json"))
            .status()
            .expect("mkfifo")
            .success()
    );
    assert_eq!(
        support::failure(FileNonceLedger::open(path)),
        ReasonCode::StorageUnavailable
    );
}

fn rejects_oversize_and_malformed() {
    for (bytes, expected) in [
        (
            vec![b'x'; 4 * 1024 * 1024 + 1],
            ReasonCode::StorageUnavailable,
        ),
        (b"{".to_vec(), ReasonCode::IntegrityRejected),
    ] {
        let root = tempdir().expect("temporary root");
        let path = root.path().join("bad-state");
        drop(FileNonceLedger::open(&path).expect("ledger"));
        fs::write(path.join("ledger-v2.json"), bytes).expect("bad state");
        assert_eq!(support::failure(FileNonceLedger::open(path)), expected);
    }
}

fn recovers_crash_temp() {
    let root = tempdir().expect("temporary root");
    let path = root.path().join("temp");
    drop(FileNonceLedger::open(&path).expect("ledger"));
    let temp = path.join(".ledger-v2.state.tmp");
    fs::write(&temp, b"partial-crash-write").expect("crash temp");
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o600)).expect("temp mode");
    drop(FileNonceLedger::open(&path).expect("temp recovered"));
    assert!(!temp.exists());
}

fn rejects_legacy_nonce_file() {
    let root = tempdir().expect("temporary root");
    let path = root.path().join("legacy");
    drop(FileNonceLedger::open(&path).expect("ledger"));
    let legacy = path.join("a".repeat(64));
    fs::write(&legacy, b"CWN1\n").expect("legacy file");
    fs::set_permissions(legacy, fs::Permissions::from_mode(0o600)).expect("legacy mode");
    assert_eq!(
        support::failure(FileNonceLedger::open(path)),
        ReasonCode::StorageUnavailable
    );
}
