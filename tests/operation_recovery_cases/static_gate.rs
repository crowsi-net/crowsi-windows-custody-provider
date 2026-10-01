use std::{fs, path::Path};

pub fn run() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dispatcher = read(root, "src/operation_only/dispatcher.rs");
    let completed = dispatcher
        .find("completed_exact")
        .expect("completed lookup");
    let invoke = dispatcher.find("invoke_exact").expect("invoke phase");
    assert!(completed < invoke);
    assert!(dispatcher.contains("ledger_binding::from_request(request)"));

    let transition = read(root, "src/operation_only/ledger_transition.rs");
    assert!(transition.contains("authorization_expires_at_epoch_s <= now"));
    assert!(transition.contains("checked_add(RESPONSE_RETENTION_SECONDS)"));
    assert!(transition.contains("saturating_add(crate::MAX_CONTROL_BYTES)"));
    let validation = read(root, "src/operation_only/ledger_validation.rs");
    assert!(validation.contains("authorization_expires_at_epoch_s"));
    assert!(validation.contains("checked_add(super::ledger_model::RESPONSE_RETENTION_SECONDS)"));

    let root_source = read(root, "src/operation_only/ledger_root.rs");
    assert!(root_source.contains("directory: File"));
    assert!(root_source.contains("self.directory.as_raw_fd()"));
    assert!(root_source.contains("identity(&named)? == self.identity"));
    assert!(root_source.contains("identity(&opened)? == self.identity"));
    assert!(root_source.contains("if !matches"));
    let file_source = read(root, "src/operation_only/ledger_fs.rs");
    assert!(!file_source.contains("root.join("));
    assert!(file_source.contains("root.child("));
    assert!(file_source.contains("root.sync()"));

    let service = read(root, "src/windows/operation_service.rs");
    assert!(service.contains("execute_body_bytes(body)"));
    let ports = read(root, "src/operation_only/ports.rs");
    assert!(!ports.contains("reserve_once") && !ports.contains("cancel_prepared"));
    let model = read(root, "src/operation_only/ledger_model.rs");
    assert!(model.contains("Cancelled"));
    assert!(model.contains("response_reservation_bytes"));
    assert!(model.contains("completion_state_reservation_bytes"));

    for relative in authored_files() {
        let source = read(root, relative);
        assert!(
            source.lines().count() < 150,
            "authored source exceeds 149 lines: {relative}"
        );
    }
}

fn read(root: &Path, relative: &str) -> String {
    fs::read_to_string(root.join(relative)).expect("source file")
}

fn authored_files() -> &'static [&'static str] {
    &[
        "src/operation_only/dispatcher.rs",
        "src/operation_only/ledger.rs",
        "src/operation_only/ledger_binding.rs",
        "src/operation_only/ledger_codec.rs",
        "src/operation_only/ledger_failpoint.rs",
        "src/operation_only/ledger_file_validation.rs",
        "src/operation_only/ledger_fs.rs",
        "src/operation_only/ledger_io.rs",
        "src/operation_only/ledger_model.rs",
        "src/operation_only/ledger_retention.rs",
        "src/operation_only/ledger_root.rs",
        "src/operation_only/ledger_root_validation.rs",
        "src/operation_only/ledger_store.rs",
        "src/operation_only/ledger_transition.rs",
        "src/operation_only/ledger_validation.rs",
        "src/operation_only/production.rs",
        "src/operation_only/response_cache.rs",
        "tests/operation_recovery.rs",
        "tests/operation_recovery_support.rs",
        "tests/operation_recovery_cases/crash.rs",
        "tests/operation_recovery_cases/crash_atomic.rs",
        "tests/operation_recovery_cases/quota.rs",
        "tests/operation_recovery_cases/quota_retention.rs",
        "tests/operation_recovery_cases/replay.rs",
        "tests/operation_recovery_cases/response_binding.rs",
        "tests/operation_recovery_cases/static_gate.rs",
        "tests/operation_recovery_cases/storage.rs",
        "tests/operation_recovery_cases/storage_files.rs",
        "tests/operation_recovery_cases/storage_swap.rs",
    ]
}
