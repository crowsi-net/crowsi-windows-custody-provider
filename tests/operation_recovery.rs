#[path = "operation_recovery_cases/mod.rs"]
mod cases;
#[path = "production_operation_support.rs"]
mod production_operation_support;
#[path = "operation_recovery_support.rs"]
mod support;

#[test]
fn response_cache_gap_restarts_with_exact_old_key_bytes() {
    cases::crash::response_cache_gap();
}

#[test]
fn state_anchor_gap_forward_recovers_exact_completed_bytes() {
    cases::crash_atomic::run();
}

#[test]
fn prepared_retry_skips_expired_live_context_but_rechecks_credential() {
    cases::crash::prepared_retry_and_drift();
}

#[test]
fn nonce_request_and_full_pa_authorization_are_exactly_bound() {
    cases::replay::full_request_binding();
}

#[test]
fn completed_cache_precedes_expired_or_rejected_live_authorization() {
    cases::replay::completed_precedes_live_state();
}

#[test]
fn clock_rollback_and_capacity_fail_closed_before_invocation() {
    cases::quota::clock_and_capacity();
}

#[test]
fn prepared_retention_releases_quota_after_durable_tombstones() {
    cases::quota::retention_releases_quota();
}

#[cfg(unix)]
#[test]
fn ledger_files_links_fifos_and_crash_temps_are_hardened() {
    cases::storage::file_types_and_temps();
}

#[cfg(unix)]
#[test]
fn pinned_root_rejects_directory_and_parent_substitution() {
    cases::storage::root_substitution();
}

#[test]
fn expired_or_overflowing_prepared_retention_is_never_committed() {
    cases::quota::invalid_retention_boundary();
}

#[test]
fn cached_response_bytes_are_canonical_and_fully_bound() {
    cases::response_binding::run();
}

#[test]
fn recovery_source_and_line_invariants_are_fixed() {
    cases::static_gate::run();
}
