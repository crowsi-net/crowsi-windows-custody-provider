#[path = "operation_only_cases/mod.rs"]
mod cases;
#[path = "operation_only_support/mod.rs"]
mod support;

#[test] // OP-01
fn op_01_generic_get_rejects_operation_only_credentials() {
    cases::op_01();
}

#[test] // OP-02
fn op_02_only_closed_rsa_ed25519_sign_and_provider_operations_are_allowed() {
    cases::op_02();
}

#[test] // OP-03
fn op_03_authorization_is_exactly_bound_and_wrong_values_are_rejected() {
    cases::op_03();
}

#[test] // OP-04
fn op_04_wrong_replayed_and_expired_authorizations_fail_closed() {
    cases::op_04();
}

#[test] // OP-05
fn op_05_output_is_secret_free_and_direct_same_user_invocation_needs_pa() {
    cases::op_05();
}

#[test] // OP-06
fn op_06_nonce_has_one_concurrent_winner_and_stays_consumed_after_restart() {
    cases::op_06();
}

#[test] // OP-07
fn op_07_malformed_oversize_trailing_and_tampered_inputs_are_rejected() {
    cases::op_07();
}

#[test]
fn device_a_revocation_does_not_invalidate_device_b() {
    cases::device_scoped_revocation();
}
