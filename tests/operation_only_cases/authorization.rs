use crowsi_windows_custody_provider::{
    OperationOnlyCredentialClass as Class, OperationOnlyRequest, ReasonCode,
};

use super::{ed25519, failure, support};

pub fn op_03() {
    let base = support::request(Class::Ed25519SigningKey, ed25519());
    let mutations: [fn(&mut OperationOnlyRequest); 15] = [
        |value| value.pa_authorization.issuer = "authority-other".into(),
        |value| value.pa_authorization.binding.service_id = "service:other".into(),
        |value| value.pa_authorization.binding.pairwise_subject = "pairwise:other".into(),
        |value| value.pa_authorization.binding.device_id = "device-other".into(),
        |value| value.pa_authorization.binding.device_proof_key_ref = "device-key:other".into(),
        |value| value.pa_authorization.binding.session_ref = "sref_windows_other".into(),
        |value| value.pa_authorization.binding.device_posture = "quarantined".into(),
        |value| value.pa_authorization.binding.device_posture_revision -= 1,
        |value| value.pa_authorization.binding.subject_revocation_epoch -= 1,
        |value| value.pa_authorization.binding.service_revocation_epoch -= 1,
        |value| value.pa_authorization.binding.device_revocation_epoch -= 1,
        |value| value.pa_authorization.binding.session_revocation_epoch -= 1,
        |value| value.pa_authorization.binding.workload_id = "workload:other".into(),
        |value| value.pa_authorization.binding.audience = "audience-other".into(),
        |value| value.pa_authorization.binding.action = "sign:rsa-pkcs1-sha256".into(),
    ];
    for mutate in mutations {
        let mut changed = base.clone();
        mutate(&mut changed);
        support::resign(&mut changed);
        let mut harness = support::Harness::new(Class::Ed25519SigningKey);
        assert_eq!(
            failure(harness.dispatcher.execute(&changed, &support::context())),
            ReasonCode::OperationOnlyAuthorizationBindingRejected
        );
    }
    let mut nonce_tamper = base;
    nonce_tamper.pa_authorization.binding.nonce = "nonce-tampered".into();
    let mut harness = support::Harness::new(Class::Ed25519SigningKey);
    assert_eq!(
        failure(
            harness
                .dispatcher
                .execute(&nonce_tamper, &support::context())
        ),
        ReasonCode::OperationOnlyAuthorizationRequired
    );
}

pub fn device_scoped_revocation() {
    let context_a = support::context();
    let request_a = support::request_for_context(Class::Ed25519SigningKey, ed25519(), &context_a);
    let mut revoked_a = context_a;
    revoked_a.device_revocation_epoch += 1;
    let mut harness_a = support::Harness::new(Class::Ed25519SigningKey);
    assert_eq!(
        failure(harness_a.dispatcher.execute(&request_a, &revoked_a)),
        ReasonCode::OperationOnlyAuthorizationBindingRejected
    );

    let mut context_b = support::context();
    context_b.device_id = "device-local-b".into();
    context_b.device_proof_key_ref = "device-key:local-b".into();
    context_b.device_posture_revision = 2;
    context_b.device_revocation_epoch = 1;
    let request_b = support::request_for_context(Class::Ed25519SigningKey, ed25519(), &context_b);
    let mut harness_b = support::Harness::new(Class::Ed25519SigningKey);
    assert!(harness_b.dispatcher.execute(&request_b, &context_b).is_ok());
}

pub fn op_04() {
    let value = support::request(Class::Ed25519SigningKey, ed25519());
    let mut harness = support::Harness::new(Class::Ed25519SigningKey);
    let first = harness
        .dispatcher
        .execute(&value, &support::context())
        .expect("first response");
    assert_eq!(
        harness
            .dispatcher
            .execute(&value, &support::context())
            .expect("exact replay"),
        first
    );
    let mut expired = support::request(Class::Ed25519SigningKey, ed25519());
    expired.pa_authorization.expires_at_epoch_s = support::NOW;
    support::resign(&mut expired);
    let mut expired_harness = support::Harness::new(Class::Ed25519SigningKey);
    assert_eq!(
        failure(
            expired_harness
                .dispatcher
                .execute(&expired, &support::context())
        ),
        ReasonCode::OperationOnlyAuthorizationExpired
    );
}
