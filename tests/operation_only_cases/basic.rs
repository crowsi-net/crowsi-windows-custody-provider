use std::sync::atomic::Ordering;

use crowsi_windows_custody_provider::{
    OperationOnlyCredentialClass as Class, ReasonCode, reject_operation_only_get,
};

use super::{ed25519, failure, provider, rsa, support};

pub fn op_01() {
    for class in [
        Class::RsaSigningKey,
        Class::Ed25519SigningKey,
        Class::ProviderOperation,
    ] {
        assert_eq!(
            failure(reject_operation_only_get(class)),
            ReasonCode::OperationOnlyExportRejected
        );
    }
}

pub fn op_02() {
    let allowed = [
        (Class::RsaSigningKey, rsa()),
        (Class::Ed25519SigningKey, ed25519()),
        (Class::ProviderOperation, provider()),
    ];
    for (class, action) in allowed {
        let mut harness = support::Harness::new(class);
        assert!(
            harness
                .dispatcher
                .execute(&support::request(class, action), &support::context())
                .is_ok()
        );
    }
    let rejected = [
        (Class::RsaSigningKey, ed25519()),
        (Class::Ed25519SigningKey, rsa()),
        (Class::ProviderOperation, rsa()),
    ];
    for (class, action) in rejected {
        let mut harness = support::Harness::new(class);
        assert_eq!(
            failure(
                harness
                    .dispatcher
                    .execute(&support::request(class, action), &support::context())
            ),
            ReasonCode::OperationOnlyActionRejected
        );
        assert_eq!(harness.calls.load(Ordering::SeqCst), 0);
    }
}

pub fn op_05() {
    let mut value = support::request(Class::Ed25519SigningKey, ed25519());
    value.pa_authorization.signature_hex = "0".repeat(128);
    let mut harness = support::Harness::new(Class::Ed25519SigningKey);
    assert_eq!(
        failure(harness.dispatcher.execute(&value, &support::context())),
        ReasonCode::OperationOnlyAuthorizationRequired
    );
    assert_eq!(harness.calls.load(Ordering::SeqCst), 0);
    support::resign(&mut value);
    let response = harness
        .dispatcher
        .execute(&value, &support::context())
        .expect("authorized operation");
    let wire = serde_json::to_string(&response).expect("response JSON");
    assert_eq!(
        response.schema,
        "crowsi://platform-custody/operation-response/v3"
    );
    assert!(!response.contains_secret_values && !response.secret_follows);
    assert!(!wire.contains("private_key") && !wire.contains("fixture-secret"));
}
