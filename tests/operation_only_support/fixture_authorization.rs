fn status(context: &OperationContext) -> CurrentDeviceStatusV1 {
    CurrentDeviceStatusV1 {
        schema: "ihat://identity/current-device-status/v1".into(),
        issuer: "ihat-identity-runtime".into(),
        audience: context.audience.clone(),
        service_id: context.service_id.clone(),
        pairwise_subject: context.pairwise_subject.clone(),
        device_id: context.device_id.clone(),
        device_proof_key_ref: context.device_proof_key_ref.clone(),
        session_ref: context.session_ref.clone(),
        device_posture: DevicePostureV1 {
            state: context.device_posture.clone(),
            revision: context.device_posture_revision,
        },
        revocation_epochs: RevocationEpochsV1 {
            subject: context.subject_revocation_epoch,
            service: context.service_revocation_epoch,
            device: context.device_revocation_epoch,
            session: context.session_revocation_epoch,
        },
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 30,
        nonce: "nonce-operation-1".into(),
        key_id: "ihat-status-key:fixture".into(),
        signature: "00".repeat(64),
    }
}

pub fn resign(value: &mut OperationOnlyRequest) {
    let bytes = authorization_signing_bytes(&value.pa_authorization).expect("signing bytes");
    value.pa_authorization.signature_hex = FakeVerifier::signature(&bytes);
}

fn action_binding(value: &OperationOnlyAction) -> String {
    match value {
        OperationOnlyAction::Sign { algorithm, .. } => format!("sign:{}", algorithm.as_str()),
        OperationOnlyAction::ProviderOperation {
            provider,
            operation,
            ..
        } => format!("provider-operation:{provider}:{operation}"),
    }
}
