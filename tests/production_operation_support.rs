use crowsi_windows_custody_provider::{
    OPERATION_AUTHORIZATION_SCHEMA, OPERATION_REQUEST_SCHEMA, OperationBinding,
    OperationOnlyAction, OperationOnlyCredentialClass, OperationOnlyRequest,
    PaOperationAuthorization, SigningAlgorithm, authorization_signing_bytes,
    operation_request_digest,
};
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    CurrentDeviceStatusV1, DevicePostureV1, RevocationEpochsV1, canonical_current_status_payload,
};

pub struct Fixture {
    pub pa: SigningKey,
    pub status: SigningKey,
}

impl Fixture {
    pub fn new() -> Self {
        Self {
            pa: SigningKey::from_bytes(&[3; 32]),
            status: SigningKey::from_bytes(&[7; 32]),
        }
    }

    pub fn trust(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": "crowsi://platform-custody/operation-trust/v1",
            "pa_key_id": "pa-operation-key:1",
            "pa_public_key_hex": hex::encode(self.pa.verifying_key().as_bytes()),
            "status_issuer": "ihat-identity-runtime",
            "status_key_id": "ihat-status-key:1",
            "status_public_key_hex": hex::encode(self.status.verifying_key().as_bytes())
        }))
        .expect("trust JSON")
    }

    pub fn request(&self, device: &str, device_epoch: u64, nonce: &str) -> OperationOnlyRequest {
        let now = now();
        let status = self.status(device, device_epoch, nonce, now);
        let mut value = request(&status, now);
        resign_authorization(&mut value, &self.pa);
        value
    }

    fn status(
        &self,
        device: &str,
        device_epoch: u64,
        nonce: &str,
        now: u64,
    ) -> CurrentDeviceStatusV1 {
        let mut value = CurrentDeviceStatusV1 {
            schema: "ihat://identity/current-device-status/v1".into(),
            issuer: "ihat-identity-runtime".into(),
            audience: "crowsi-windows-custody-provider".into(),
            service_id: "service:crowsi".into(),
            pairwise_subject: "pairwise:crowsi:owner-1".into(),
            device_id: device.into(),
            device_proof_key_ref: format!("device-key:{device}"),
            session_ref: format!("sref_windows_{device}"),
            device_posture: DevicePostureV1 {
                state: "compliant".into(),
                revision: 4,
            },
            revocation_epochs: RevocationEpochsV1 {
                subject: 3,
                service: 5,
                device: device_epoch,
                session: 11,
            },
            issued_at_epoch_s: now - 1,
            expires_at_epoch_s: now + 29,
            nonce: nonce.into(),
            key_id: "ihat-status-key:1".into(),
            signature: String::new(),
        };
        value.signature = hex::encode(
            self.status
                .sign(&canonical_current_status_payload(&value))
                .to_bytes(),
        );
        value
    }
}

fn request(status: &CurrentDeviceStatusV1, now: u64) -> OperationOnlyRequest {
    let mut value = OperationOnlyRequest {
        schema: OPERATION_REQUEST_SCHEMA.into(),
        request_id: format!("request-{}", status.nonce),
        credential_id: "operation-key-1".into(),
        expected_revision: revision(),
        credential_class: OperationOnlyCredentialClass::Ed25519SigningKey,
        action: OperationOnlyAction::Sign {
            algorithm: SigningAlgorithm::Ed25519,
            digest_sha256: format!("sha256:{}", "b".repeat(64)),
        },
        current_device_status: status.clone(),
        pa_authorization: PaOperationAuthorization {
            schema: OPERATION_AUTHORIZATION_SCHEMA.into(),
            issuer: "crowsi-policy-administrator".into(),
            key_id: "pa-operation-key:1".into(),
            binding: binding(status),
            issued_at_epoch_s: now - 1,
            expires_at_epoch_s: now + 20,
            signature_hex: String::new(),
        },
    };
    value.pa_authorization.binding.request_digest_sha256 =
        operation_request_digest(&value).expect("digest");
    value
}

fn binding(status: &CurrentDeviceStatusV1) -> OperationBinding {
    OperationBinding {
        service_id: status.service_id.clone(),
        pairwise_subject: status.pairwise_subject.clone(),
        device_id: status.device_id.clone(),
        device_proof_key_ref: status.device_proof_key_ref.clone(),
        session_ref: status.session_ref.clone(),
        device_posture: status.device_posture.state.clone(),
        device_posture_revision: status.device_posture.revision,
        subject_revocation_epoch: status.revocation_epochs.subject,
        service_revocation_epoch: status.revocation_epochs.service,
        device_revocation_epoch: status.revocation_epochs.device,
        session_revocation_epoch: status.revocation_epochs.session,
        workload_id: "workload:crowsi-windows-custody".into(),
        audience: status.audience.clone(),
        action: "sign:ed25519".into(),
        request_digest_sha256: String::new(),
        nonce: status.nonce.clone(),
    }
}

pub fn resign_authorization(value: &mut OperationOnlyRequest, key: &SigningKey) {
    let bytes = authorization_signing_bytes(&value.pa_authorization).expect("signing bytes");
    value.pa_authorization.signature_hex = hex::encode(key.sign(&bytes).to_bytes());
}

pub fn revision() -> String {
    format!("rev1:{}", "a".repeat(64))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("current Unix time")
        .as_secs()
}
