use crowsi_windows_custody_provider::{
    DurableOperationNonceLedger, OperationLedgerBinding, OperationOnlyDispatcher,
    OperationOnlyResponse, OperationOnlyResult, ReasonCode, Result, SigningAlgorithm,
};

use super::super::{production_operation_support::Fixture, support};

struct Cache(Vec<u8>);

impl DurableOperationNonceLedger for Cache {
    fn completed_exact(&self, _: &OperationLedgerBinding, _: u64) -> Result<Option<Vec<u8>>> {
        Ok(Some(self.0.clone()))
    }

    fn invoke_exact(
        &self,
        _: &OperationLedgerBinding,
        _: u64,
        _: &mut dyn FnMut() -> Result<()>,
        _: &mut dyn FnMut() -> Result<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        panic!("completed cache must precede invocation")
    }
}

pub fn run() {
    let fixture = Fixture::new();
    let request = fixture.request("device-a", 7, "response-binding");
    let valid = OperationOnlyResponse {
        schema: crowsi_windows_custody_provider::OPERATION_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        credential_id: request.credential_id.clone(),
        revision: request.expected_revision.clone(),
        result: OperationOnlyResult::Signature {
            algorithm: SigningAlgorithm::Ed25519,
            value_hex: "ab".repeat(64),
        },
        contains_secret_values: false,
        secret_follows: false,
    };
    let mut invalid = Vec::new();
    let mut changed = valid.clone();
    changed.request_id = "other-request".into();
    invalid.push(changed);
    let mut changed = valid.clone();
    changed.credential_id = "other-credential".into();
    invalid.push(changed);
    let mut changed = valid.clone();
    changed.revision = format!("rev1:{}", "b".repeat(64));
    invalid.push(changed);
    let mut changed = valid.clone();
    changed.result = OperationOnlyResult::Signature {
        algorithm: SigningAlgorithm::RsaPkcs1Sha256,
        value_hex: "ab".repeat(64),
    };
    invalid.push(changed);
    let mut changed = valid;
    changed.contains_secret_values = true;
    invalid.push(changed);
    let mut changed = invalid[0].clone();
    changed.request_id.clone_from(&request.request_id);
    changed.secret_follows = true;
    invalid.push(changed);
    for response in invalid {
        reject(
            &request,
            serde_json::to_vec(&response).expect("response JSON"),
        );
    }
    let mut noncanonical = serde_json::to_vec(&OperationOnlyResponse {
        schema: crowsi_windows_custody_provider::OPERATION_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        credential_id: request.credential_id.clone(),
        revision: request.expected_revision.clone(),
        result: OperationOnlyResult::Signature {
            algorithm: SigningAlgorithm::Ed25519,
            value_hex: "ab".repeat(64),
        },
        contains_secret_values: false,
        secret_follows: false,
    })
    .expect("response JSON");
    noncanonical.push(b' ');
    reject(&request, noncanonical);
}

fn reject(request: &crowsi_windows_custody_provider::OperationOnlyRequest, bytes: Vec<u8>) {
    let mut dispatcher = OperationOnlyDispatcher::new(
        support::Backend::new(),
        support::RejectVerifier,
        Cache(bytes),
    );
    assert_eq!(
        support::failure(dispatcher.execute(
            request,
            &support::context(request, request.pa_authorization.issued_at_epoch_s + 1),
        )),
        ReasonCode::IntegrityRejected
    );
}
