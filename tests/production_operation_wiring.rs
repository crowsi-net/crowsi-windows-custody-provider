use super::production_operation_support::Fixture;
use tempfile::tempdir;

#[cfg(unix)]
#[test] // OP-12
fn operation_client_uses_the_pinned_clean_environment_helper_path() {
    use crowsi_windows_custody_provider::{CustodyClient, HelperIdentity};
    use sha2::{Digest, Sha256};
    use std::{fs, os::unix::fs::PermissionsExt, time::Duration};

    let root = tempdir().expect("temporary root");
    let helper = root.path().join("provider.exe");
    let script = r"#!/usr/bin/python3
import json, os, struct, sys
n = struct.unpack('>I', sys.stdin.buffer.read(4))[0]
r = json.loads(sys.stdin.buffer.read(n))
if sys.stdin.buffer.read(1) or any(k != 'LC_CTYPE' for k in os.environ):
    raise SystemExit(9)
o = {'schema':'crowsi://platform-custody/operation-response/v3',
 'request_id':r['request_id'],'credential_id':r['credential_id'],
 'revision':r['expected_revision'],
 'result':{'kind':'signature','algorithm':'ed25519','value_hex':'ab'*64},
 'contains_secret_values':False,'secret_follows':False}
b = json.dumps(o,separators=(',',':')).encode()
sys.stdout.buffer.write(struct.pack('>I',len(b))+b)
";
    fs::write(&helper, script).expect("helper script");
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).expect("helper mode");
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(script.as_bytes())));
    let identity = HelperIdentity::new(helper, digest).expect("pinned helper");
    let client = CustodyClient::new(identity, "unused.operation-only", Duration::from_secs(2))
        .expect("client");
    let request = Fixture::new().request("device-a", 7, "nonce-op-12");
    client
        .execute_operation(&request)
        .expect("operation response");
}

#[test] // OP-13
fn windows_helper_source_routes_v3_to_cng_and_has_no_operation_export_path() {
    let root = env!("CARGO_MANIFEST_DIR");
    let service = std::fs::read_to_string(format!("{root}/src/windows/service.rs"))
        .expect("Windows service source");
    let backend = std::fs::read_to_string(format!("{root}/src/windows/cng_sign.rs"))
        .expect("CNG signing source");
    let operation_service =
        std::fs::read_to_string(format!("{root}/src/windows/operation_service.rs"))
            .expect("operation service source");
    let export_gate = std::fs::read_to_string(format!("{root}/src/operation_only/generic_get.rs"))
        .expect("generic export gate source");
    assert!(service.contains("OPERATION_REQUEST_SCHEMA"));
    assert!(service.contains("registered_class"));
    assert!(service.contains("reject_registered_generic_operation"));
    assert!(export_gate.contains("OperationOnlyExportRejected"));
    assert!(operation_service.contains("ProductionOperationDispatcher"));
    assert!(backend.contains("NCryptOpenKey") && backend.contains("NCryptSignHash"));
    assert!(backend.contains("NCRYPT_EXPORT_POLICY_PROPERTY"));
    assert!(backend.contains("export_policy == 0"));
    assert!(!backend.contains("Store::get") && !backend.contains("expose_secret"));
    for schema in [
        "operation-request-v3.schema.json",
        "operation-response-v3.schema.json",
        "operation-trust-v1.schema.json",
        "cng-key-registry-v1.schema.json",
    ] {
        let body = std::fs::read(format!("{root}/schemas/{schema}")).expect("schema source");
        let _: serde_json::Value = serde_json::from_slice(&body).expect("valid schema JSON");
    }
}
