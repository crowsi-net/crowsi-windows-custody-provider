use std::{fs, io::Cursor, time::Duration};

use crowsi_windows_custody_provider::{
    MAX_CONTROL_BYTES, Operation, PROTOCOL, REQUEST_SCHEMA, ReasonCode, Request, RuntimeConfig,
    decode_control, encode_control, read_frame, write_frame,
};

#[path = "operation_only.rs"]
mod operation_only;

#[test]
fn request_contract_is_closed_and_versioned() {
    let request = Request::new("coela.crowsi.credentials", "request-1", Operation::Doctor);
    let bytes = encode_control(&request).expect("request should encode");
    let decoded: Request = decode_control(&bytes).expect("request should decode");
    assert_eq!(decoded.schema, REQUEST_SCHEMA);
    assert_eq!(decoded.protocol, PROTOCOL);
    let unknown = br#"{"schema":"crowsi://platform-custody/request/v1","protocol":"crowsi-windows-custody-v1","namespace":"coela.crowsi.credentials","request_id":"r","operation":{"operation":"doctor"},"extra":true}"#;
    assert_eq!(
        decode_control::<Request>(unknown)
            .expect_err("unknown field must fail")
            .reason(),
        ReasonCode::ContractRejected
    );
}

#[test]
fn frame_is_variable_length_bounded_and_exact() {
    let mut output = Vec::new();
    write_frame(&mut output, b"abc", MAX_CONTROL_BYTES).expect("frame should encode");
    assert_eq!(&output[..4], &[0, 0, 0, 3]);
    assert_eq!(
        read_frame(&mut Cursor::new(output), MAX_CONTROL_BYTES).expect("frame should decode"),
        b"abc"
    );
    assert!(
        write_frame(
            &mut Vec::new(),
            &vec![0; MAX_CONTROL_BYTES + 1],
            MAX_CONTROL_BYTES
        )
        .is_err()
    );
    assert!(read_frame(&mut Cursor::new(vec![0, 0, 0, 4, 1]), MAX_CONTROL_BYTES).is_err());
}

#[test]
fn runtime_rejects_unknown_fields_and_wrong_provider_kind() {
    let value = serde_json::json!({
        "schema": "crowsi://platform-custody/runtime/v1",
        "kind": "linux-secret-service", "namespace": "coela.crowsi.credentials",
        "helper_path": "/tmp/helper.exe",
        "helper_sha256": format!("sha256:{}", "0".repeat(64)), "protocol_version": PROTOCOL
    });
    let config: RuntimeConfig = serde_json::from_value(value).expect("shape should decode");
    assert_eq!(
        failure(config.into_client(Duration::from_secs(5))).reason(),
        ReasonCode::ContractRejected
    );
    let unknown = serde_json::json!({
        "schema": "crowsi://platform-custody/runtime/v1", "kind": "windows-dpapi-user",
        "namespace": "coela.crowsi.credentials", "protocol_version": PROTOCOL,
        "helper_path": "/tmp/helper.exe",
        "helper_sha256": format!("sha256:{}", "0".repeat(64)), "fallback": true
    });
    assert!(serde_json::from_value::<RuntimeConfig>(unknown).is_err());
}

fn failure<T>(
    result: crowsi_windows_custody_provider::Result<T>,
) -> crowsi_windows_custody_provider::CustodyError {
    match result {
        Ok(_) => panic!("operation must fail"),
        Err(error) => error,
    }
}

#[test]
fn runtime_schema_has_exact_six_field_contract() {
    let root = env!("CARGO_MANIFEST_DIR");
    let bytes = fs::read(format!(
        "{root}/schemas/platform-custody-runtime-v1.schema.json"
    ))
    .expect("schema should exist");
    let schema: serde_json::Value = serde_json::from_slice(&bytes).expect("schema should parse");
    assert_eq!(
        schema["required"].as_array().expect("required array").len(),
        6
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["properties"]["kind"]["const"], "windows-dpapi-user");
    assert_eq!(schema["properties"]["protocol_version"]["const"], PROTOCOL);
}

#[test]
fn reason_codes_are_closed_prefixed_wire_values() {
    let encoded =
        serde_json::to_string(&ReasonCode::IntegrityRejected).expect("reason code should encode");
    assert_eq!(encoded, r#""windows-custody-integrity-rejected""#);
    assert!(serde_json::from_str::<ReasonCode>(r#""integrity-rejected""#).is_err());
}
