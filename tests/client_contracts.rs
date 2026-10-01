#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    time::Duration,
};

use crowsi_windows_custody_provider::{
    CustodyClient, HelperIdentity, ReasonCode, RuntimeConfig, SecretOutput,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

static_assertions::assert_not_impl_any!(SecretOutput: Clone, std::fmt::Debug, serde::Serialize);

#[test]
fn helper_identity_rejects_digest_drift_and_symlink() {
    let directory = tempdir().expect("temporary directory");
    let helper = directory.path().join("provider.exe");
    fs::write(&helper, b"binary").expect("helper fixture");
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(b"binary")));
    assert!(HelperIdentity::new(helper.clone(), digest.clone()).is_ok());
    fs::write(&helper, b"changed").expect("helper replacement");
    assert_eq!(
        failure(HelperIdentity::new(helper.clone(), digest)).reason(),
        ReasonCode::HelperIdentityRejected
    );
    let link = directory.path().join("linked.exe");
    symlink(&helper, &link).expect("symlink fixture");
    let changed = format!("sha256:{}", hex::encode(Sha256::digest(b"changed")));
    assert!(HelperIdentity::new(link, changed).is_err());
}

#[test]
fn timed_out_helper_is_terminated_and_reaped() {
    let directory = tempdir().expect("temporary directory");
    let helper = directory.path().join("blocked.exe");
    fs::write(&helper, b"#!/bin/sh\nsleep 5\n").expect("helper fixture");
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).expect("helper mode");
    let digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(fs::read(&helper).expect("helper bytes")))
    );
    let identity = HelperIdentity::new(helper, digest).expect("valid helper identity");
    let client = CustodyClient::new(
        identity,
        "coela.crowsi.credentials",
        Duration::from_millis(20),
    )
    .expect("valid client");
    assert_eq!(
        failure(client.doctor("request-timeout")).reason(),
        ReasonCode::TransportTimeout
    );
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
fn ext4_helper_completes_one_clean_environment_exchange() {
    let directory = tempdir().expect("temporary directory");
    let helper = directory.path().join("provider.exe");
    let source = r"#!/usr/bin/python3
import json, os, struct, sys
n = struct.unpack('>I', sys.stdin.buffer.read(4))[0]
request = json.loads(sys.stdin.buffer.read(n))
if sys.stdin.buffer.read(1) or any(k.endswith('SECRET') for k in os.environ):
    raise SystemExit(2)
response = {'schema':'crowsi://platform-custody/response/v1',
 'protocol':'crowsi-windows-custody-v1','request_id':request['request_id'],
 'result':{'state':'ready','operation':'doctor','metadata':None,'secret_follows':False},
 'contains_secret_values':False}
body = json.dumps(response, separators=(',', ':')).encode()
sys.stdout.buffer.write(struct.pack('>I', len(body)) + body)
";
    fs::write(&helper, source).expect("helper fixture");
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).expect("helper mode");
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(source.as_bytes())));
    let runtime = RuntimeConfig::new("coela.crowsi.credentials".into(), helper, digest)
        .expect("valid runtime");
    let bytes = serde_json::to_vec(&runtime).expect("runtime encoding");
    let client = RuntimeConfig::parse(&bytes)
        .expect("runtime parsing")
        .into_client(Duration::from_secs(2))
        .expect("client composition");
    assert!(
        client
            .doctor("request-ext4")
            .expect("doctor response")
            .response
            .metadata()
            .is_none()
    );
}

#[test]
fn source_has_no_powershell_or_secret_argv_fallback() {
    let root = env!("CARGO_MANIFEST_DIR");
    let process =
        fs::read_to_string(format!("{root}/src/client/process.rs")).expect("client source");
    let windows = fs::read_to_string(format!("{root}/src/windows/dpapi.rs")).expect("DPAPI source");
    let storage =
        fs::read_to_string(format!("{root}/src/windows/storage.rs")).expect("storage source");
    let replace =
        fs::read_to_string(format!("{root}/src/windows/replace.rs")).expect("replace source");
    let storage_file = fs::read_to_string(format!("{root}/src/windows/storage_file.rs"))
        .expect("storage file source");
    let binding = fs::read_to_string(format!("{root}/src/binding.rs")).expect("binding source");
    assert!(process.contains(".env_clear()"));
    assert!(process.contains("child.kill()") && process.contains("child.wait()"));
    assert!(!process.to_ascii_lowercase().contains("powershell"));
    assert!(windows.contains("CRYPTPROTECT_UI_FORBIDDEN"));
    assert!(storage.contains("FILE_ATTRIBUTE_REPARSE_POINT"));
    assert!(storage.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
    assert!(storage.contains("ensure_directory_chain"));
    assert!(replace.contains("MOVEFILE_WRITE_THROUGH"));
    assert!(replace.contains("safe_destination(destination)?"));
    assert!(replace.matches("safe_source(").count() >= 3);
    assert!(storage_file.contains("MAX_PROTECTED_BYTES_U64 + 1"));
    assert!(storage_file.contains("binding::entropy(namespace, id)"));
    assert!(binding.contains("namespace_len.to_be_bytes()"));
    assert!(binding.contains("credential_len.to_be_bytes()"));
}
