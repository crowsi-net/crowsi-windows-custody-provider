#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt, time::Duration};

use crowsi_windows_custody_provider::{CustodyClient, HelperIdentity};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const SECRET: &[u8] = b"credential-material";

#[test]
fn put_and_get_keep_secret_out_of_control_json() {
    let directory = tempdir().expect("temporary directory");
    let helper = directory.path().join("provider.exe");
    fs::write(&helper, helper_source()).expect("helper fixture");
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).expect("helper mode");
    let bytes = fs::read(&helper).expect("helper bytes");
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
    let identity = HelperIdentity::new(helper, digest).expect("helper identity");
    let client = CustodyClient::new(identity, "coela.crowsi.credentials", Duration::from_secs(2))
        .expect("client");
    let put = client
        .put("request-put", "github.app.pem", None, SECRET)
        .expect("put exchange");
    let revision = put
        .response
        .metadata()
        .expect("put metadata")
        .revision()
        .to_owned();
    assert!(revision.starts_with("rev1:"));
    assert_ne!(
        revision,
        format!("sha256:{}", hex::encode(Sha256::digest(SECRET)))
    );
    assert!(
        !serde_json::to_vec(&put.response)
            .expect("response JSON")
            .windows(SECRET.len())
            .any(|window| window == SECRET)
    );
    let get = client
        .get("request-get", "github.app.pem", revision)
        .expect("get exchange");
    get.expose_secret(|secret| assert_eq!(secret, Some(SECRET)));
}

fn helper_source() -> &'static str {
    r"#!/usr/bin/python3
import json, struct, sys
def read_frame():
    size = struct.unpack('>I', sys.stdin.buffer.read(4))[0]
    return sys.stdin.buffer.read(size)
def write_frame(body):
    sys.stdout.buffer.write(struct.pack('>I', len(body)) + body)
body = read_frame()
request = json.loads(body)
operation = request['operation']['operation']
secret = b'credential-material'
if secret in body:
    raise SystemExit(2)
if operation == 'put' and read_frame() != secret:
    raise SystemExit(3)
if sys.stdin.buffer.read(1):
    raise SystemExit(4)
revision = 'rev1:' + ('a' * 64)
metadata = {'credential_id':'github.app.pem','revision':revision,
 'provider_kind':'windows-dpapi-user'}
response = {'schema':'crowsi://platform-custody/response/v1',
 'protocol':'crowsi-windows-custody-v1','request_id':request['request_id'],
 'result':{'state':'ready','operation':operation,'metadata':metadata,
 'secret_follows':operation == 'get'},'contains_secret_values':False}
write_frame(json.dumps(response, separators=(',', ':')).encode())
if operation == 'get':
    write_frame(secret)
"
}
