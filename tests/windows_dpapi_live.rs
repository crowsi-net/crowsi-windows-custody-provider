use std::{fs::File, io::Read, path::PathBuf, time::Duration};

use crowsi_windows_custody_provider::{CustodyClient, ReasonCode, RuntimeConfig};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const EXECUTABLE_ENV: &str = "CROWSI_WINDOWS_CUSTODY_PROVIDER_EXECUTABLE";

#[test]
#[ignore = "requires an explicit Windows PE and the interactive DPAPI user profile"]
fn live_dpapi_lifecycle_is_isolated_and_recoverable() {
    let Some(executable) = std::env::var_os(EXECUTABLE_ENV).map(PathBuf::from) else {
        return;
    };
    assert!(
        executable.is_absolute(),
        "provider executable must be absolute"
    );
    require_pe(&executable);
    let namespace = format!("crowsi.integration.{}", random_hex(16));
    let credential_id = format!("integration:{}", random_hex(16));
    let runtime = RuntimeConfig::new(namespace, executable.clone(), digest(&executable))
        .expect("live provider identity");
    let client = runtime
        .into_client(Duration::from_secs(10))
        .expect("live custody client");
    client.doctor("live-doctor").expect("DPAPI doctor");

    let mut secret = Zeroizing::new(vec![0_u8; 64]);
    getrandom::fill(&mut secret).expect("test entropy");
    let put = client
        .put("live-put", &credential_id, None, &secret)
        .expect("DPAPI put");
    let revision = put
        .response
        .metadata()
        .expect("put metadata")
        .revision()
        .to_owned();
    let mut cleanup = Cleanup::new(&client, &credential_id, &revision);

    let metadata = client
        .metadata("live-metadata", &credential_id)
        .expect("DPAPI metadata");
    assert_eq!(
        metadata.response.metadata().expect("metadata").revision(),
        revision
    );
    let get = client
        .get("live-get", &credential_id, &revision)
        .expect("DPAPI get");
    assert!(get.expose_secret(|value| value == Some(secret.as_slice())));
    client
        .delete("live-delete", &credential_id, &revision)
        .expect("DPAPI delete");
    cleanup.disarm();
    let Err(missing) = client.metadata("live-not-found", &credential_id) else {
        panic!("deleted credential must not remain");
    };
    assert_eq!(missing.reason(), ReasonCode::CredentialNotFound);
}

struct Cleanup<'a> {
    client: &'a CustodyClient,
    credential_id: &'a str,
    revision: Option<&'a str>,
}

impl<'a> Cleanup<'a> {
    fn new(client: &'a CustodyClient, credential_id: &'a str, revision: &'a str) -> Self {
        Self {
            client,
            credential_id,
            revision: Some(revision),
        }
    }

    fn disarm(&mut self) {
        self.revision = None;
    }
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        if let Some(revision) = self.revision.take() {
            let _ = self
                .client
                .delete("live-finally-delete", self.credential_id, revision);
        }
    }
}

fn digest(path: &std::path::Path) -> String {
    let mut file = File::open(path).expect("provider executable");
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = file.read(&mut buffer).expect("provider executable bytes");
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn require_pe(path: &std::path::Path) {
    assert_eq!(
        path.extension().and_then(|value| value.to_str()),
        Some("exe")
    );
    let mut magic = [0_u8; 2];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut magic))
        .expect("provider PE header");
    assert_eq!(magic, *b"MZ", "provider must be a Windows PE image");
}

fn random_hex(length: usize) -> String {
    let mut bytes = vec![0_u8; length];
    getrandom::fill(&mut bytes).expect("test identifier entropy");
    hex::encode(bytes)
}
