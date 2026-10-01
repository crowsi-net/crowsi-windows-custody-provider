use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

use crate::{
    OperationOnlyCredentialClass, ReasonCode, Result,
    protocol::{identifier, revision},
};

use super::{
    known_folder::custody_root,
    storage::{ensure_directory_chain, reparse},
};

const SCHEMA: &str = "crowsi://platform-custody/cng-key-registry/v1";
const MAX_BYTES: u64 = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    schema: String,
    credentials: Vec<CngEntry>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CngEntry {
    pub credential_id: String,
    pub revision: String,
    pub credential_class: OperationOnlyCredentialClass,
    pub provider_name: String,
    pub key_name: String,
}

pub(super) fn load() -> Result<Vec<CngEntry>> {
    let body = read_bounded(&registry_path()?)?;
    let mut decoder = serde_json::Deserializer::from_slice(&body);
    let value = Registry::deserialize(&mut decoder).map_err(|_| ReasonCode::IntegrityRejected)?;
    decoder.end().map_err(|_| ReasonCode::IntegrityRejected)?;
    if value.schema != SCHEMA || value.credentials.is_empty() || value.credentials.len() > 256 {
        return Err(ReasonCode::IntegrityRejected.into());
    }
    for (index, entry) in value.credentials.iter().enumerate() {
        let valid = identifier(&entry.credential_id, 128)
            && revision(&entry.revision)
            && windows_name(&entry.provider_name, 128)
            && windows_name(&entry.key_name, 240)
            && !value.credentials[..index]
                .iter()
                .any(|prior| prior.credential_id == entry.credential_id);
        if !valid {
            return Err(ReasonCode::IntegrityRejected.into());
        }
    }
    Ok(value.credentials)
}

pub(super) fn registered_class(id: &str) -> Result<Option<OperationOnlyCredentialClass>> {
    let path = registry_path()?;
    match fs::symlink_metadata(&path) {
        Ok(_) => Ok(load()?
            .into_iter()
            .find(|item| item.credential_id == id)
            .map(|item| item.credential_class)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(ReasonCode::StorageUnavailable.into()),
    }
}

pub(super) fn operation_root() -> Result<PathBuf> {
    let root = custody_root()?.join("operation-only-v2");
    ensure_directory_chain(&root)?;
    Ok(root)
}

pub(super) fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ReasonCode::StorageUnavailable)?;
    if !metadata.is_file() || reparse(&metadata) || metadata.len() > MAX_BYTES {
        return Err(ReasonCode::IntegrityRejected.into());
    }
    let mut body = Vec::new();
    OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .and_then(|file| file.take(MAX_BYTES + 1).read_to_end(&mut body))
        .map_err(|_| ReasonCode::StorageUnavailable)?;
    if body.is_empty() || body.len() as u64 > MAX_BYTES {
        return Err(ReasonCode::IntegrityRejected.into());
    }
    Ok(body)
}

fn registry_path() -> Result<PathBuf> {
    Ok(operation_root()?.join("cng-key-registry-v1.json"))
}

fn windows_name(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'.' | b'_' | b':' | b'-')
        })
}
