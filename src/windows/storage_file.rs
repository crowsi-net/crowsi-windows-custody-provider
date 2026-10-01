use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use getrandom::fill;
use sha2::{Digest, Sha256};
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
use zeroize::Zeroizing;

use crate::{ReasonCode, Result, protected, record::SecretRecord};

use super::{dpapi, replace::replace, storage::reparse};

const MAX_PROTECTED_BYTES_U64: u64 = 128 * 1024;

pub(super) fn load_optional(
    root: &Path,
    namespace: &str,
    id: &str,
) -> Result<Option<SecretRecord>> {
    match fs::symlink_metadata(credential_path(root, id)) {
        Ok(_) => load(root, namespace, id).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(ReasonCode::StorageUnavailable.into()),
    }
}

pub(super) fn load(root: &Path, namespace: &str, id: &str) -> Result<SecretRecord> {
    let path = credential_path(root, id);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ReasonCode::CredentialNotFound
        } else {
            ReasonCode::StorageUnavailable
        }
    })?;
    if !metadata.is_file() || reparse(&metadata) || metadata.len() > MAX_PROTECTED_BYTES_U64 {
        return Err(ReasonCode::IntegrityRejected.into());
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| ReasonCode::StorageUnavailable)?;
    let mut body = Vec::with_capacity(capacity);
    OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .and_then(|file| {
            let opened = file.metadata()?;
            if !opened.is_file() || reparse(&opened) || opened.len() > MAX_PROTECTED_BYTES_U64 {
                return Err(std::io::Error::other("record is not a regular file"));
            }
            file.take(MAX_PROTECTED_BYTES_U64 + 1)
                .read_to_end(&mut body)
        })
        .map_err(|_| ReasonCode::StorageUnavailable)?;
    if body.len() > protected::MAX_PROTECTED_BYTES {
        return Err(ReasonCode::IntegrityRejected.into());
    }
    let cipher = protected::decode(&body)?;
    let clear = Zeroizing::new(dpapi::unprotect(
        cipher,
        &crate::binding::entropy(namespace, id),
    )?);
    let record = SecretRecord::decode(&clear, namespace)?;
    (record.credential_id == id)
        .then_some(record)
        .ok_or(ReasonCode::IntegrityRejected.into())
}

pub(super) fn persist(root: &Path, namespace: &str, record: &SecretRecord) -> Result<()> {
    let clear = record.encode()?;
    let cipher = dpapi::protect(
        &clear,
        &crate::binding::entropy(namespace, &record.credential_id),
    )?;
    let body = protected::encode(&cipher)?;
    let temporary = root.join(format!(".write-{}", random_name()?));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&temporary)
        .map_err(|_| ReasonCode::StorageUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| ReasonCode::StorageUnavailable)?;
    if !metadata.is_file() || reparse(&metadata) {
        return Err(ReasonCode::StorageUnavailable.into());
    }
    let write = file
        .write_all(&body)
        .and_then(|()| file.sync_all())
        .map_err(|_| ReasonCode::StorageUnavailable);
    drop(file);
    if let Err(error) = write {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    let metadata = fs::symlink_metadata(&temporary).map_err(|_| ReasonCode::StorageUnavailable)?;
    if !metadata.is_file() || reparse(&metadata) {
        let _ = fs::remove_file(&temporary);
        return Err(ReasonCode::StorageUnavailable.into());
    }
    let result = replace(&temporary, &credential_path(root, &record.credential_id));
    let _ = fs::remove_file(temporary);
    result
}

pub(super) fn credential_path(root: &Path, id: &str) -> PathBuf {
    root.join(format!(
        "{}.dpapi",
        hex::encode(Sha256::digest(id.as_bytes()))
    ))
}

fn random_name() -> Result<String> {
    let mut bytes = [0_u8; 16];
    fill(&mut bytes).map_err(|_| ReasonCode::BackendUnavailable)?;
    Ok(hex::encode(bytes))
}
