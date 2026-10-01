use std::{
    fs::{self, File, OpenOptions},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
};

use sha2::Digest;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{Metadata, ReasonCode, Result, record::SecretRecord};

use super::{dpapi, known_folder::custody_root, storage_file};

pub(super) struct Store {
    namespace: String,
    root: PathBuf,
    _lock: File,
}

impl Store {
    pub(super) fn open(namespace: &str) -> Result<Self> {
        let root = custody_root()?.join(hex::encode(sha2::Sha256::digest(namespace.as_bytes())));
        ensure_directory_chain(&root)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(root.join("provider.lock"))
            .map_err(|_| ReasonCode::StorageUnavailable)?;
        let lock_metadata = lock
            .metadata()
            .map_err(|_| ReasonCode::StorageUnavailable)?;
        if !lock_metadata.is_file() || reparse(&lock_metadata) {
            return Err(ReasonCode::StorageUnavailable.into());
        }
        Ok(Self {
            namespace: namespace.into(),
            root,
            _lock: lock,
        })
    }

    pub(super) fn doctor(&self) -> Result<()> {
        let mut clear = Zeroizing::new(b"crowsi-dpapi-probe-v1".to_vec());
        let entropy = crate::binding::entropy(&self.namespace, "__doctor__");
        let cipher = dpapi::protect(&clear, &entropy)?;
        let mut recovered = Zeroizing::new(dpapi::unprotect(&cipher, &entropy)?);
        let valid = *clear == *recovered;
        clear.zeroize();
        recovered.zeroize();
        valid
            .then_some(())
            .ok_or(ReasonCode::IntegrityRejected.into())
    }

    pub(super) fn put(
        &self,
        id: &str,
        expected: Option<&str>,
        secret: Zeroizing<Vec<u8>>,
    ) -> Result<Metadata> {
        let current = storage_file::load_optional(&self.root, &self.namespace, id)?;
        if current.as_ref().map(|item| item.revision.as_str()) != expected {
            return Err(ReasonCode::CredentialChanged.into());
        }
        let record = SecretRecord::new(&self.namespace, id.to_owned(), secret)?;
        storage_file::persist(&self.root, &self.namespace, &record)?;
        let confirmed = storage_file::load(&self.root, &self.namespace, id)?;
        if confirmed.revision != record.revision {
            return Err(ReasonCode::CredentialChanged.into());
        }
        Ok(Metadata::new(id.to_owned(), record.revision))
    }

    pub(super) fn metadata(&self, id: &str) -> Result<Metadata> {
        let record = storage_file::load(&self.root, &self.namespace, id)?;
        Ok(Metadata::new(id.to_owned(), record.revision))
    }

    pub(super) fn get(&self, id: &str, expected: &str) -> Result<SecretRecord> {
        let record = storage_file::load(&self.root, &self.namespace, id)?;
        (record.revision == expected)
            .then_some(record)
            .ok_or(ReasonCode::CredentialChanged.into())
    }

    pub(super) fn delete(&self, id: &str, expected: &str) -> Result<Metadata> {
        let record = self.get(id, expected)?;
        let path = storage_file::credential_path(&self.root, id);
        fs::remove_file(&path).map_err(|_| ReasonCode::StorageUnavailable)?;
        if path.exists() {
            return Err(ReasonCode::StorageUnavailable.into());
        }
        Ok(Metadata::new(id.to_owned(), record.revision))
    }
}

pub(super) fn reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

pub(super) fn ensure_directory_chain(path: &std::path::Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_directory_chain(parent)?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !reparse(&metadata) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| ReasonCode::StorageUnavailable)?;
            let metadata =
                fs::symlink_metadata(path).map_err(|_| ReasonCode::StorageUnavailable)?;
            (metadata.is_dir() && !reparse(&metadata))
                .then_some(())
                .ok_or(ReasonCode::StorageUnavailable.into())
        }
        Ok(_) | Err(_) => Err(ReasonCode::StorageUnavailable.into()),
    }
}
