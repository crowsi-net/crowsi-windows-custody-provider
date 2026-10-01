use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use crate::{ReasonCode, Result};

#[derive(Clone)]
pub struct HelperIdentity {
    path: PathBuf,
    digest: String,
}

impl HelperIdentity {
    /// Pins one absolute, canonical, non-linked helper image to its exact digest.
    ///
    /// # Errors
    ///
    /// Rejects missing, relative, linked, non-file, changed, or malformed helper identities.
    pub fn new(path: impl Into<PathBuf>, digest: impl Into<String>) -> Result<Self> {
        let identity = Self {
            path: path.into(),
            digest: digest.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub(crate) fn verified_path(&self) -> Result<&Path> {
        self.validate()?;
        Ok(&self.path)
    }

    fn validate(&self) -> Result<()> {
        if !self.path.is_absolute() || !valid_digest(&self.digest) {
            return Err(ReasonCode::HelperIdentityRejected.into());
        }
        let canonical = self
            .path
            .canonicalize()
            .map_err(|_| ReasonCode::HelperIdentityRejected)?;
        if canonical != self.path || linked_component(&self.path)? {
            return Err(ReasonCode::HelperIdentityRejected.into());
        }
        let metadata = self
            .path
            .metadata()
            .map_err(|_| ReasonCode::HelperIdentityRejected)?;
        if !metadata.is_file() || file_digest(&self.path)? != self.digest {
            return Err(ReasonCode::HelperIdentityRejected.into());
        }
        Ok(())
    }
}

fn linked_component(path: &Path) -> Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = current
            .symlink_metadata()
            .map_err(|_| ReasonCode::HelperIdentityRejected)?;
        if metadata.file_type().is_symlink() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn file_digest(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|_| ReasonCode::HelperIdentityRejected)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| ReasonCode::HelperIdentityRejected)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
