use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt as _;
#[cfg(unix)]
use std::os::{fd::AsRawFd as _, unix::fs::OpenOptionsExt as _};

use crate::{ReasonCode, Result};

use super::ledger_root_validation::{
    RootIdentity, create, identity, validate_ancestors, validate_directory,
};

#[derive(Debug)]
pub(super) struct LedgerRoot {
    path: PathBuf,
    directory: File,
    identity: RootIdentity,
}

impl LedgerRoot {
    pub fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(ReasonCode::StorageUnavailable.into());
        }
        if !path.exists() {
            validate_ancestors(path)?;
            create(path)?;
        }
        let canonical = fs::canonicalize(path).map_err(|_| ReasonCode::StorageUnavailable)?;
        if canonical != path {
            return Err(ReasonCode::StorageUnavailable.into());
        }
        validate_ancestors(&canonical)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        #[cfg(windows)]
        options.custom_flags(0x0220_0000).share_mode(0);
        let directory = options
            .open(&canonical)
            .map_err(|_| ReasonCode::StorageUnavailable)?;
        let metadata = directory
            .metadata()
            .map_err(|_| ReasonCode::StorageUnavailable)?;
        validate_directory(&metadata)?;
        #[cfg(unix)]
        let identity = identity(&metadata)?;
        #[cfg(windows)]
        let identity = identity(&directory)?;
        let value = Self {
            path: canonical,
            directory,
            identity,
        };
        value.verify_layout()?;
        Ok(value)
    }

    pub fn child(&self, name: &str) -> Result<PathBuf> {
        self.verify_named()?;
        if name.contains('/') || name.contains('\\') || matches!(name, "." | "..") {
            return Err(ReasonCode::StorageUnavailable.into());
        }
        Ok(self.directory_path().join(name))
    }

    pub fn sync(&self) -> Result<()> {
        self.verify_named()?;
        self.directory
            .sync_all()
            .map_err(|_| ReasonCode::StorageUnavailable)?;
        self.verify_named()
    }

    pub fn verify_named(&self) -> Result<()> {
        validate_ancestors(&self.path)?;
        let named = fs::symlink_metadata(&self.path).map_err(|_| ReasonCode::StorageUnavailable)?;
        validate_directory(&named)?;
        #[cfg(unix)]
        let matches = {
            let opened = self
                .directory
                .metadata()
                .map_err(|_| ReasonCode::StorageUnavailable)?;
            identity(&named)? == self.identity && identity(&opened)? == self.identity
        };
        #[cfg(windows)]
        let matches = identity(&self.directory)? == self.identity;
        if !matches {
            return Err(ReasonCode::IntegrityRejected.into());
        }
        Ok(())
    }

    pub fn verify_layout(&self) -> Result<()> {
        self.verify_named()?;
        self.validate_entries()
    }

    fn validate_entries(&self) -> Result<()> {
        const ALLOWED: [&str; 5] = [
            "ledger-v2.json",
            "ledger-v2.anchor",
            "ledger-v2.lock",
            ".ledger-v2.state.tmp",
            ".ledger-v2.anchor.tmp",
        ];
        for entry in
            fs::read_dir(self.directory_path()).map_err(|_| ReasonCode::StorageUnavailable)?
        {
            let entry = entry.map_err(|_| ReasonCode::StorageUnavailable)?;
            let name = entry.file_name();
            if !ALLOWED.contains(&name.to_str().ok_or(ReasonCode::StorageUnavailable)?) {
                return Err(ReasonCode::StorageUnavailable.into());
            }
        }
        self.verify_named()
    }

    #[cfg(unix)]
    fn directory_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }

    #[cfg(windows)]
    fn directory_path(&self) -> PathBuf {
        self.path.clone()
    }
}
