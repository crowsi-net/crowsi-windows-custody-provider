use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt as _;

use crate::{ReasonCode, Result};

use super::ledger_root::LedgerRoot;

pub(super) const MAX_LEDGER_BYTES: usize = 4 * 1024 * 1024;

pub(super) fn open_lock(root: &LedgerRoot) -> Result<File> {
    let path = root.child("ledger-v2.lock")?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    configure(&mut options, 0o600);
    let file = options
        .open(&path)
        .map_err(|_| ReasonCode::StorageUnavailable)?;
    super::ledger_file_validation::validate(&path, &file, Some(0))?;
    root.verify_named()?;
    Ok(file)
}

pub(super) fn validate_lock(root: &LedgerRoot, file: &File) -> Result<()> {
    let path = root.child("ledger-v2.lock")?;
    super::ledger_file_validation::validate(&path, file, Some(0))?;
    root.verify_named()
}

pub(super) fn read_optional(root: &LedgerRoot, name: &str) -> Result<Option<Vec<u8>>> {
    let path = root.child(name)?;
    let mut options = OpenOptions::new();
    options.read(true);
    configure(&mut options, 0o600);
    let mut file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            root.verify_named()?;
            return Ok(None);
        }
        Err(_) => return Err(ReasonCode::StorageUnavailable.into()),
    };
    super::ledger_file_validation::validate(&path, &file, None)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take((MAX_LEDGER_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ReasonCode::StorageUnavailable)?;
    if bytes.len() > MAX_LEDGER_BYTES {
        return Err(ReasonCode::StorageUnavailable.into());
    }
    super::ledger_file_validation::validate(&path, &file, Some(bytes.len() as u64))?;
    root.verify_named()?;
    Ok(Some(bytes))
}

pub(super) fn atomic_write(
    root: &LedgerRoot,
    destination: &str,
    temporary: &str,
    bytes: &[u8],
) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_LEDGER_BYTES {
        return Err(ReasonCode::StorageUnavailable.into());
    }
    let temp = root.child(temporary)?;
    let target = root.child(destination)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    configure(&mut options, 0o600);
    let mut file = options
        .open(&temp)
        .map_err(|_| ReasonCode::StorageUnavailable)?;
    super::ledger_file_validation::validate(&temp, &file, Some(0))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| ReasonCode::StorageUnavailable)?;
    super::ledger_file_validation::validate(&temp, &file, Some(bytes.len() as u64))?;
    drop(file);
    replace(&temp, &target)?;
    root.sync()
}

pub(super) fn remove_temp(root: &LedgerRoot, name: &str) -> Result<()> {
    if read_optional(root, name)?.is_none() {
        return Ok(());
    }
    fs::remove_file(root.child(name)?).map_err(|_| ReasonCode::StorageUnavailable)?;
    root.sync()
}

fn configure(options: &mut OpenOptions, mode: u32) {
    #[cfg(unix)]
    options
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    #[cfg(windows)]
    {
        let _ = mode;
        options.custom_flags(0x0020_0000).share_mode(0);
    }
}

#[cfg(unix)]
fn replace(source: &std::path::Path, destination: &std::path::Path) -> Result<()> {
    fs::rename(source, destination).map_err(|_| ReasonCode::StorageUnavailable.into())
}

#[cfg(windows)]
fn replace(source: &std::path::Path, destination: &std::path::Path) -> Result<()> {
    crate::windows::replace::replace(source, destination)
}
