use std::{fs, fs::File, path::Path};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt as _;

use crate::{ReasonCode, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RootIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    mode: u32,
    #[cfg(windows)]
    volume: u32,
    #[cfg(windows)]
    index: u64,
}

#[cfg(unix)]
pub(super) fn create(path: &Path) -> Result<()> {
    let mut value = fs::DirBuilder::new();
    value
        .mode(0o700)
        .create(path)
        .map_err(|_| ReasonCode::StorageUnavailable.into())
}

#[cfg(windows)]
pub(super) fn create(path: &Path) -> Result<()> {
    fs::create_dir(path).map_err(|_| ReasonCode::StorageUnavailable.into())
}

pub(super) fn validate_directory(value: &fs::Metadata) -> Result<()> {
    if !value.is_dir() || linked(value) {
        return Err(ReasonCode::StorageUnavailable.into());
    }
    #[cfg(unix)]
    if value.uid() != current_uid()? || value.permissions().mode() & 0o777 != 0o700 {
        return Err(ReasonCode::StorageUnavailable.into());
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn identity(value: &fs::Metadata) -> Result<RootIdentity> {
    Ok(RootIdentity {
        dev: value.dev(),
        ino: value.ino(),
        uid: value.uid(),
        mode: value.mode(),
    })
}

#[cfg(windows)]
pub(super) fn identity(value: &File) -> Result<RootIdentity> {
    let value = crate::windows::file_identity(value)?;
    Ok(RootIdentity {
        volume: value.volume,
        index: value.index,
    })
}

#[cfg(unix)]
fn linked(value: &fs::Metadata) -> bool {
    value.file_type().is_symlink()
}

#[cfg(windows)]
fn linked(value: &fs::Metadata) -> bool {
    value.file_type().is_symlink() || value.file_attributes() & 0x400 != 0
}

#[cfg(unix)]
pub(super) fn validate_ancestors(path: &Path) -> Result<()> {
    let uid = current_uid()?;
    for ancestor in path.parent().into_iter().flat_map(Path::ancestors) {
        let value = fs::symlink_metadata(ancestor).map_err(|_| ReasonCode::StorageUnavailable)?;
        let mode = value.permissions().mode();
        if !value.is_dir()
            || value.file_type().is_symlink()
            || value.uid() != uid && value.uid() != 0
            || mode & 0o022 != 0 && mode & 0o1000 == 0
        {
            return Err(ReasonCode::StorageUnavailable.into());
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn validate_ancestors(_: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn current_uid() -> Result<u32> {
    let value =
        fs::read_to_string("/proc/self/status").map_err(|_| ReasonCode::StorageUnavailable)?;
    value
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .ok_or(ReasonCode::StorageUnavailable)?
        .parse()
        .map_err(|_| ReasonCode::StorageUnavailable.into())
}
