use std::{fs, fs::File, path::Path};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt as _;

use crate::{ReasonCode, Result};

pub(super) fn validate(path: &Path, file: &File, size: Option<u64>) -> Result<()> {
    let opened = file
        .metadata()
        .map_err(|_| ReasonCode::StorageUnavailable)?;
    let named = fs::symlink_metadata(path).map_err(|_| ReasonCode::StorageUnavailable)?;
    if !opened.is_file()
        || linked(&opened)
        || !same_file(file, &opened, &named)
        || size.is_some_and(|value| opened.len() != value)
    {
        return Err(ReasonCode::StorageUnavailable.into());
    }
    validate_owner(file, &opened)
}

#[cfg(unix)]
fn validate_owner(_: &File, value: &fs::Metadata) -> Result<()> {
    if value.uid() != current_uid()?
        || value.permissions().mode() & 0o777 != 0o600
        || value.nlink() != 1
    {
        return Err(ReasonCode::StorageUnavailable.into());
    }
    Ok(())
}

#[cfg(windows)]
fn validate_owner(file: &File, _: &fs::Metadata) -> Result<()> {
    if crate::windows::link_count(file)? != 1 {
        return Err(ReasonCode::StorageUnavailable.into());
    }
    Ok(())
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
fn same_file(_: &File, left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
fn same_file(_: &File, left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
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
