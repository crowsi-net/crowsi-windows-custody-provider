use std::{fs, os::windows::ffi::OsStrExt, path::Path};

use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};

use crate::{ReasonCode, Result};

pub(crate) fn replace(source: &Path, destination: &Path) -> Result<()> {
    safe_source(source)?;
    safe_destination(destination)?;
    let source_wide = wide(source)?;
    let destination_wide = wide(destination)?;
    // SAFETY: both buffers are live, NUL-terminated UTF-16 paths and the flags request one
    // same-volume, write-through replacement. No pointer escapes this synchronous call.
    let result = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(ReasonCode::StorageUnavailable.into());
    }
    safe_source(destination)
}

fn safe_destination(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or(ReasonCode::StorageUnavailable)?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| ReasonCode::StorageUnavailable)?;
    if !parent_metadata.is_dir() || reparse(&parent_metadata) {
        return Err(ReasonCode::StorageUnavailable.into());
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !reparse(&metadata) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(ReasonCode::StorageUnavailable.into()),
    }
}

fn safe_source(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ReasonCode::StorageUnavailable)?;
    (metadata.is_file() && !reparse(&metadata))
        .then_some(())
        .ok_or(ReasonCode::StorageUnavailable.into())
}

fn reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn wide(path: &Path) -> Result<Vec<u16>> {
    let mut value = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if value.contains(&0) {
        return Err(ReasonCode::StorageUnavailable.into());
    }
    value.push(0);
    Ok(value)
}
