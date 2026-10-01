use std::{fs::File, mem::MaybeUninit, os::windows::io::AsRawHandle as _};

use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
};

use crate::{ReasonCode, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    pub(crate) volume: u32,
    pub(crate) index: u64,
}

pub(crate) fn identity(file: &File) -> Result<FileIdentity> {
    let value = information(file)?;
    Ok(FileIdentity {
        volume: value.dwVolumeSerialNumber,
        index: (u64::from(value.nFileIndexHigh) << 32) | u64::from(value.nFileIndexLow),
    })
}

pub(crate) fn link_count(file: &File) -> Result<u32> {
    Ok(information(file)?.nNumberOfLinks)
}

fn information(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut value = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    // SAFETY: the raw handle is borrowed from a live File, the output points to a valid,
    // writable structure, and the synchronous call cannot retain either pointer.
    let status = unsafe { GetFileInformationByHandle(file.as_raw_handle(), value.as_mut_ptr()) };
    if status == 0 {
        return Err(ReasonCode::StorageUnavailable.into());
    }
    // SAFETY: GetFileInformationByHandle succeeded and initialized the whole structure.
    Ok(unsafe { value.assume_init() })
}
