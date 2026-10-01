use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf, ptr, slice};

use windows_sys::Win32::{
    System::Com::CoTaskMemFree,
    UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
};

use crate::{ReasonCode, Result};

pub(super) fn custody_root() -> Result<PathBuf> {
    let mut raw = ptr::null_mut();
    // SAFETY: SHGetKnownFolderPath initializes `raw` on success. The returned COM allocation is
    // scanned only to its terminating NUL and is released exactly once with CoTaskMemFree.
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, ptr::null_mut(), &raw mut raw) };
    if result < 0 || raw.is_null() {
        return Err(ReasonCode::StorageUnavailable.into());
    }
    // SAFETY: a successful call returns a NUL-terminated UTF-16 string.
    let path = unsafe {
        let mut length = 0;
        while *raw.add(length) != 0 {
            length += 1;
        }
        let value = OsString::from_wide(slice::from_raw_parts(raw, length));
        CoTaskMemFree(raw.cast());
        PathBuf::from(value)
    };
    Ok(path.join("Crowsi").join("Custody").join("v1"))
}
