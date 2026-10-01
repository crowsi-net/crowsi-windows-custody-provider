use std::{ptr, slice};

use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    },
};
use zeroize::Zeroize;

use crate::{ReasonCode, Result};

pub(super) fn protect(clear: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
    transform(clear, entropy, true)
}

pub(super) fn unprotect(cipher: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
    transform(cipher, entropy, false)
}

fn transform(input: &[u8], entropy: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    let input_len = u32::try_from(input.len()).map_err(|_| ReasonCode::ContractRejected)?;
    let entropy_len = u32::try_from(entropy.len()).map_err(|_| ReasonCode::ContractRejected)?;
    let input_blob = CRYPT_INTEGER_BLOB {
        cbData: input_len,
        pbData: input.as_ptr().cast_mut(),
    };
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy_len,
        pbData: entropy.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let mut description = ptr::null_mut();
    // SAFETY: every blob points to a live bounded slice for the duration of this synchronous call;
    // output pointers are owned by LocalAlloc and released below on every successful call.
    let success = unsafe {
        if encrypt {
            CryptProtectData(
                &raw const input_blob,
                ptr::null(),
                &raw const entropy_blob,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut output,
            )
        } else {
            CryptUnprotectData(
                &raw const input_blob,
                &raw mut description,
                &raw const entropy_blob,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut output,
            )
        }
    };
    if success == 0 || output.pbData.is_null() || output.cbData == 0 {
        // SAFETY: failed DPAPI calls may still return LocalAlloc-owned buffers. Each non-null
        // allocation is released once; no returned content is interpreted on this path.
        unsafe {
            if !output.pbData.is_null() {
                LocalFree(output.pbData.cast());
            }
            if !description.is_null() {
                LocalFree(description.cast());
            }
        }
        return Err(ReasonCode::IntegrityRejected.into());
    }
    let Ok(output_len) = usize::try_from(output.cbData) else {
        // SAFETY: conversion cannot fail on supported Windows targets; release defensively.
        unsafe {
            LocalFree(output.pbData.cast());
            if !description.is_null() {
                LocalFree(description.cast());
            }
        }
        return Err(ReasonCode::IntegrityRejected.into());
    };
    if output_len > crate::protected::MAX_PROTECTED_BYTES {
        // SAFETY: the successful call returned one `output_len` byte LocalAlloc allocation.
        unsafe {
            slice::from_raw_parts_mut(output.pbData, output_len).zeroize();
            LocalFree(output.pbData.cast());
            if !description.is_null() {
                LocalFree(description.cast());
            }
        }
        return Err(ReasonCode::IntegrityRejected.into());
    }
    // SAFETY: DPAPI returned `cbData` initialized bytes at `pbData` and retains ownership until
    // LocalFree. We copy them, erase decrypted allocator memory, and then release it exactly once.
    let result = unsafe {
        let allocated = slice::from_raw_parts_mut(output.pbData, output_len);
        let copied = allocated.to_vec();
        if !encrypt {
            allocated.zeroize();
        }
        LocalFree(output.pbData.cast());
        if !description.is_null() {
            LocalFree(description.cast());
        }
        copied
    };
    Ok(result)
}
