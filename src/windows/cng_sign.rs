use std::{ffi::OsStr, mem::size_of, os::windows::ffi::OsStrExt, ptr};

use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_PKCS1_PADDING_INFO, BCRYPT_SHA256_ALGORITHM, NCRYPT_EXPORT_POLICY_PROPERTY,
    NCRYPT_KEY_HANDLE, NCRYPT_PAD_PKCS1_FLAG, NCRYPT_PROV_HANDLE, NCryptFreeObject,
    NCryptGetProperty, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSignHash,
};

use crate::{ReasonCode, Result, SigningAlgorithm};

use super::cng_registry::CngEntry;

pub(super) fn sign(entry: &CngEntry, algorithm: SigningAlgorithm, digest: &str) -> Result<String> {
    let digest = decode_digest(digest)?;
    let padding = match algorithm {
        SigningAlgorithm::RsaPkcs1Sha256 => Some(BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
        }),
        SigningAlgorithm::Ed25519 => None,
    };
    sign_cng(entry, &digest, padding.as_ref())
}

pub(super) fn sign_rsa(entry: &CngEntry, digest: &str) -> Result<String> {
    sign(entry, SigningAlgorithm::RsaPkcs1Sha256, digest)
}

fn sign_cng(
    entry: &CngEntry,
    digest: &[u8],
    padding: Option<&BCRYPT_PKCS1_PADDING_INFO>,
) -> Result<String> {
    let provider_name = wide(&entry.provider_name);
    let key_name = wide(&entry.key_name);
    let mut provider: NCRYPT_PROV_HANDLE = 0;
    let mut key: NCRYPT_KEY_HANDLE = 0;
    // SAFETY: pointers reference live NUL-terminated UTF-16 buffers and initialized handles.
    let opened = unsafe {
        NCryptOpenStorageProvider(&raw mut provider, provider_name.as_ptr(), 0) >= 0
            && NCryptOpenKey(provider, &raw mut key, key_name.as_ptr(), 0, 0) >= 0
    };
    if !opened || !nonexportable(key) {
        free(key, provider);
        return Err(ReasonCode::BackendUnavailable.into());
    }
    let padding_ptr = padding.map_or(ptr::null(), |value| ptr::from_ref(value).cast());
    let flags = padding.map_or(0, |_| NCRYPT_PAD_PKCS1_FLAG);
    let mut size = 0;
    // SAFETY: the valid key is read only and this call only measures the result.
    let measured = unsafe {
        NCryptSignHash(
            key,
            padding_ptr,
            digest.as_ptr(),
            u32::try_from(digest.len()).unwrap_or(0),
            ptr::null_mut(),
            0,
            &raw mut size,
            flags,
        )
    };
    if measured < 0 || size == 0 || size > 8192 {
        free(key, provider);
        return Err(ReasonCode::BackendUnavailable.into());
    }
    let mut signature = vec![0; size as usize];
    // SAFETY: the buffer has the measured capacity for the same key and arguments.
    let signed = unsafe {
        NCryptSignHash(
            key,
            padding_ptr,
            digest.as_ptr(),
            u32::try_from(digest.len()).unwrap_or(0),
            signature.as_mut_ptr(),
            size,
            &raw mut size,
            flags,
        )
    };
    free(key, provider);
    if signed < 0 || size as usize > signature.len() {
        return Err(ReasonCode::BackendUnavailable.into());
    }
    signature.truncate(size as usize);
    Ok(hex::encode(signature))
}

fn decode_digest(value: &str) -> Result<Vec<u8>> {
    value
        .strip_prefix("sha256:")
        .and_then(|hex| hex::decode(hex).ok())
        .filter(|bytes| bytes.len() == 32)
        .ok_or(ReasonCode::OperationOnlyInputRejected.into())
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

fn nonexportable(key: NCRYPT_KEY_HANDLE) -> bool {
    let mut export_policy = u32::MAX;
    let mut size = 0;
    // SAFETY: the output is one initialized u32 and CNG reports the exact bytes written.
    let status = unsafe {
        NCryptGetProperty(
            key,
            NCRYPT_EXPORT_POLICY_PROPERTY,
            ptr::from_mut(&mut export_policy).cast(),
            u32::try_from(size_of::<u32>()).unwrap_or(0),
            &raw mut size,
            0,
        )
    };
    status >= 0 && size as usize == size_of::<u32>() && export_policy == 0
}

fn free(key: NCRYPT_KEY_HANDLE, provider: NCRYPT_PROV_HANDLE) {
    // SAFETY: each nonzero handle returned above is released once after use.
    unsafe {
        if key != 0 {
            let _ = NCryptFreeObject(key);
        }
        if provider != 0 {
            let _ = NCryptFreeObject(provider);
        }
    }
}
