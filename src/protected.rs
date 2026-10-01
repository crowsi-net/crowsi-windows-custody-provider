use sha2::{Digest, Sha256};

use crate::{ReasonCode, Result};

const MAGIC: &[u8; 4] = b"CWP1";
pub(crate) const MAX_PROTECTED_BYTES: usize = 128 * 1024;

pub(crate) fn encode(cipher: &[u8]) -> Result<Vec<u8>> {
    if cipher.is_empty() || cipher.len() > MAX_PROTECTED_BYTES - 40 {
        return Err(ReasonCode::StorageUnavailable.into());
    }
    let length = u32::try_from(cipher.len()).map_err(|_| ReasonCode::StorageUnavailable)?;
    let mut body = Vec::with_capacity(8 + cipher.len() + 32);
    body.extend_from_slice(MAGIC);
    body.extend_from_slice(&length.to_be_bytes());
    body.extend_from_slice(cipher);
    body.extend_from_slice(&Sha256::digest(cipher));
    Ok(body)
}

pub(crate) fn decode(body: &[u8]) -> Result<&[u8]> {
    if body.len() < 40 || body.len() > MAX_PROTECTED_BYTES || body.get(..4) != Some(MAGIC) {
        return Err(ReasonCode::IntegrityRejected.into());
    }
    let length = u32::from_be_bytes(
        body[4..8]
            .try_into()
            .map_err(|_| ReasonCode::IntegrityRejected)?,
    ) as usize;
    let end = 8_usize
        .checked_add(length)
        .ok_or(ReasonCode::IntegrityRejected)?;
    let cipher = body.get(8..end).ok_or(ReasonCode::IntegrityRejected)?;
    let digest = Sha256::digest(cipher);
    if end + 32 != body.len() || digest[..] != body[end..] {
        return Err(ReasonCode::IntegrityRejected.into());
    }
    Ok(cipher)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};
    use crate::ReasonCode;

    #[test]
    fn protected_blob_detects_ciphertext_and_length_tampering() {
        let mut body = encode(b"dpapi-ciphertext").expect("valid protected blob");
        body[10] ^= 1;
        assert_eq!(
            decode(&body).expect_err("tampering must fail").reason(),
            ReasonCode::IntegrityRejected
        );
        let mut body = encode(b"dpapi-ciphertext").expect("valid protected blob");
        body[7] ^= 1;
        assert_eq!(
            decode(&body)
                .expect_err("length tampering must fail")
                .reason(),
            ReasonCode::IntegrityRejected
        );
    }
}
