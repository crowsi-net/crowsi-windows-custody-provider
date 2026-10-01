use std::io::{Read, Write};

use zeroize::Zeroizing;

use crate::{ReasonCode, Result};

pub const MAX_CONTROL_BYTES: usize = 16 * 1024;
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

/// Reads one variable-length frame after validating its four-byte length prefix.
///
/// # Errors
///
/// Rejects empty, oversized, truncated, or unavailable input.
pub fn read_frame(reader: &mut impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut prefix = [0_u8; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(|_| ReasonCode::ContractRejected)?;
    let length =
        usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| ReasonCode::ContractRejected)?;
    if length == 0 || length > limit {
        return Err(ReasonCode::ContractRejected.into());
    }
    let mut body = vec![0_u8; length];
    reader
        .read_exact(&mut body)
        .map_err(|_| ReasonCode::ContractRejected)?;
    Ok(body)
}

pub(crate) fn read_secret_frame(reader: &mut impl Read) -> Result<Zeroizing<Vec<u8>>> {
    let mut prefix = [0_u8; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(|_| ReasonCode::ContractRejected)?;
    let length =
        usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| ReasonCode::ContractRejected)?;
    if length == 0 || length > MAX_SECRET_BYTES {
        return Err(ReasonCode::ContractRejected.into());
    }
    let mut body = Zeroizing::new(vec![0_u8; length]);
    reader
        .read_exact(&mut body)
        .map_err(|_| ReasonCode::ContractRejected)?;
    Ok(body)
}

/// Writes one bounded variable-length frame without logging its payload.
///
/// # Errors
///
/// Rejects empty, oversized, unrepresentable, or unavailable output.
pub fn write_frame(writer: &mut impl Write, body: &[u8], limit: usize) -> Result<()> {
    if body.is_empty() || body.len() > limit {
        return Err(ReasonCode::ContractRejected.into());
    }
    let length = u32::try_from(body.len()).map_err(|_| ReasonCode::ContractRejected)?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(body))
        .map_err(|_| ReasonCode::TransportUnavailable.into())
}

pub(crate) fn require_eof(reader: &mut impl Read) -> Result<()> {
    let mut trailing = [0_u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => Ok(()),
        _ => Err(ReasonCode::ContractRejected.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::read_secret_frame;

    #[test]
    fn secret_frame_is_zeroizing_and_rejects_partial_input() {
        let mut complete = Cursor::new([0, 0, 0, 3, 1, 2, 3]);
        let secret = read_secret_frame(&mut complete).expect("secret frame");
        assert_eq!(&*secret, &[1, 2, 3]);
        let mut partial = Cursor::new([0, 0, 0, 3, 1]);
        assert!(read_secret_frame(&mut partial).is_err());
    }
}
