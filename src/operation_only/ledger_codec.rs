use serde::Deserialize as _;
use sha2::{Digest as _, Sha256};

use crate::{ReasonCode, Result};

use super::ledger_model::LedgerState;

pub(super) fn decode_state(bytes: &[u8]) -> Result<LedgerState> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let state =
        LedgerState::deserialize(&mut decoder).map_err(|_| ReasonCode::IntegrityRejected)?;
    decoder.end().map_err(|_| ReasonCode::IntegrityRejected)?;
    Ok(state)
}

pub(super) fn anchor_bytes(revision: u64, digest: &str) -> Vec<u8> {
    format!("CROWSI-OPERATION-LEDGER-ANCHOR-V2\n{revision}\n{digest}\n").into_bytes()
}

pub(super) fn decode_anchor(bytes: &[u8]) -> Result<(u64, String)> {
    let text = std::str::from_utf8(bytes).map_err(|_| ReasonCode::IntegrityRejected)?;
    let fields = text.split('\n').collect::<Vec<_>>();
    if fields.len() != 4
        || fields[0] != "CROWSI-OPERATION-LEDGER-ANCHOR-V2"
        || !fields[3].is_empty()
        || fields[2].len() != 64
        || !fields[2]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ReasonCode::IntegrityRejected.into());
    }
    let revision = fields[1]
        .parse()
        .map_err(|_| ReasonCode::IntegrityRejected)?;
    Ok((revision, fields[2].into()))
}

pub(super) fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
