use std::{path::Path, sync::Arc};

use crate::{ReasonCode, Result};

use super::{ledger_model::LedgerState, ledger_root::LedgerRoot, ledger_store::LedgerStore};

const STATE: &str = "ledger-v2.json";
const ANCHOR: &str = "ledger-v2.anchor";
const STATE_TEMP: &str = ".ledger-v2.state.tmp";
const ANCHOR_TEMP: &str = ".ledger-v2.anchor.tmp";

pub(super) fn open_root(path: &Path) -> Result<Arc<LedgerRoot>> {
    let root = Arc::new(LedgerRoot::open(path)?);
    with_locked(&root, |store| store.validate())?;
    Ok(root)
}

pub(super) fn with_locked<T>(
    root: &Arc<LedgerRoot>,
    action: impl FnOnce(&mut LedgerStore) -> Result<T>,
) -> Result<T> {
    root.verify_layout()?;
    let lock = super::ledger_fs::open_lock(root)?;
    lock.lock().map_err(|_| ReasonCode::StorageUnavailable)?;
    super::ledger_fs::validate_lock(root, &lock)?;
    let result = recover_temps(root)
        .and_then(|()| load(root))
        .and_then(|mut store| action(&mut store));
    let final_validation =
        super::ledger_fs::validate_lock(root, &lock).and_then(|()| root.verify_layout());
    lock.unlock().map_err(|_| ReasonCode::StorageUnavailable)?;
    match result {
        Ok(value) => {
            final_validation?;
            Ok(value)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn commit_state(
    root: &LedgerRoot,
    state: &mut LedgerState,
    previous_digest: &str,
) -> Result<String> {
    state.revision = state
        .revision
        .checked_add(1)
        .ok_or(ReasonCode::StorageUnavailable)?;
    state.previous_state_sha256 = previous_digest.into();
    let bytes = serde_json::to_vec(state).map_err(|_| ReasonCode::StorageUnavailable)?;
    if bytes.len() > super::ledger_fs::MAX_LEDGER_BYTES {
        return Err(ReasonCode::StorageUnavailable.into());
    }
    let digest = super::ledger_codec::sha256(&bytes);
    super::ledger_fs::atomic_write(root, STATE, STATE_TEMP, &bytes)?;
    super::ledger_failpoint::trip(super::OperationLedgerFailpoint::AfterStateReplaceBeforeAnchor)?;
    super::ledger_fs::atomic_write(
        root,
        ANCHOR,
        ANCHOR_TEMP,
        &super::ledger_codec::anchor_bytes(state.revision, &digest),
    )?;
    Ok(digest)
}

fn load(root: &Arc<LedgerRoot>) -> Result<LedgerStore> {
    let state = super::ledger_fs::read_optional(root, STATE)?;
    let anchor = super::ledger_fs::read_optional(root, ANCHOR)?;
    match (state, anchor) {
        (None, None) => initialize(root),
        (Some(bytes), None) => forward_initial(root, &bytes),
        (None, Some(_)) => Err(ReasonCode::IntegrityRejected.into()),
        (Some(bytes), Some(anchor)) => load_existing(root, &bytes, &anchor),
    }
}

fn initialize(root: &Arc<LedgerRoot>) -> Result<LedgerStore> {
    let mut state = LedgerState::default();
    let digest = commit_state(root, &mut state, &"0".repeat(64))?;
    Ok(LedgerStore {
        root: Arc::clone(root),
        state,
        state_sha256: digest,
    })
}

fn forward_initial(root: &Arc<LedgerRoot>, bytes: &[u8]) -> Result<LedgerStore> {
    let state = super::ledger_codec::decode_state(bytes)?;
    let digest = super::ledger_codec::sha256(bytes);
    if state.revision != 1 || state.previous_state_sha256 != "0".repeat(64) {
        return Err(ReasonCode::IntegrityRejected.into());
    }
    super::ledger_fs::atomic_write(
        root,
        ANCHOR,
        ANCHOR_TEMP,
        &super::ledger_codec::anchor_bytes(state.revision, &digest),
    )?;
    let store = LedgerStore {
        root: Arc::clone(root),
        state,
        state_sha256: digest,
    };
    store.validate()?;
    Ok(store)
}

fn load_existing(root: &Arc<LedgerRoot>, bytes: &[u8], anchor: &[u8]) -> Result<LedgerStore> {
    let state = super::ledger_codec::decode_state(bytes)?;
    let digest = super::ledger_codec::sha256(bytes);
    let (revision, anchored) = super::ledger_codec::decode_anchor(anchor)?;
    if state.revision == revision && digest == anchored {
        let store = LedgerStore {
            root: Arc::clone(root),
            state,
            state_sha256: digest,
        };
        store.validate()?;
        return Ok(store);
    }
    if state.revision == revision.saturating_add(1) && state.previous_state_sha256 == anchored {
        super::ledger_fs::atomic_write(
            root,
            ANCHOR,
            ANCHOR_TEMP,
            &super::ledger_codec::anchor_bytes(state.revision, &digest),
        )?;
        let store = LedgerStore {
            root: Arc::clone(root),
            state,
            state_sha256: digest,
        };
        store.validate()?;
        return Ok(store);
    }
    Err(ReasonCode::IntegrityRejected.into())
}

fn recover_temps(root: &LedgerRoot) -> Result<()> {
    super::ledger_fs::remove_temp(root, STATE_TEMP)?;
    super::ledger_fs::remove_temp(root, ANCHOR_TEMP)
}
