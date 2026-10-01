use base64::Engine as _;

use crate::{ReasonCode, Result};

use super::{
    OperationLedgerBinding,
    ledger_model::{
        MAX_CACHED_RESPONSE_BYTES, MAX_NEW_PREPARED_RECORDS, OperationRecord, OperationRecordState,
        RESPONSE_RETENTION_SECONDS,
    },
    ledger_store::LedgerStore,
};

pub(super) fn prepare(
    store: &mut LedgerStore,
    binding: &OperationLedgerBinding,
    now: u64,
    accept: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    if binding.authorization_expires_at_epoch_s <= now {
        return Err(ReasonCode::OperationOnlyAuthorizationExpired.into());
    }
    let retain_until = binding
        .authorization_expires_at_epoch_s
        .checked_add(RESPONSE_RETENTION_SECONDS)
        .ok_or(ReasonCode::OperationOnlyAuthorizationExpired)?;
    if store.state().records.len() >= MAX_NEW_PREPARED_RECORDS
        || projected_response_bytes(store) > MAX_CACHED_RESPONSE_BYTES
    {
        return Err(ReasonCode::StorageUnavailable.into());
    }
    accept()?;
    store.state_mut().records.insert(
        binding.full_request_digest_sha256.clone(),
        OperationRecord {
            binding: binding.clone(),
            prepared_at_epoch_s: now,
            prepared_retain_until_epoch_s: retain_until,
            response_reservation_bytes: crate::MAX_CONTROL_BYTES,
            state: OperationRecordState::Prepared,
        },
    );
    store.state_mut().nonce_index.insert(
        binding.nonce_digest_sha256.clone(),
        binding.full_request_digest_sha256.clone(),
    );
    store.state_mut().request_id_index.insert(
        binding.request_id_digest_sha256.clone(),
        binding.full_request_digest_sha256.clone(),
    );
    store.commit()
}

pub(super) fn complete(
    store: &mut LedgerStore,
    binding: &OperationLedgerBinding,
    now: u64,
    bytes: &[u8],
) -> Result<()> {
    if bytes.is_empty() || bytes.len() > crate::MAX_CONTROL_BYTES {
        return Err(ReasonCode::OperationOnlyResultUnknown.into());
    }
    let record = store
        .state_mut()
        .records
        .get_mut(&binding.full_request_digest_sha256)
        .ok_or(ReasonCode::IntegrityRejected)?;
    record.response_reservation_bytes = 0;
    record.state = OperationRecordState::Completed {
        completed_at_epoch_s: now,
        response_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
    };
    if store
        .state()
        .cached_bytes()
        .saturating_add(store.state().reserved_bytes())
        > MAX_CACHED_RESPONSE_BYTES
    {
        return Err(ReasonCode::OperationOnlyResultUnknown.into());
    }
    store.commit()
}

fn projected_response_bytes(store: &LedgerStore) -> usize {
    store
        .state()
        .cached_bytes()
        .saturating_add(store.state().reserved_bytes())
        .saturating_add(crate::MAX_CONTROL_BYTES)
}
