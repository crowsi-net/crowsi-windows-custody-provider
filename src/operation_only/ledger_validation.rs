use crate::{ReasonCode, Result};

use super::{
    OperationLedgerBinding,
    ledger_model::{
        LEDGER_SCHEMA, MAX_CACHED_RESPONSE_BYTES, MAX_RECORDS, OperationRecord,
        OperationRecordState,
    },
    ledger_store::LedgerStore,
};

impl LedgerStore {
    pub fn validate(&self) -> Result<()> {
        let state_bytes =
            serde_json::to_vec(&self.state).map_err(|_| ReasonCode::IntegrityRejected)?;
        if self.state.schema != LEDGER_SCHEMA
            || self.state.revision == 0
            || !digest(&self.state.previous_state_sha256)
            || self.state.records.len() > MAX_RECORDS
            || self.state.nonce_index.len() != self.state.records.len()
            || self.state.request_id_index.len() != self.state.records.len()
            || self
                .state
                .cached_bytes()
                .saturating_add(self.state.reserved_bytes())
                > MAX_CACHED_RESPONSE_BYTES
            || state_bytes.len() > super::ledger_fs::MAX_LEDGER_BYTES
            || state_bytes
                .len()
                .saturating_add(self.state.completion_state_reservation_bytes())
                > super::ledger_fs::MAX_LEDGER_BYTES
        {
            return Err(ReasonCode::IntegrityRejected.into());
        }
        for (key, record) in &self.state.records {
            if key != &record.binding.full_request_digest_sha256
                || !valid_binding(&record.binding)
                || self
                    .state
                    .nonce_index
                    .get(&record.binding.nonce_digest_sha256)
                    != Some(key)
                || self
                    .state
                    .request_id_index
                    .get(&record.binding.request_id_digest_sha256)
                    != Some(key)
                || record.prepared_at_epoch_s > self.state.clock_high_watermark_epoch_s
                || record.binding.authorization_expires_at_epoch_s <= record.prepared_at_epoch_s
                || record.prepared_retain_until_epoch_s
                    != record
                        .binding
                        .authorization_expires_at_epoch_s
                        .checked_add(super::ledger_model::RESPONSE_RETENTION_SECONDS)
                        .ok_or(ReasonCode::IntegrityRejected)?
                || !valid_record_state(record, self.state.clock_high_watermark_epoch_s)
            {
                return Err(ReasonCode::IntegrityRejected.into());
            }
        }
        Ok(())
    }
}

fn valid_record_state(record: &OperationRecord, watermark: u64) -> bool {
    match &record.state {
        OperationRecordState::Prepared => {
            record.response_reservation_bytes == crate::MAX_CONTROL_BYTES
                && record.prepared_retain_until_epoch_s > record.prepared_at_epoch_s
        }
        OperationRecordState::Completed {
            completed_at_epoch_s,
            response_base64,
        } => {
            use base64::Engine as _;
            let decoded = base64::engine::general_purpose::STANDARD.decode(response_base64);
            *completed_at_epoch_s >= record.prepared_at_epoch_s
                && *completed_at_epoch_s <= watermark
                && record.response_reservation_bytes == 0
                && !response_base64.is_empty()
                && response_base64.len() <= crate::MAX_CONTROL_BYTES.div_ceil(3) * 4
                && decoded.is_ok_and(|bytes| {
                    bytes.len() <= crate::MAX_CONTROL_BYTES
                        && base64::engine::general_purpose::STANDARD.encode(&bytes)
                            == response_base64.as_str()
                })
        }
        OperationRecordState::Cancelled {
            cancelled_at_epoch_s,
        } => {
            *cancelled_at_epoch_s >= record.prepared_at_epoch_s
                && *cancelled_at_epoch_s <= watermark
                && record.response_reservation_bytes == 0
        }
    }
}

fn valid_binding(value: &OperationLedgerBinding) -> bool {
    digest(&value.full_request_digest_sha256)
        && digest(&value.nonce_digest_sha256)
        && digest(&value.request_id_digest_sha256)
        && !value.credential_id.is_empty()
        && !value.expected_revision.is_empty()
        && value.authorization_expires_at_epoch_s > 0
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
