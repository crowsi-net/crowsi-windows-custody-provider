use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::OperationLedgerBinding;

pub(super) const LEDGER_SCHEMA: &str = "crowsi://windows-custody/operation-ledger/v2";
pub(super) const MAX_RECORDS: usize = 256;
pub(super) const MAX_NEW_PREPARED_RECORDS: usize = MAX_RECORDS - 1;
pub(super) const MAX_CACHED_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub(super) const MAX_COMPLETION_STATE_GROWTH_BYTES: usize =
    crate::MAX_CONTROL_BYTES.div_ceil(3) * 4 + 128;
pub(super) const RESPONSE_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;
pub(super) const TOMBSTONE_RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LedgerState {
    pub schema: String,
    pub revision: u64,
    pub previous_state_sha256: String,
    pub clock_high_watermark_epoch_s: u64,
    pub records: BTreeMap<String, OperationRecord>,
    pub nonce_index: BTreeMap<String, String>,
    pub request_id_index: BTreeMap<String, String>,
}

impl Default for LedgerState {
    fn default() -> Self {
        Self {
            schema: LEDGER_SCHEMA.into(),
            revision: 0,
            previous_state_sha256: "0".repeat(64),
            clock_high_watermark_epoch_s: 0,
            records: BTreeMap::new(),
            nonce_index: BTreeMap::new(),
            request_id_index: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationRecord {
    pub binding: OperationLedgerBinding,
    pub prepared_at_epoch_s: u64,
    pub prepared_retain_until_epoch_s: u64,
    pub response_reservation_bytes: usize,
    pub state: OperationRecordState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum OperationRecordState {
    Prepared,
    Completed {
        completed_at_epoch_s: u64,
        response_base64: String,
    },
    Cancelled {
        cancelled_at_epoch_s: u64,
    },
}

impl LedgerState {
    pub fn cached_bytes(&self) -> usize {
        self.records
            .values()
            .map(|record| match &record.state {
                OperationRecordState::Completed {
                    response_base64, ..
                } => decoded_length(response_base64),
                _ => 0,
            })
            .sum()
    }

    pub fn reserved_bytes(&self) -> usize {
        self.records
            .values()
            .map(|record| record.response_reservation_bytes)
            .sum()
    }

    pub fn completion_state_reservation_bytes(&self) -> usize {
        self.records
            .values()
            .filter(|record| matches!(record.state, OperationRecordState::Prepared))
            .count()
            .saturating_mul(MAX_COMPLETION_STATE_GROWTH_BYTES)
    }

    pub fn remove(&mut self, key: &str) {
        if let Some(record) = self.records.remove(key) {
            self.nonce_index.remove(&record.binding.nonce_digest_sha256);
            self.request_id_index
                .remove(&record.binding.request_id_digest_sha256);
        }
    }
}

fn decoded_length(value: &str) -> usize {
    let padding =
        usize::from(value.ends_with('=')).saturating_add(usize::from(value.ends_with("==")));
    value
        .len()
        .saturating_div(4)
        .saturating_mul(3)
        .saturating_sub(padding)
}
