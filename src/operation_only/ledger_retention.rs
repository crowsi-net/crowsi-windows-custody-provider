use super::{
    ledger_model::{OperationRecordState, RESPONSE_RETENTION_SECONDS, TOMBSTONE_RETENTION_SECONDS},
    ledger_store::LedgerStore,
};

impl LedgerStore {
    pub(super) fn prune_expired(&mut self, now: u64) -> bool {
        let mut changed = false;
        for record in self.state.records.values_mut() {
            if matches!(record.state, OperationRecordState::Prepared)
                && now >= record.prepared_retain_until_epoch_s
            {
                record.state = OperationRecordState::Cancelled {
                    cancelled_at_epoch_s: now,
                };
                record.response_reservation_bytes = 0;
                changed = true;
            }
            if let OperationRecordState::Completed {
                completed_at_epoch_s,
                ..
            } = record.state
                && now.saturating_sub(completed_at_epoch_s) >= RESPONSE_RETENTION_SECONDS
            {
                record.state = OperationRecordState::Cancelled {
                    cancelled_at_epoch_s: now,
                };
                record.response_reservation_bytes = 0;
                changed = true;
            }
        }
        let remove = self
            .state
            .records
            .iter()
            .filter_map(|(key, record)| match record.state {
                OperationRecordState::Cancelled {
                    cancelled_at_epoch_s,
                } if now.saturating_sub(cancelled_at_epoch_s) >= TOMBSTONE_RETENTION_SECONDS => {
                    Some(key.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        changed |= !remove.is_empty();
        for key in remove {
            self.state.remove(&key);
        }
        changed
    }
}
