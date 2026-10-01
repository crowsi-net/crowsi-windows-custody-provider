use crate::{ReasonCode, Result};

use super::{
    OperationLedgerBinding,
    ledger_model::{LedgerState, OperationRecordState},
    ledger_root::LedgerRoot,
};

pub(super) enum LedgerMatch {
    Absent,
    Prepared,
    Completed(Vec<u8>),
    Cancelled,
}

pub(super) struct LedgerStore {
    pub root: std::sync::Arc<LedgerRoot>,
    pub state: LedgerState,
    pub state_sha256: String,
}

impl LedgerStore {
    pub fn state(&self) -> &LedgerState {
        &self.state
    }
    pub fn state_mut(&mut self) -> &mut LedgerState {
        &mut self.state
    }

    pub fn classify(&self, binding: &OperationLedgerBinding) -> Result<LedgerMatch> {
        let nonce = self.state.nonce_index.get(&binding.nonce_digest_sha256);
        let request = self
            .state
            .request_id_index
            .get(&binding.request_id_digest_sha256);
        match (nonce, request) {
            (None, None)
                if !self
                    .state
                    .records
                    .contains_key(&binding.full_request_digest_sha256) =>
            {
                Ok(LedgerMatch::Absent)
            }
            (Some(left), Some(right))
                if left == right && left == &binding.full_request_digest_sha256 =>
            {
                let record = self
                    .state
                    .records
                    .get(left)
                    .ok_or(ReasonCode::IntegrityRejected)?;
                if &record.binding != binding {
                    return Err(ReasonCode::IntegrityRejected.into());
                }
                match &record.state {
                    OperationRecordState::Prepared => Ok(LedgerMatch::Prepared),
                    OperationRecordState::Completed {
                        response_base64, ..
                    } => {
                        use base64::Engine as _;
                        base64::engine::general_purpose::STANDARD
                            .decode(response_base64)
                            .map(LedgerMatch::Completed)
                            .map_err(|_| ReasonCode::IntegrityRejected.into())
                    }
                    OperationRecordState::Cancelled { .. } => Ok(LedgerMatch::Cancelled),
                }
            }
            (Some(_), _) | (_, Some(_)) => {
                Err(ReasonCode::OperationOnlyAuthorizationReplayed.into())
            }
            (None, None) => Err(ReasonCode::IntegrityRejected.into()),
        }
    }

    pub fn observe_and_prune(&mut self, now: u64) -> Result<()> {
        if now < self.state.clock_high_watermark_epoch_s {
            return Err(ReasonCode::OperationOnlyAuthorizationReplayed.into());
        }
        if now > self.state.clock_high_watermark_epoch_s {
            self.state.clock_high_watermark_epoch_s = now;
            self.commit()?;
        }
        if self.prune_expired(now) {
            self.commit()?;
        }
        Ok(())
    }

    pub fn commit(&mut self) -> Result<()> {
        self.validate()?;
        let digest =
            super::ledger_io::commit_state(&self.root, &mut self.state, &self.state_sha256)?;
        self.state_sha256 = digest;
        Ok(())
    }
}
