use getrandom::fill;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::protocol::{MAX_SECRET_BYTES, identifier, namespace, revision};
use crate::{ReasonCode, Result};

const MAGIC: &[u8; 4] = b"CWR2";
const BINDING_BYTES: usize = 32;
const DIGEST_BYTES: usize = 32;
const REVISION_BYTES: usize = 32;
const REVISION_TEXT_BYTES: usize = 5 + REVISION_BYTES * 2;

pub(crate) struct SecretRecord {
    namespace_binding: [u8; BINDING_BYTES],
    pub credential_id: String,
    pub revision: String,
    pub secret: Zeroizing<Vec<u8>>,
}

impl SecretRecord {
    pub(crate) fn new(
        namespace_value: &str,
        credential_id: String,
        secret: Zeroizing<Vec<u8>>,
    ) -> Result<Self> {
        if !namespace(namespace_value)
            || !identifier(&credential_id, 128)
            || secret.is_empty()
            || secret.len() > MAX_SECRET_BYTES
        {
            return Err(ReasonCode::ContractRejected.into());
        }
        let mut token = [0_u8; REVISION_BYTES];
        fill(&mut token).map_err(|_| ReasonCode::BackendUnavailable)?;
        Ok(Self {
            namespace_binding: crate::binding::namespace(namespace_value),
            credential_id,
            revision: format!("rev1:{}", hex::encode(token)),
            secret,
        })
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let id = self.credential_id.as_bytes();
        let id_len = u16::try_from(id.len()).map_err(|_| ReasonCode::ContractRejected)?;
        let secret_len =
            u32::try_from(self.secret.len()).map_err(|_| ReasonCode::ContractRejected)?;
        let mut body = Vec::with_capacity(
            4 + BINDING_BYTES
                + 2
                + id.len()
                + REVISION_TEXT_BYTES
                + 4
                + self.secret.len()
                + DIGEST_BYTES,
        );
        body.extend_from_slice(MAGIC);
        body.extend_from_slice(&self.namespace_binding);
        body.extend_from_slice(&id_len.to_be_bytes());
        body.extend_from_slice(id);
        body.extend_from_slice(self.revision.as_bytes());
        body.extend_from_slice(&secret_len.to_be_bytes());
        body.extend_from_slice(&self.secret);
        body.extend_from_slice(&Sha256::digest(&self.secret));
        Ok(Zeroizing::new(body))
    }

    pub(crate) fn decode(body: &[u8], expected_namespace: &str) -> Result<Self> {
        let minimum = 4 + BINDING_BYTES + 2 + 1 + REVISION_TEXT_BYTES + 4 + 1 + DIGEST_BYTES;
        if body.len() < minimum || body.get(..4) != Some(MAGIC) {
            return Err(ReasonCode::IntegrityRejected.into());
        }
        let id_length_at = 4 + BINDING_BYTES;
        let id_at = id_length_at + 2;
        let id_len = usize::from(u16::from_be_bytes([
            body[id_length_at],
            body[id_length_at + 1],
        ]));
        let revision_at = id_at
            .checked_add(id_len)
            .ok_or(ReasonCode::IntegrityRejected)?;
        let length_at = revision_at
            .checked_add(REVISION_TEXT_BYTES)
            .ok_or(ReasonCode::IntegrityRejected)?;
        let secret_at = length_at
            .checked_add(4)
            .ok_or(ReasonCode::IntegrityRejected)?;
        if secret_at > body.len() {
            return Err(ReasonCode::IntegrityRejected.into());
        }
        let size = usize::try_from(u32::from_be_bytes(
            body[length_at..secret_at]
                .try_into()
                .map_err(|_| ReasonCode::IntegrityRejected)?,
        ))
        .map_err(|_| ReasonCode::IntegrityRejected)?;
        let secret_end = secret_at
            .checked_add(size)
            .ok_or(ReasonCode::IntegrityRejected)?;
        if secret_end.checked_add(DIGEST_BYTES) != Some(body.len()) {
            return Err(ReasonCode::IntegrityRejected.into());
        }
        let record = Self {
            namespace_binding: body[4..id_length_at]
                .try_into()
                .map_err(|_| ReasonCode::IntegrityRejected)?,
            credential_id: text(body, id_at, revision_at)?,
            revision: text(body, revision_at, length_at)?,
            secret: Zeroizing::new(body[secret_at..secret_end].to_vec()),
        };
        record.validate(expected_namespace, &body[secret_end..])?;
        Ok(record)
    }

    fn validate(&self, namespace_value: &str, expected_digest: &[u8]) -> Result<()> {
        let valid = namespace(namespace_value)
            && self.namespace_binding == crate::binding::namespace(namespace_value)
            && identifier(&self.credential_id, 128)
            && revision(&self.revision)
            && !self.secret.is_empty()
            && self.secret.len() <= MAX_SECRET_BYTES
            && Sha256::digest(&self.secret)[..] == *expected_digest;
        valid
            .then_some(())
            .ok_or(ReasonCode::IntegrityRejected.into())
    }
}

fn text(body: &[u8], start: usize, end: usize) -> Result<String> {
    std::str::from_utf8(&body[start..end])
        .map(str::to_owned)
        .map_err(|_| ReasonCode::IntegrityRejected.into())
}

#[cfg(test)]
#[path = "record_tests.rs"]
mod tests;
