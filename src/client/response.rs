use zeroize::{Zeroize, Zeroizing};

use crate::Response;

pub struct ClientResponse {
    pub response: Response,
    secret: Option<SecretOutput>,
}

impl ClientResponse {
    pub(crate) fn new(response: Response, secret: Option<Zeroizing<Vec<u8>>>) -> Self {
        Self {
            response,
            secret: secret.map(SecretOutput),
        }
    }

    /// Provides temporary access while preserving zeroization on drop.
    pub fn expose_secret<T>(&self, use_secret: impl FnOnce(Option<&[u8]>) -> T) -> T {
        use_secret(self.secret.as_ref().map(SecretOutput::as_slice))
    }

    pub(crate) fn has_secret(&self) -> bool {
        self.secret.is_some()
    }
}

pub struct SecretOutput(Zeroizing<Vec<u8>>);

impl SecretOutput {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for ClientResponse {
    fn drop(&mut self) {
        if let Some(secret) = &mut self.secret {
            secret.0.zeroize();
        }
    }
}
