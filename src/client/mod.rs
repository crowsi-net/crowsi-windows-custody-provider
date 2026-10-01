mod identity;
#[cfg(feature = "operation-only")]
mod operation_process;
mod operations;
mod process;
mod response;
mod runtime;
mod validate;

pub use identity::HelperIdentity;
pub use response::{ClientResponse, SecretOutput};
pub use runtime::RuntimeConfig;

use std::time::Duration;

#[cfg(feature = "operation-only")]
use crate::{OperationOnlyRequest, OperationOnlyResponse};
use crate::{Request, Result};

pub struct CustodyClient {
    helper: HelperIdentity,
    namespace: String,
    timeout: Duration,
}

impl CustodyClient {
    /// Creates a client only for a currently verified helper image.
    ///
    /// # Errors
    ///
    /// Rejects an invalid namespace or timeout outside one millisecond to thirty seconds.
    pub fn new(
        helper: HelperIdentity,
        namespace: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self> {
        let namespace = namespace.into();
        if timeout.is_zero()
            || timeout > Duration::from_secs(30)
            || !crate::protocol::namespace(&namespace)
        {
            return Err(crate::ReasonCode::ContractRejected.into());
        }
        Ok(Self {
            helper,
            namespace,
            timeout,
        })
    }

    /// Performs one closed protocol exchange over anonymous stdio.
    ///
    /// # Errors
    ///
    /// Rejects a changed helper, invalid request, timeout, or malformed provider response.
    pub fn execute(&self, request: &Request, secret: Option<&[u8]>) -> Result<ClientResponse> {
        if request.namespace != self.namespace {
            return Err(crate::ReasonCode::ContractRejected.into());
        }
        process::exchange(&self.helper, self.timeout, request, secret)
    }

    /// Executes one operation-only request over the same pinned, clean helper process boundary.
    ///
    /// # Errors
    ///
    /// Rejects invalid input, changed helper identity, timeout, or malformed output.
    #[cfg(feature = "operation-only")]
    pub fn execute_operation(
        &self,
        request: &OperationOnlyRequest,
    ) -> Result<OperationOnlyResponse> {
        operation_process::exchange(&self.helper, self.timeout, request)
    }
}
