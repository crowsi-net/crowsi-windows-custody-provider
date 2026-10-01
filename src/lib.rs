//! Windows-native owner-local custody and its bounded WSL client contract.

#[cfg(any(windows, test))]
mod binding;
mod client;
mod error;
#[cfg(feature = "operation-only")]
mod operation_only;
#[cfg(any(windows, test))]
mod protected;
mod protocol;
#[cfg(any(windows, test))]
mod record;
#[cfg(all(windows, feature = "operation-only"))]
mod windows;

pub use client::{ClientResponse, CustodyClient, HelperIdentity, RuntimeConfig, SecretOutput};
pub use error::{CustodyError, ReasonCode, Result};
#[cfg(feature = "operation-only")]
pub use operation_only::{
    DurableOperationNonceLedger, FileNonceLedger, MAX_OPERATION_INPUT_BYTES,
    OPERATION_AUTHORIZATION_AUDIENCE, OPERATION_AUTHORIZATION_ISSUER,
    OPERATION_AUTHORIZATION_SCHEMA, OPERATION_REQUEST_SCHEMA, OPERATION_RESPONSE_SCHEMA,
    OPERATION_SERVICE_ID, OPERATION_TRUST_SCHEMA, OPERATION_WORKLOAD_ID, OperationBinding,
    OperationContext, OperationCredentialMetadata, OperationLedgerBinding, OperationOnlyAction,
    OperationOnlyBackend, OperationOnlyCredentialClass, OperationOnlyDispatcher,
    OperationOnlyRequest, OperationOnlyResponse, OperationOnlyResult, OperationOnlyStore,
    OperationTrust, PaAuthorizationVerifier, PaOperationAuthorization,
    ProductionOperationDispatcher, SigningAlgorithm, WindowsOperationBackend, WindowsOperationPort,
    authorization_signing_bytes, decode_operation_request, operation_request_digest,
    reject_operation_only_get, reject_registered_generic_operation,
};
#[doc(hidden)]
#[cfg(feature = "operation-only")]
pub use operation_only::{OperationLedgerFailpoint, arm_operation_ledger_failpoint};
pub use protocol::{
    MAX_CONTROL_BYTES, MAX_SECRET_BYTES, Metadata, Operation, PROTOCOL, PROVIDER_KIND,
    REQUEST_SCHEMA, RESPONSE_SCHEMA, RUNTIME_SCHEMA, Request, Response, ResponseState,
    decode_control, encode_control, read_frame, write_frame,
};

#[cfg(all(windows, feature = "operation-only"))]
pub use windows::serve_one;
