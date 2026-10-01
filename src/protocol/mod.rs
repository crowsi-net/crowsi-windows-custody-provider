mod frame;
mod request;
mod response;
mod validation;

pub use frame::{MAX_CONTROL_BYTES, MAX_SECRET_BYTES, read_frame, write_frame};
pub(crate) use frame::{read_secret_frame, require_eof};
pub use request::{Operation, Request};
pub use response::{Metadata, Response, ResponseState};
pub use validation::{decode_control, encode_control};
pub(crate) use validation::{identifier, revision};
pub(crate) use validation::{namespace, validate_request};

pub const RUNTIME_SCHEMA: &str = "crowsi://platform-custody/runtime/v1";
pub const REQUEST_SCHEMA: &str = "crowsi://platform-custody/request/v1";
pub const PROTOCOL: &str = "crowsi-windows-custody-v1";
pub const PROVIDER_KIND: &str = "windows-dpapi-user";
pub const RESPONSE_SCHEMA: &str = "crowsi://platform-custody/response/v1";
