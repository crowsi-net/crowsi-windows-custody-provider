mod cng_operation;
mod cng_registry;
#[allow(unsafe_code)]
mod cng_sign;
#[allow(unsafe_code)]
mod dpapi;
#[allow(unsafe_code)]
mod file_identity;
#[allow(unsafe_code)]
mod known_folder;
mod operation_service;
#[allow(unsafe_code)]
pub(crate) mod replace;
mod service;
mod storage;
mod storage_file;

pub(crate) use file_identity::{identity as file_identity, link_count};
pub use service::serve_one;
