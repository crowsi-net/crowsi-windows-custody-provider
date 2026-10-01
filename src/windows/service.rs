use std::io::{Read, Write};

use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::{
    MAX_CONTROL_BYTES, MAX_SECRET_BYTES, read_secret_frame, require_eof, validate_request,
};
use crate::{
    Operation, ReasonCode, Request, Response, Result, decode_control, encode_control, read_frame,
    write_frame,
};

use super::storage::Store;
use super::{cng_registry, operation_service};

/// Serves one bounded request and returns only the reviewed response shape.
///
/// # Errors
///
/// Returns a closed provider error when framing, validation, storage, or output fails.
pub fn serve_one(mut input: impl Read, mut output: impl Write) -> Result<()> {
    let body = read_frame(&mut input, MAX_CONTROL_BYTES)?;
    if operation_v2(&body) {
        require_eof(&mut input)?;
        let response = operation_service::execute(&body)?;
        write_frame(&mut output, &response, MAX_CONTROL_BYTES)?;
        return output
            .flush()
            .map_err(|_| ReasonCode::TransportUnavailable.into());
    }
    let request: Request = decode_control(&body)?;
    let request_id = request.request_id.clone();
    let handled = match handle(&mut input, request) {
        Ok(result) => result,
        Err(error) => Handled::new(Response::error(request_id, error.reason())),
    };
    let control = encode_control(&handled.response)?;
    write_frame(&mut output, &control, MAX_CONTROL_BYTES)?;
    if let Some(mut secret) = handled.secret {
        write_frame(&mut output, &secret, MAX_SECRET_BYTES)?;
        secret.zeroize();
    }
    output
        .flush()
        .map_err(|_| ReasonCode::TransportUnavailable.into())
}

struct Handled {
    response: Response,
    secret: Option<Zeroizing<Vec<u8>>>,
}

impl Handled {
    fn new(response: Response) -> Self {
        Self {
            response,
            secret: None,
        }
    }
    fn secret(response: Response, secret: Zeroizing<Vec<u8>>) -> Self {
        Self {
            response,
            secret: Some(secret),
        }
    }
}

fn handle(input: &mut impl Read, request: Request) -> Result<Handled> {
    validate_request(&request)?;
    reject_registered_operation_export(&request.operation)?;
    let id = request.request_id.clone();
    let secret = match request.operation {
        Operation::Put { .. } => Some(read_secret_frame(input)?),
        _ => None,
    };
    require_eof(input)?;
    let store = Store::open(&request.namespace)?;
    match request.operation {
        Operation::Doctor => {
            store.doctor()?;
            Ok(Handled::new(Response::ready(id, "doctor", None, false)))
        }
        Operation::Put {
            credential_id,
            expected_revision,
        } => {
            let metadata = store.put(
                &credential_id,
                expected_revision.as_deref(),
                secret.ok_or(ReasonCode::ContractRejected)?,
            )?;
            Ok(Handled::new(Response::ready(
                id,
                "put",
                Some(metadata),
                false,
            )))
        }
        Operation::Metadata { credential_id } => {
            let metadata = store.metadata(&credential_id)?;
            Ok(Handled::new(Response::ready(
                id,
                "metadata",
                Some(metadata),
                false,
            )))
        }
        Operation::Get {
            credential_id,
            expected_revision,
        } => {
            let record = store.get(&credential_id, &expected_revision)?;
            let response = Response::ready(
                id,
                "get",
                Some(crate::Metadata::new(credential_id, expected_revision)),
                true,
            );
            Ok(Handled::secret(response, record.secret))
        }
        Operation::Delete {
            credential_id,
            expected_revision,
        } => {
            let metadata = store.delete(&credential_id, &expected_revision)?;
            Ok(Handled::new(Response::ready(
                id,
                "delete",
                Some(metadata),
                false,
            )))
        }
    }
}

fn operation_v2(body: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct Envelope {
        schema: String,
    }
    serde_json::from_slice::<Envelope>(body)
        .is_ok_and(|value| value.schema == crate::OPERATION_REQUEST_SCHEMA)
}

fn reject_registered_operation_export(operation: &Operation) -> Result<()> {
    let id = match operation {
        Operation::Put { credential_id, .. }
        | Operation::Get { credential_id, .. }
        | Operation::Delete { credential_id, .. } => Some(credential_id),
        Operation::Doctor | Operation::Metadata { .. } => None,
    };
    let registered = id
        .map(|value| cng_registry::registered_class(value))
        .transpose()?
        .flatten();
    crate::reject_registered_generic_operation(operation, registered)
}
