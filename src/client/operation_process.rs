use std::{
    io::Write,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use crate::{
    MAX_CONTROL_BYTES, OperationOnlyRequest, OperationOnlyResponse, ReasonCode, Result,
    decode_operation_request, read_frame, write_frame,
};

use super::HelperIdentity;

pub(super) fn exchange(
    helper: &HelperIdentity,
    timeout: Duration,
    request: &OperationOnlyRequest,
) -> Result<OperationOnlyResponse> {
    let body = serde_json::to_vec(request).map_err(|_| ReasonCode::OperationOnlyInputRejected)?;
    decode_operation_request(&body)?;
    let mut child = Command::new(helper.verified_path()?)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ReasonCode::TransportUnavailable)?;
    let mut stdin = child.stdin.take().ok_or(ReasonCode::TransportUnavailable)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(ReasonCode::TransportUnavailable)?;
    let reader = thread::spawn(move || read_response(stdout));
    let send = write_frame(&mut stdin, &body, MAX_CONTROL_BYTES).and_then(|()| {
        stdin
            .flush()
            .map_err(|_| ReasonCode::TransportUnavailable.into())
    });
    drop(stdin);
    if let Err(error) = send {
        terminate(&mut child);
        let _ = reader.join();
        return Err(error);
    }
    let waited = wait(&mut child, timeout);
    let response = reader
        .join()
        .map_err(|_| ReasonCode::TransportUnavailable)?;
    waited?;
    let response = response?;
    validate_response(&response, request)?;
    Ok(response)
}

fn read_response(mut output: impl std::io::Read) -> Result<OperationOnlyResponse> {
    let body = read_frame(&mut output, MAX_CONTROL_BYTES)?;
    let mut decoder = serde_json::Deserializer::from_slice(&body);
    let response = serde::Deserialize::deserialize(&mut decoder)
        .map_err(|_| ReasonCode::OperationOnlyResultUnknown)?;
    decoder
        .end()
        .map_err(|_| ReasonCode::OperationOnlyResultUnknown)?;
    crate::protocol::require_eof(&mut output)?;
    Ok(response)
}

fn validate_response(
    response: &OperationOnlyResponse,
    request: &OperationOnlyRequest,
) -> Result<()> {
    let valid = response.schema == crate::OPERATION_RESPONSE_SCHEMA
        && response.request_id == request.request_id
        && response.credential_id == request.credential_id
        && response.revision == request.expected_revision
        && !response.contains_secret_values
        && !response.secret_follows
        && crate::operation_only::valid_operation_result(&request.action, &response.result);
    valid
        .then_some(())
        .ok_or(ReasonCode::OperationOnlyResultUnknown.into())
}

fn wait(child: &mut std::process::Child, timeout: Duration) -> Result<()> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| ReasonCode::TransportUnavailable)?
        {
            return status
                .success()
                .then_some(())
                .ok_or(ReasonCode::TransportUnavailable.into());
        }
        if started.elapsed() >= timeout {
            terminate(child);
            return Err(ReasonCode::TransportTimeout.into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn terminate(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}
