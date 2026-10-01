use std::{
    io::Write,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use crate::protocol::{
    MAX_CONTROL_BYTES, MAX_SECRET_BYTES, read_secret_frame, require_eof, validate_request,
};
use crate::{
    ReasonCode, Request, Response, ResponseState, Result, decode_control, encode_control,
    read_frame, write_frame,
};

use super::{ClientResponse, HelperIdentity, validate};

pub(super) fn exchange(
    helper: &HelperIdentity,
    timeout: Duration,
    request: &Request,
    secret: Option<&[u8]>,
) -> Result<ClientResponse> {
    validate_request(request)?;
    validate::secret_shape(&request.operation, secret)?;
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
    let request_id = request.request_id.clone();
    let reader = thread::spawn(move || read_response(stdout));
    let send = encode_control(&request)
        .and_then(|body| write_frame(&mut stdin, &body, MAX_CONTROL_BYTES))
        .and_then(|()| match secret {
            Some(value) => write_frame(&mut stdin, value, MAX_SECRET_BYTES),
            None => Ok(()),
        })
        .and_then(|()| {
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
    let output = reader
        .join()
        .map_err(|_| ReasonCode::TransportUnavailable)?;
    waited?;
    let output = output?;
    validate::response(&output, &request_id, &request.operation)?;
    if let Some(reason) = output.response.reason_code() {
        return Err(reason.into());
    }
    Ok(output)
}

fn read_response(mut stdout: impl std::io::Read) -> Result<ClientResponse> {
    let body = read_frame(&mut stdout, MAX_CONTROL_BYTES)?;
    let response: Response = decode_control(&body)?;
    let secret = match &response.result {
        ResponseState::Ready {
            secret_follows: true,
            ..
        } => Some(read_secret_frame(&mut stdout)?),
        _ => None,
    };
    let output = ClientResponse::new(response, secret);
    require_eof(&mut stdout)?;
    Ok(output)
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
