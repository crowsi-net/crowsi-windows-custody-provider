mod authorization;
mod basic;
mod ledger_input;

use crowsi_windows_custody_provider::{OperationOnlyAction, ReasonCode, SigningAlgorithm};

pub use authorization::{device_scoped_revocation, op_03, op_04};
pub use basic::{op_01, op_02, op_05};
pub use ledger_input::{op_06, op_07};

use super::support;

fn ed25519() -> OperationOnlyAction {
    OperationOnlyAction::Sign {
        algorithm: SigningAlgorithm::Ed25519,
        digest_sha256: format!("sha256:{}", "b".repeat(64)),
    }
}

fn rsa() -> OperationOnlyAction {
    OperationOnlyAction::Sign {
        algorithm: SigningAlgorithm::RsaPkcs1Sha256,
        digest_sha256: digest(),
    }
}

fn provider() -> OperationOnlyAction {
    OperationOnlyAction::ProviderOperation {
        provider: "github".into(),
        operation: "sign-app-jwt".into(),
        input_digest_sha256: digest(),
    }
}

fn digest() -> String {
    format!("sha256:{}", "c".repeat(64))
}

fn failure<T>(result: crowsi_windows_custody_provider::Result<T>) -> ReasonCode {
    match result {
        Ok(_) => panic!("operation must fail"),
        Err(error) => error.reason(),
    }
}
