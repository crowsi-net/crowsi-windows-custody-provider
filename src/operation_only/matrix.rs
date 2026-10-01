use super::{
    OperationOnlyAction, OperationOnlyCredentialClass, OperationOnlyResult, SigningAlgorithm,
};

pub(crate) fn valid_matrix(
    class: OperationOnlyCredentialClass,
    action: &OperationOnlyAction,
) -> bool {
    match (class, action) {
        (
            OperationOnlyCredentialClass::RsaSigningKey,
            OperationOnlyAction::Sign {
                algorithm: SigningAlgorithm::RsaPkcs1Sha256,
                ..
            },
        )
        | (
            OperationOnlyCredentialClass::Ed25519SigningKey,
            OperationOnlyAction::Sign {
                algorithm: SigningAlgorithm::Ed25519,
                ..
            },
        ) => true,
        (
            OperationOnlyCredentialClass::ProviderOperation,
            OperationOnlyAction::ProviderOperation {
                provider,
                operation,
                ..
            },
        ) => provider == "github" && operation == "sign-app-jwt",
        _ => false,
    }
}

pub(crate) fn valid_result(action: &OperationOnlyAction, result: &OperationOnlyResult) -> bool {
    match (action, result) {
        (
            OperationOnlyAction::Sign { algorithm, .. },
            OperationOnlyResult::Signature {
                algorithm: actual,
                value_hex,
            },
        ) => algorithm == actual && bounded_hex(value_hex, 64, 16_384),
        (
            OperationOnlyAction::ProviderOperation {
                provider,
                operation,
                ..
            },
            OperationOnlyResult::ProviderResult {
                provider: actual_provider,
                operation: actual_operation,
                value_hex,
            },
        ) => {
            provider == actual_provider
                && operation == actual_operation
                && bounded_hex(value_hex, 2, 16_384)
        }
        _ => false,
    }
}

pub(crate) fn action_binding(action: &OperationOnlyAction) -> String {
    match action {
        OperationOnlyAction::Sign { algorithm, .. } => format!("sign:{}", algorithm.as_str()),
        OperationOnlyAction::ProviderOperation {
            provider,
            operation,
            ..
        } => format!("provider-operation:{provider}:{operation}"),
    }
}

fn bounded_hex(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
