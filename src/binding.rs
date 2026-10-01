use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub(crate) fn namespace(namespace: &str) -> [u8; 32] {
    Sha256::digest(
        [
            b"crowsi-custody-namespace-v1\0".as_slice(),
            namespace.as_bytes(),
        ]
        .concat(),
    )
    .into()
}

pub(crate) fn entropy(namespace: &str, credential_id: &str) -> Zeroizing<Vec<u8>> {
    let mut digest = Sha256::new();
    digest.update(b"crowsi-windows-custody-v1\0");
    let namespace_len = u64::try_from(namespace.len()).unwrap_or(u64::MAX);
    let credential_len = u64::try_from(credential_id.len()).unwrap_or(u64::MAX);
    digest.update(namespace_len.to_be_bytes());
    digest.update(namespace.as_bytes());
    digest.update(credential_len.to_be_bytes());
    digest.update(credential_id.as_bytes());
    Zeroizing::new(digest.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::{entropy, namespace};

    #[test]
    fn exact_namespace_and_identifier_are_bound_without_concatenation_ambiguity() {
        assert_ne!(entropy("alpha", "same"), entropy("beta", "same"));
        assert_ne!(entropy("alpha", "bc"), entropy("alphab", "c"));
        assert_ne!(namespace("alpha"), namespace("beta"));
    }
}
