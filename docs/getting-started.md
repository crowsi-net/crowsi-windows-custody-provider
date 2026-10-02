# Using crowsi-windows-custody-provider

Protect owner-local credential storage using Windows CurrentUser DPAPI and a verified native helper.

## Before you start

Windows user context and the registered helper are required, including when the caller runs in WSL. This is not a Linux Secret Service backend.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Access protected custody from the declared Rust client.
- Pin the helper identity before a bounded operation.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
