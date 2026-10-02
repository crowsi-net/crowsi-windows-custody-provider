# crowsi-windows-custody-provider

Protect owner-local credential storage using Windows CurrentUser DPAPI and a verified native helper.

## What you can do

- Access protected custody from the declared Rust client.
- Pin the helper identity before a bounded operation.

## Current scope

Windows user context and the registered helper are required, including when the caller runs in WSL. This is not a Linux Secret Service backend.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Schemas](schemas) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
