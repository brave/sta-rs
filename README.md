# sta-rs

Rust workspace for implementing basic functionality of [STAR: Distributed
Secret-Sharing for Threshold Aggregation
Reporting](https://arxiv.org/abs/2109.10074).

## Disclaimer

WARNING the libraries present in this workspace have not been audited,
use at your own risk! This code is under active development and may
change substantially in future versions.

## Crates

- [sta-rs](./sta-rs): A rust implementation of the [STAR
  protocol](https://arxiv.org/abs/2109.10074).
- [ppoprf](./ppoprf): A rust implementation of the PPOPRF protocol
  detailed in the [STAR paper](https://arxiv.org/abs/2109.10074).
- [sharks](./sharks): A fork of the existing [sharks
  crate](https://crates.io/crates/sharks) for performing Shamir secret
  sharing, using larger base fields of sizes 129 and 255 bits. The
  fields were implemented using 
- [adss](./adss): A rust implementation of the [Adept Secret
  Sharing scheme](https://eprint.iacr.org/2020/800) of Bellare et al,
  based on the forked [star-sharks](./sharks) crate, using the underlying
  finite field implementation made available in
  [zkcrypto/ff](https://github.com/zkcrypto/ff).
- [star-wasm](./star-wasm): WASM bindings for using [sta-rs](./sta-rs)
  functionality.

## Quickstart

Build & test:
```
cargo build
cargo test
```

Benchmarks:
```
cargo bench
```

Open local copy of documentation:
```
cargo doc --open --no-deps
```
## Example usage

### WASM

See [star-wasm](./star-wasm/src/lib.rs) for public API functions exposed
by libraries.

- The `create_share` function should be called by clients, and creates
  the `share` and `tag` sent in a STAR client message, as well as the
  encryption `key` used to encrypt data to the server. Once this
  function has been called, use `key` to encrypt the desired data into a
  `ciphertext` object (using a valid AES encryption method). The client
  should then send `(ciphertext, share, tag)` to the aggregation server.
- The `group_shares` function takes in a collection of `share` objects
  and recovers the `key` object that the client used for encrypting
  `ciphertext`. This function only succeeds if the number of shares is
  higher than the prescribed threshold.

