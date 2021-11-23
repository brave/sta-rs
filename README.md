# sta-rs

Rust library for implementing basic functionality of [STAR: Distributed
Secret-Sharing for Threshold Aggregation
Reporting](https://arxiv.org/abs/2109.10074).

## Disclaimer

WARNING this library has not been audited, use at your own risk! This
code is under active development and may change substantially in future
versions.

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

## Example usage

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


## Components

- Secret sharing is implemented using a modified implementation of the
  Rust [Sharks library](https://crates.io/crates/sharks) that makes use
  of larger base fields (129 and 255 bits, implemented using
  [zkcrypto/ff](https://github.com/zkcrypto/ff)). The secret sharing
  approach is constructed using the [Adept Secret Sharing
  framework](https://eprint.iacr.org/2020/800) of Bellare et al.
- All symmetric cryptography is implemented using the Rust
  implementation of the [STROBE
  protocol](https://docs.rs/strobe-rs/0.6.2/strobe_rs/) framework.
- The Puncturable Pseudorandom Oblivious Pseudorandom Function (PPOPRF)
  library is implemented using the PPOPRF construction detailed in the
  [STAR paper](https://arxiv.org/abs/2109.10074), using the
  Goldreich-Goldwasser-Micali (GGM) puncturable PRF. This functionality
  is considered experimental.

## Supported features

Currently only functions used in the STAR1 protocol are supported and
used elsewhere. Experimental functions for running the randomness server
(and PPOPRF) required in STAR2 are provided under the `star2` feature.
These functions can be tested using the `--all-features` flag.