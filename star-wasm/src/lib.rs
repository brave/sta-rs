//! WebAssembly bindings for the STAR protocol
//!
//! This provides a threshold-aggregation scheme based on secret sharing,
//! allowing data to be encrypted by clients in a way that a receiving
//! server can only decrypt values submitted by multiple clients, offering
//! safety-in-numbers privacy.

use wasm_bindgen::prelude::*;

use base64::{engine::Engine as _, prelude::BASE64_STANDARD};

use sta_rs::{
  derive_ske_key, share_recover, MessageGenerator, Share, SingleMeasurement,
  WASMSharingMaterial,
};

// NOTE - this can be used for debugging. Disabled for the production build.
// extern crate console_error_panic_hook;
// use std::panic;

/// This function takes as input a secret (the `measurement`), a `threshold` (number of shares
/// required to retrieve the encryption key and the initial secret on the server-side) and an
/// `epoch` (used for versioning).
///
/// It returns a triple (tag, share, key) where:
/// - `tag` is used to group "compatible" shares on the server-side, this is used to get all the
/// shares which were derived from the same secret.
/// - `share` contains the secret (`key`) which can then be used server-side to retrive the
/// decryption key and access the original metadata associated with a URL (only once the threshold
/// has been met)
/// - `key` is the encryption key which will be used by the client to encrypt the metadata before
/// sending to the server. the `key` will *never* be sent to the server.
///
/// What we send to the backend is a pair (share, encrypted_metadata). Which means that the server
/// must have received at least `threshold` shares for a given secret to be able to recover the
/// decryption key and decrypt `encrypted_metadata`.
#[wasm_bindgen]
pub fn create_share(measurement: &[u8], threshold: u32, epoch: &str) -> String {
  // NOTE - enable for debugging.
  // panic::set_hook(Box::new(console_error_panic_hook::hook));

  let mg = MessageGenerator::new(
    SingleMeasurement::new(measurement),
    threshold,
    epoch.as_bytes(),
  );
  let share_result = mg.share_with_local_randomness();
  if share_result.is_err() {
    return "".to_owned();
  }
  let WASMSharingMaterial { key, share, tag } = share_result.unwrap();

  let key_b64 = BASE64_STANDARD.encode(key);
  let share_b64 = BASE64_STANDARD.encode(share.to_bytes());
  let tag_b64 = BASE64_STANDARD.encode(tag);

  format!(
    r#"{{"key": "{key_b64}", "share": "{share_b64}", "tag": "{tag_b64}"}}"#
  )
}

/// This function takes as argument a (serialized) list of shares (type: Share). The assumption is
/// that the user of this function will already have grouped shares by `tag` and only calls the
/// `group_shares` function if we have received more than `threshold` shares.
#[wasm_bindgen]
pub fn group_shares(serialized_shares: &str, epoch: &str) -> Option<String> {
  // 1. deserialize shares into Vec<Share>
  let shares: Vec<Share> = serialized_shares
    .split('\n')
    .map(|chunk| {
      Share::from_bytes(&BASE64_STANDARD.decode(chunk).unwrap()).unwrap()
    })
    .collect();

  // 2. call recover(shares)
  let res = share_recover(&shares);
  if res.is_err() {
    return None;
  }
  let message = res.unwrap().get_message();

  // 3. call derive_ske_key
  let mut enc_key = vec![0u8; 16];
  derive_ske_key(&message, epoch.as_bytes(), &mut enc_key);

  Some(BASE64_STANDARD.encode(&enc_key))
}
