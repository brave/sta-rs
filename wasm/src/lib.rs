use wasm_bindgen::prelude::*;

use base64::{decode, encode};

use adss_rs::{recover, Share};
use sta_rs::{derive_ske_key, Client};

/// This function takes as input a secret (the `url`), a `threshold` (number of shares required to
/// retrieved the encryption key and the initial secret on the server-side) and an `epoch` (used for
/// versioning).
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
pub fn create_share(url: &str, threshold: u32, epoch: &str) -> String {
    let client = Client::new(url.as_bytes(), threshold, epoch, true, None);

    let mut rnd = vec![0u8; 32];
    client.sample_local_randomness(&mut rnd);
    let r = client.derive_random_values(&rnd);

    // Replaced `derive_ciphertext` by `derive_key` with same argument.
    // let ciphertext = self.derive_ciphertext(&r[0]);
    let key = client.derive_key(&r[0]);

    let share = client.share(&r[0], &r[1]);
    let tag = &r[2];

    // key: Vec<u8>
    // share: Share
    // tag: Vec<u8>
    let key_b64 = encode(&key);
    let share_b64 = encode(&share.to_bytes());
    let tag_b64 = encode(&tag);

    format!(
        r#"{{"key": "{}", "share": "{}", "tag": "{}", "kl": "{}"}}"#,
        key_b64, share_b64, tag_b64, key.len(),
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
        .map(|chunk| Share::from_bytes(&decode(chunk).unwrap()).unwrap())
        .collect();

    // 2. call recover(shares)
    let res = recover(&shares);
    if res.is_err() {
        return None;
    }
    let message = res.unwrap().get_message();

    // 3. call derive_ske_key
    let mut enc_key = vec![0u8; 16];
    derive_ske_key(&message, epoch.as_bytes(), &mut enc_key);

    Some(encode(&enc_key).to_string())
}
