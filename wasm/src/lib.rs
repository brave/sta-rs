use wasm_bindgen::prelude::*;

use sta_rs::Client;

#[wasm_bindgen]
pub fn create_share(url: &str, threshold: u32, epoch: &str) -> Vec<u8> {
    // TODO - add auxiliary data
    let client = Client::new(url.as_bytes(), threshold, epoch, true, None);
    let triple = client.generate_triple(None);
    triple.to_bytes()
}
