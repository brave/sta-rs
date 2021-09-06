use wasm_bindgen::prelude::*;

use sta_rs::Client;

#[wasm_bindgen]
pub fn create_share(url: &str, threshold: usize, epoch: &str) -> sta_rs::Triple {
    // TODO - add auxiliary data
    // TODO - return `triple` serialized
    let client = Client::new(url.as_bytes(), threshold, epoch, true, None);
    let triple = client.generate_triple(None);
    "Ok!".to_string()
}
