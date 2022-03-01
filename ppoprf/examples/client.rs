//! Example clieant for the ppoprf randomness web service.
//!
//! This tests and demonstrates the ppoprf evaluation function
//! in an Actix-Web service application by making example queries.
//!
//! To verify the example works, start the server in one terminal:
//! ```sh
//! cargo run --example server
//! ```
//!
//! In another terminal, launch the client:
//! ```sh
//! cargo run --example client
//! ```

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use env_logger::Env;
use log::info;
use reqwest::blocking::{Client, get};
use serde::Serialize;

/// Fetch the server identification string.
///
/// Acts as a basic availability ping.
fn fetch_ident(url: &str) -> reqwest::Result<()> {
    let res = get(url)?;
    let status = res.status();
    let text = res.text()?;

    info!("{} - {}", status, text);

    Ok(())
}

/// Explicit query body.
#[derive(Serialize)]
struct Query {
    name: String,
    points: Vec<String>,
}

/// Fetch randomness from the server.
///
/// Acts as a basic round-trip test.
fn fetch_randomness(url: &str) -> reqwest::Result<()> {
    let query = Query {
        name: "example client".into(),
        points: vec![ base64::encode(RISTRETTO_BASEPOINT_COMPRESSED.0), ],
    };
    let client = Client::new();
    let res = client.post(url)
        .json(&query)
        .send()?;
    let status = res.status();
    let text = res.text()?;

    info!("{} - {}", status, text);

    Ok(())
}

fn main() {
    let url = "http://localhost:8080";

    env_logger::init_from_env(Env::default().default_filter_or("info"));

    info!("Contacting server at {}", url);
    fetch_ident(&url).unwrap();
    fetch_randomness(&url).unwrap();
}
