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

use env_logger::Env;
use log::info;
use reqwest::blocking::{Client, get};

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

/// Fetch randomness from the server.
///
/// Acts as a basic round-trip test.
fn fetch_randomness(url: &str) -> reqwest::Result<()> {
    let client = Client::new();
    let res = client.post(url)
        .header("Content-Type", "application/json")
        .body("{\"name\":\"example client\", \"points\": [
                [226, 242, 174, 10, 106, 188, 78, 113,
                 168, 132, 169, 97, 197, 0, 81, 95,
                 88, 227, 11, 106, 165, 130, 221, 141,
                 182, 166, 89, 69, 224, 141, 45, 118]]}")
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
