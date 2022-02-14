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
use reqwest::blocking::get;

/// Fetch the server identification string.
///
/// Acts as a basic availability ping.
fn fetch_id(url: &str) -> reqwest::Result<()> {
    let res = get(url)?;
    let status = res.status();
    let text = res.text()?;

    info!("{} - {}", status, text);

    Ok(())
}

fn main() {
    let url = "http://localhost:8080";

    env_logger::init_from_env(Env::default().default_filter_or("info"));

    info!("Contacting server at {}", url);
    fetch_id(&url).unwrap();
}
