//! Example ppoprf randomness web service.
//!
//! This wraps the ppoprf evaluation function in an Actix-Web
//! service application so it can be accessed over https.
//!
//! To verify the example works, start the server in one terminal:
//! ```sh
//! cargo run --example server
//! ```
//!
//! In another terminal, verify the GET method returns a service
//! identification:
//! ```sh
//! curl --silent localhost:8080
//! ```
//!
//! Finally verify the POST method returns an altered point:
//! ```sh
//! curl --silent localhost:8080 \
//!     --header 'Content-Type: application/json' \
//!     --data '{"name":"Nested STAR", "points": [
//!         [226, 242, 174, 10, 106, 188, 78, 113,
//!          168, 132, 169, 97, 197, 0, 81, 95,
//!          88, 227, 11, 106, 165, 130, 221, 141,
//!          182, 166, 89, 69, 224, 141, 45, 118]]}'
//! ```

use actix_web::middleware::Logger;
use actix_web::{get, post, web};
use env_logger::Env;
use dotenv::dotenv;
use std::env;
use log::info;

use std::sync::{Arc, RwLock};

use curve25519_dalek::ristretto::CompressedRistretto;
use ppoprf::ppoprf;

use serde::{Deserialize, Serialize};

const DEFAULT_EPOCH_DURATION: u64 = 5;
const DEFAULT_MDS: &str = "116;117;118;119;120";
const EPOCH_DURATION_ENV_KEY: &str = "EPOCH_DURATION";
const MDS_ENV_KEY: &str = "METADATA_TAGS";

#[derive(Deserialize)]
struct EvalRequest {
    name: String,
    points: Vec<CompressedRistretto>,
}

#[derive(Serialize)]
struct EvalResponse {
    name: String,
    results: Vec<ppoprf::Evaluation>,
}

struct ServerState {
    prf_server: ppoprf::Server,
    md_idx: usize
}
type State = Arc<RwLock<ServerState>>;

#[get("/")]
async fn index() -> &'static str {
    // Simple string to identify the server.
    concat!(
        "STAR protocol randomness server.\n",
        "See https://arxiv.org/abs/2109.10074 for more information.\n"
    )
}

#[post("/")]
async fn eval(
    state: web::Data<State>,
    data: web::Json<EvalRequest>,
) -> web::Json<EvalResponse> {
    let state = state.read().unwrap();
    // Pass each point from the client through the ppoprf.
    let result = data
        .points
        .iter()
        .map(|p| state.prf_server.eval(&p, state.md_idx, false))
        .collect();

    // Return the results.
    web::Json(EvalResponse {
        name: data.name.clone(),
        results: result,
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let host = "localhost";
    let port = 8080;

    env_logger::init_from_env(Env::default().default_filter_or("info"));
    info!("Server configured on {} port {}", host, port);

    // Metadata tags marking each randomness epoch.
    let mds: Vec<Vec<u8>> = env::var(MDS_ENV_KEY)
        .unwrap_or(DEFAULT_MDS.to_string())
        .split(';')
        .map(|y| {
            y.split(',').map(|x| {
                x.parse().expect(
                    "Could not parse metadata tags. Must contain 8-bit unsigned values!"
                )
            }).collect()
        }).collect();

    // Time interval between puncturing each successive md.
    let epoch = std::time::Duration::from_secs(
        match env::var(EPOCH_DURATION_ENV_KEY) {
            Ok(val) => {
                val.parse().expect(
                    "Could not parse epoch duration. It must be a positive number!"
                )
            },
            Err(_) => DEFAULT_EPOCH_DURATION
        }
    );

    // Shared actix webapp state cloned into each server thread.
    // We use an RWLock to handle the infrequent puncture events.
    // Only read access is necessary to answer queries.
    let state = Arc::new(RwLock::new(ServerState {
        prf_server: ppoprf::Server::new(&mds),
        md_idx: 0
    }));

    // Spawn a background task.
    let background_state = state.clone();
    actix_web::rt::spawn(async move {
        log::info!("Spawned background epoch rotation task");
        // Wait for the end of an epoch.
        for md in &mds {
            actix_web::rt::time::delay_for(epoch).await;
            if let Ok(mut state) = background_state.write() {
                log::info!("Epoch rotation: puncturing '{:?}'", md);
                state.prf_server.puncture(md);
                state.md_idx += 1;
            }
            log::info!("Epoch rotation complete");
        }
    });

    // Pass a factory closure to configure the server.
    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            // Register app state.
            .data(state.clone())
            // Register routes.
            .service(index)
            .service(eval)
            // Add logging and other middleware.
            .wrap(Logger::default())
    })
    // Bind and start handling the requested address and port.
    .bind((host, port as u16))?
    .run()
    .await
}
