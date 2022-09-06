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
//!     --data '{"name":"STAR", "points": [
//!         "4vKuCmq8TnGohKlhxQBRX1jjC2qlgt2NtqZZReCNLXY="
//!         ]}'
//! ```

use actix_web::middleware::Logger;
use actix_web::{
  error::ResponseError, get, http::StatusCode, post, web, HttpResponse,
};
use dotenvy::dotenv;
use env_logger::Env;
use log::{info, warn};

use std::collections::VecDeque;
use std::env;

use std::sync::{Arc, RwLock};

use ppoprf::ppoprf;

use derive_more::{Display, Error, From};
use serde::{Deserialize, Serialize};

const DEFAULT_EPOCH_DURATION: u64 = 5;
const DEFAULT_MDS: &str = "116;117;118;119;120";
const EPOCH_DURATION_ENV_KEY: &str = "EPOCH_DURATION";
const MDS_ENV_KEY: &str = "METADATA_TAGS";

#[derive(Deserialize)]
struct EvalRequest {
  name: String,
  points: Vec<ppoprf::Point>,
}

#[derive(Serialize)]
struct EvalResponse {
  name: String,
  results: Vec<ppoprf::Evaluation>,
}

struct ServerState {
  prf_server: ppoprf::Server,
  active_md: u8,
  future_mds: VecDeque<u8>,
}
type State = Arc<RwLock<ServerState>>;

#[derive(Debug, Error, From, Display)]
enum ServerError {
  #[display(fmt = "PPRF error: {}", _0)]
  Pprf(ppoprf::PPRFError),
}

#[derive(Serialize)]
struct ServerErrorResponse {
  error: String,
}

impl ResponseError for ServerError {
  fn error_response(&self) -> HttpResponse {
    HttpResponse::build(self.status_code()).json(ServerErrorResponse {
      error: format!("{}", self),
    })
  }

  fn status_code(&self) -> StatusCode {
    match *self {
      ServerError::Pprf(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
  }
}

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
) -> Result<web::Json<EvalResponse>, ServerError> {
  let state = state.read().unwrap();

  // Pass each point from the client through the ppoprf.
  let result: Result<Vec<ppoprf::Evaluation>, ppoprf::PPRFError> = data
    .points
    .iter()
    .map(|p| state.prf_server.eval(p, state.active_md, false))
    .collect();

  // Return the results.
  Ok(web::Json(EvalResponse {
    name: data.name.clone(),
    results: result?,
  }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
  dotenv().ok();

  let host = "localhost";
  let port = 8080;

  env_logger::init_from_env(Env::default().default_filter_or("info"));
  info!("Server configured on {} port {}", host, port);

  // Metadata tags marking each randomness epoch.
  let mds_str = match env::var(MDS_ENV_KEY) {
    Ok(val) => val,
    Err(_) => {
      info!(
        "{} env var not defined, using default: {}",
        MDS_ENV_KEY, DEFAULT_MDS
      );
      DEFAULT_MDS.to_string()
    }
  };
  let mds: Vec<u8> = mds_str
    .split(';')
    .map(|y| {
      y.parse().expect(
        "Could not parse metadata tags. Must contain 8-bit unsigned values!",
      )
    })
    .collect();

  // Time interval between puncturing each successive md.
  let epoch =
    std::time::Duration::from_secs(match env::var(EPOCH_DURATION_ENV_KEY) {
      Ok(val) => val.parse().expect(
        "Could not parse epoch duration. It must be a positive number!",
      ),
      Err(_) => {
        info!(
          "{} env var not defined, using default: {} seconds",
          EPOCH_DURATION_ENV_KEY, DEFAULT_EPOCH_DURATION
        );
        DEFAULT_EPOCH_DURATION
      }
    });

  // Shared actix webapp state cloned into each server thread.
  // We use an RWLock to handle the infrequent puncture events.
  // Only read access is necessary to answer queries.
  let state = Arc::new(RwLock::new(ServerState {
    prf_server: ppoprf::Server::new(mds.clone()).unwrap(),
    active_md: mds[0],
    future_mds: VecDeque::from(mds[1..].to_vec()),
  }));
  info!("PPOPRF initialized with epoch metadata tags {:?}", &mds);

  // Spawn a background task.
  let background_state = state.clone();
  actix_web::rt::spawn(async move {
    info!(
      "Background task will rotate epoch every {} seconds",
      epoch.as_secs()
    );
    // Loop over the list of configured epoch metadata tags.
    for &md in &mds {
      info!(
        "Epoch tag now '{:?}'; next rotation in {} seconds",
        md,
        epoch.as_secs()
      );
      // Wait for the end of an epoch.
      actix_web::rt::time::sleep(epoch).await;
      if let Ok(mut state) = background_state.write() {
        info!("Epoch rotation: puncturing '{:?}'", md);
        state.prf_server.puncture(md).unwrap();
        let new_md = state.future_mds.pop_front().unwrap();
        state.active_md = new_md;
      }
    }
    warn!("All epoch tags punctured! No further evaluations possible.");
  });

  // Pass a factory closure to configure the server.
  let server_state = web::Data::new(state.clone());
  actix_web::HttpServer::new(move || {
    actix_web::App::new()
      // Register app state.
      .app_data(server_state.clone())
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
