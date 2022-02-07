/// Example ppoprf randomness web service.
///
/// This wraps the ppoprf evaluation function in an Actix-Web
/// service application so it can be accessed over https.

use actix_web::{get, post, web};
use actix_web::middleware::Logger;
use env_logger::Env;
use log::info;

use curve25519_dalek::ristretto::CompressedRistretto;
use ppoprf::ppoprf;

use serde::{Serialize, Deserialize};

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

#[get("/")]
async fn index() -> &'static str {
    // Simple string to identify the server.
    concat!("STAR protocol randomness server.\n",
        "See https://arxiv.org/abs/2109.10074 for more information.\n")
}

#[post("/")]
async fn eval(server: web::Data<ppoprf::Server>, data: web::Json<EvalRequest>)
        -> web::Json<EvalResponse> {
    // Pass each point from the client through the ppoprf.
    let result = data.points.iter()
        .map(|p| server.eval(&p, 0, false))
        .collect();

    // Return the results.
    web::Json(EvalResponse {
        name: data.name.clone(),
        results: result,
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let host = "localhost";
    let port = 8080;

    env_logger::init_from_env(Env::default().default_filter_or("info"));
    info!("Server configured on {} port {}", host, port);

    // Actix webapp state cloned into each server thread.
    let test_mds = vec![vec!['t' as u8]];
    let server = ppoprf::Server::new(&test_mds);

    // Pass a factory closure to configure the server.
    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            // Register app state.
            .data(server.clone())
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
