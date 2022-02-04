/// Example ppoprf randomness web service.
///
/// This wraps the ppoprf evaluation function in an Actix-Web
/// service application so it can be accessed over https.

use actix_web::{get, Responder};

#[get("/")]
async fn index() -> impl Responder {
    // Simple string to identify the server.
    concat!("STAR protocol randomness server.\n",
        "See https://arxiv.org/abs/2109.10074 for more information.\n")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let host = "localhost";
    let port = 8080;

    actix_web::HttpServer::new(|| {
        actix_web::App::new()
            .service(index)
    })
    .bind((host, port as u16))?
    .run()
    .await
}
