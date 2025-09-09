mod db;
mod config;
mod models;
mod controllers;
mod services;
mod utils;
mod routes;
mod middlewares;

use actix_web::{App, HttpServer, web, http};
use actix_cors::Cors;
use dotenvy::dotenv;
use db::{get_db_pool, get_redis_client};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();
    let pool = get_db_pool().await;
    let redis_client = get_redis_client();

    HttpServer::new(move || {
        App::new()
            .wrap(
                Cors::default()
                    .allowed_origin("http://185.14.92.144:3000/") // asal Next.js
                    .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
                    .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
                    .allowed_header(http::header::CONTENT_TYPE)
                    .supports_credentials()
            )
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(redis_client.clone()))
            .configure(routes::config)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
