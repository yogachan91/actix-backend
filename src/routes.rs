use actix_web::web;
use crate::controllers::auth_controller::{register, login, logout, refresh_token};
use crate::middlewares::auth_middleware::AuthMiddleware;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/auth")
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/refresh", web::post().to(refresh_token))
            .service(
                web::scope("")
                    .wrap(AuthMiddleware) // proteksi hanya user login yang bisa logout
                    .route("/logout", web::post().to(logout))
            )
    );
}
