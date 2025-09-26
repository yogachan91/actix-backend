use actix_web::web;
use crate::controllers::auth_controller::{aktivasi_akun, login, logout, refresh_token, register};
use crate::middlewares::auth_middleware::AuthMiddleware;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/auth")
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/aktivasi-user/{token}", web::get().to(aktivasi_akun))
            .route("/refresh", web::post().to(refresh_token))
            .service(
                web::scope("")
                    .wrap(AuthMiddleware) // proteksi hanya user login yang bisa logout
                    .route("/logout", web::post().to(logout))
            )
    );
}
