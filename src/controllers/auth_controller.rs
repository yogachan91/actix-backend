use actix_web::{web, HttpResponse, Responder, HttpRequest, HttpMessage};
use crate::services::auth_service::{register_user, login_user, logout_user, aktivasi_user};
use crate::db::DbPool;
use crate::models::user::{RegisterRequest, LoginRequest};
use crate::utils::token::{get_refresh_token, generate_token, Claims};
use serde_json::json;
use serde::Deserialize;
use jsonwebtoken::{decode, DecodingKey, Validation};
use redis::Client as RedisClient;

pub async fn register(pool: web::Data<DbPool>, req: web::Json<RegisterRequest>) -> impl Responder {
    match register_user(pool.get_ref(), req.into_inner()).await {
        Ok(result) => HttpResponse::Ok().json(json!({
            "message": "Berhasil Daftar, Mohon check di email anda untuk verifikasi akun.",
            "user_id": result.user.id,
            "verify_id": result.verify.id
        })),
        Err(e) => HttpResponse::BadRequest().json(json!({ "error": e })),
    }
}

pub async fn aktivasi_akun(
    pool: web::Data<DbPool>,
    path: web::Path<String>, // ambil token dari path
) -> impl Responder {
    let token = path.into_inner();

    match aktivasi_user(pool.get_ref(), &token).await {
        Ok(_) => HttpResponse::Ok().json(json!({
            "message": "Aktivasi akun berhasil, silakan login."
        })),
        Err(e) => HttpResponse::BadRequest().json(json!({
            "error": e
        })),
    }
}


pub async fn login(
    pool: web::Data<DbPool>,
    redis: web::Data<RedisClient>,
    req: web::Json<LoginRequest>
) -> impl Responder {
    match login_user(pool.get_ref(), redis.get_ref(), req.into_inner()).await {
        Ok((id, access, refresh)) => HttpResponse::Ok().json(json!({
            "access_token": access,
            "refresh_token": refresh,
            "id": id
        })),
        Err(e) => HttpResponse::Unauthorized().json(json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

pub async fn refresh_token(
    redis: web::Data<RedisClient>,
    req: web::Json<RefreshRequest>
) -> impl Responder {
    let token_data = decode::<Claims>(
        &req.refresh_token,
        &DecodingKey::from_secret(std::env::var("REFRESH_SECRET").unwrap().as_ref()),
        &Validation::default(),
    );

    if let Ok(data) = token_data {
        let user_id = data.claims.sub;
        if let Ok(Some(stored_token)) = get_refresh_token(redis.get_ref(), &user_id).await {
            if stored_token == req.refresh_token {
                let new_access = generate_token(&user_id, false);
                return HttpResponse::Ok().json(json!({ "access_token": new_access }));
            }
        }
    }
    HttpResponse::Unauthorized().json(json!({ "error": "Invalid refresh token" }))
}

pub async fn logout(
    redis: web::Data<RedisClient>,
    req: HttpRequest
) -> impl Responder {
    if let Some(claims) = req.extensions().get::<Claims>() {
        match logout_user(redis.get_ref(), &claims.sub).await {
            Ok(_) => HttpResponse::Ok().json(json!({ "message": "Logged out" })),
            Err(_) => HttpResponse::InternalServerError().json(json!({ "error": "Failed to logout" })),
        }
    } else {
        HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }))
    }
}
