use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration};
use std::env;
use redis::AsyncCommands;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

/// Generate JWT (Access Token atau Refresh Token)
pub fn generate_token(user_id: &str, is_refresh: bool) -> String {
    let secret = if is_refresh {
        env::var("REFRESH_SECRET").unwrap()
    } else {
        env::var("JWT_SECRET").unwrap()
    };

    let expiration = if is_refresh { 60 * 60 * 24 * 7 } else { 60 * 60 }; // refresh 7 hari, access 1 jam
    let claims = Claims {
        sub: user_id.to_string(),
        exp: (Utc::now() + Duration::seconds(expiration)).timestamp() as usize,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref())).unwrap()
}

/// Simpan refresh token di Redis
pub async fn store_refresh_token(redis: &redis::Client, user_id: &str, token: &str) -> redis::RedisResult<()> {
    let mut conn = redis.get_multiplexed_async_connection().await?;
    // Simpan token dengan key "refresh_token:<user_id>" selama 7 hari
    conn.set_ex(format!("refresh_token:{}", user_id), token, 60*60*24*7).await
}

/// Ambil refresh token dari Redis
pub async fn get_refresh_token(redis: &redis::Client, user_id: &str) -> redis::RedisResult<Option<String>> {
    let mut conn = redis.get_multiplexed_async_connection().await?;
    conn.get(format!("refresh_token:{}", user_id)).await
}

/// Hapus refresh token (logout)
pub async fn remove_refresh_token(redis: &redis::Client, user_id: &str) -> redis::RedisResult<()> {
    let mut conn = redis.get_multiplexed_async_connection().await?;
    conn.del(format!("refresh_token:{}", user_id)).await
}
