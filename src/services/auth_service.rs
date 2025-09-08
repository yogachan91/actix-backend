use crate::models::user::{RegisterRequest, LoginRequest, User};
use crate::models::sistem::Sistem;
use crate::models::verify_register::VerifyRegister; // ✅ import verify_register
use crate::utils::token::{generate_token, store_refresh_token, remove_refresh_token};
use crate::db::DbPool;
use sqlx::{query, query_as};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, rand_core::OsRng, PasswordHash};
use rand::{distributions::Alphanumeric, Rng};
use redis::Client as RedisClient;
use chrono::{Utc, Duration};
use serde::Serialize; // ✅ untuk return struct

#[derive(Debug, Serialize)]
pub struct RegisterResult {
    pub user: User,
    pub verify: VerifyRegister,
}

fn generate_random_id() -> String {
    let random: String = (0..4).map(|_| rand::thread_rng().sample(Alphanumeric) as char).collect();
    let random2: String = (0..4).map(|_| rand::thread_rng().sample(Alphanumeric) as char).collect();
    let random3: String = (0..4).map(|_| rand::thread_rng().sample(Alphanumeric) as char).collect();
    let random4: String = (0..4).map(|_| rand::thread_rng().sample(Alphanumeric) as char).collect();
    format!("{}-{}-{}-{}", random, random2, random3, random4)
}

pub async fn register_user(pool: &DbPool, req: RegisterRequest) -> Result<RegisterResult, String> {
    // ✅ Cek duplicate email
    let existing = query("SELECT id FROM users WHERE email = $1 AND status = 2")
        .bind(&req.email)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?;

    if existing.is_some() {
        return Err("Error! Email tersebut duplicate".to_string());
    }

    // ✅ Ambil expired_days dari tabel sistem
    let sistem_row: Option<Sistem> = query_as::<_, Sistem>(
        "SELECT * FROM sistem WHERE nama = 'EXPIRED_REGISTER' LIMIT 1"
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;

    let expired_days = sistem_row
        .and_then(|s| s.value_int)
        .unwrap_or(30); // default 30 hari

    let created_date = Utc::now();
    let expired_date = created_date + Duration::days(expired_days.into());

    // ✅ Hash password
    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(req.password.as_bytes(), &salt)
        .map_err(|e| e.to_string())?
        .to_string();

    let id_user = generate_random_id();

    // ✅ Insert ke users
    let user = query_as::<_, User>(
        "INSERT INTO users (id, first_name, last_name, email, password, status, aktif, created_date, expired_date) 
         VALUES ($1, $2, $3, $4, $5, 2, 0, $6, $7) 
         RETURNING *"
    )
    .bind(&id_user)
    .bind(&req.first_name)
    .bind(&req.last_name)
    .bind(&req.email)
    .bind(&hashed_password)
    .bind(&created_date)
    .bind(&expired_date)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;

    // ✅ Insert ke verify_register
    let id_verify = generate_random_id();
    let verify = query_as::<_, VerifyRegister>(
        "INSERT INTO verify_register (id, id_user, email, aktif, created_date) 
         VALUES ($1, $2, $3, 1, $4) 
         RETURNING *"
    )
    .bind(&id_verify)
    .bind(&id_user)
    .bind(&req.email)
    .bind(&created_date)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;

    Ok(RegisterResult { user, verify })
}

pub async fn login_user(
    pool: &DbPool,
    redis: &RedisClient,
    req: LoginRequest
) -> Result<(String, String), String> {
    let user = query_as::<_, User>("SELECT * FROM users WHERE email = $1 AND status = 1")
        .bind(&req.email)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("Invalid email or password")?;

    let parsed_hash = PasswordHash::new(&user.password).map_err(|e| e.to_string())?;
    if Argon2::default()
        .verify_password(req.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return Err("Invalid email or password".into());
    }

    let access_token = generate_token(&user.id, false);
    let refresh_token = generate_token(&user.id, true);

    store_refresh_token(redis, &user.id, &refresh_token)
        .await
        .map_err(|e| e.to_string())?;

    Ok((access_token, refresh_token))
}

pub async fn logout_user(redis: &RedisClient, user_id: &str) -> Result<(), String> {
    remove_refresh_token(redis, user_id)
        .await
        .map_err(|e| e.to_string())
}
