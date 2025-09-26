use crate::models::user::{RegisterRequest, LoginRequest, User};
use crate::models::sistem::Sistem;
use crate::models::verify_register::VerifyRegister;
use crate::models::profile::{ProfileRequest, Profile};
use crate::utils::token::{generate_token, store_refresh_token, remove_refresh_token};
use crate::db::DbPool;
use sqlx::{query, query_as};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, rand_core::OsRng, PasswordHash};
use rand::{distributions::Alphanumeric, Rng};
use redis::Client as RedisClient;
use chrono::{Utc, Duration};
use serde::Serialize;
use std::env;

use reqwest::Client as HttpClient;
use serde_json::json;

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
    // 1) Cek duplicate email (status = 2)
    let existing = query("SELECT id FROM users WHERE email = $1 AND status = 2")
        .bind(&req.email)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?;

    if existing.is_some() {
        return Err("Error! Email tersebut duplicate".to_string());
    }

    // 2) Ambil expired_days dari tabel sistem
    let sistem_row: Option<Sistem> = query_as::<_, Sistem>(
        "SELECT * FROM sistem WHERE nama = 'EXPIRED_REGISTER' LIMIT 1"
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;

    let expired_days = sistem_row
        .and_then(|s| s.value_int)
        .unwrap_or(30);

    let created_date = Utc::now();
    let expired_date = created_date + Duration::days(expired_days.into());

    // 3) Hash password (argon2)
    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(req.password.as_bytes(), &salt)
        .map_err(|e| e.to_string())?
        .to_string();

    let id_user = generate_random_id();

    // 4) Insert ke users
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
    .bind(&created_date.naive_utc())
    .bind(&expired_date.naive_utc())
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;

    // 5) Insert ke verify_register
    let id_verify = generate_random_id();
    let verify = query_as::<_, VerifyRegister>(
        "INSERT INTO verify_register (id, id_user, email, aktif, created_date) 
         VALUES ($1, $2, $3, 1, $4) 
         RETURNING *"
    )
    .bind(&id_verify)
    .bind(&id_user)
    .bind(&req.email)
    .bind(&created_date.naive_utc())
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;

    // 6) Kirim email verifikasi via SendGrid HTTP API (reqwest)
    let sendgrid_api_key = env::var("SENDGRID_API_KEY")
        .map_err(|_| "SENDGRID_API_KEY not set".to_string())?;

    let http = HttpClient::new();

    let verify_link = format!("http://185.14.92.144:3000/verify?token={}", &verify.id);
    let subject = "Aktivasi Akun Anda";
    let content_html = format!(
        "Halo {},<br><br>Terima kasih sudah mendaftar.<br>\
        Silakan klik link berikut untuk aktivasi akun Anda:<br>\
        <a href=\"{}\">Aktivasi Akun</a>",
        req.first_name, verify_link
    );

    // body sesuai spec /v3/mail/send
    let body = json!({
        "personalizations": [
            {
                "to": [
                    { "email": req.email, "name": format!("{} {}", req.first_name, req.last_name) }
                ],
                "subject": subject
            }
        ],
        "from": { "email": "yogachandraw@gmail.com", "name": "Admin" },
        "content": [
            { "type": "text/html", "value": content_html }
        ]
    });

    // kirim
    let resp = http.post("https://api.sendgrid.com/v3/mail/send")
        .bearer_auth(sendgrid_api_key)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Failed to send email request: {}", e))?;

    let status = resp.status(); // simpan status dulu
    let txt = resp.text().await.unwrap_or_else(|_| "<no-body>".to_string());

    if !status.is_success() {
        eprintln!("SendGrid send failed. status={} body={}", status, txt);
        // return Err(format!("Failed send verification email: {}", status));
    } else {
        println!("✅ Email verifikasi terkirim ke {}", req.email);
    }

    // 7) Return hasil
    Ok(RegisterResult { user, verify })
}


pub async fn aktivasi_user(pool: &DbPool, token: &str) -> Result<(), String> {
    // cek apakah token valid
    let existing = query("SELECT id FROM verify_register WHERE id = $1 AND aktif = 0")
        .bind(token)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?;

    if existing.is_some() {
        return Err("Error! Link aktivasi expired atau sudah tidak aktif.".to_string());
    } 

    // 2) Ambil expired_register dari tabel sistem
    let sistem_row: Option<Sistem> = query_as::<_, Sistem>(
        "SELECT * FROM sistem WHERE nama = 'EXPIRED_VERIFY_REGISTER' LIMIT 1"
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;

    let expired_minutes = sistem_row
        .and_then(|s| s.value_int)
        .unwrap_or(60); // default 60 menit kalau null

    // mencari data verifikasi user
    let user_verifikasi: Option<VerifyRegister> = query_as::<_, VerifyRegister>(
        "SELECT id, id_user, created_date, aktif FROM verify_register WHERE id = $1 AND aktif = 1"
    )
    .bind(token)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;

    let user_verifikasi = match user_verifikasi {
    Some(u) => u,
    None => return Err("Error! Link aktivasi tidak ditemukan.".to_string()),
};

    // Bandingkan waktu created_date dengan expired_minutes
    let now = chrono::Utc::now().naive_utc();
    let expired_time = user_verifikasi.created_date + Duration::minutes(expired_minutes as i64);

    if now > expired_time {
        return Err("Error! Link aktivasi expired.".to_string());
    }

    // update verifikasi_register status nonaktif
    query("UPDATE verify_register SET aktif = 0 WHERE id = $1")
        .bind(token)
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?;

    // update user status aktif
    query("UPDATE users SET aktif = 1 WHERE id = $1")
        .bind(&user_verifikasi.id_user)
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?;

    let id_profile = generate_random_id();

    // 4) Insert ke users
    let profile = query_as::<_, Profile>(
        "INSERT INTO profile (id, id_user, gender, no_telp, company, alamat, kelurahan, kecamatan, kota, provinsi, kode_pos) 
         VALUES ($1, $2, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) 
         RETURNING *"
    )
    .bind(&id_profile)
    .bind(&user_verifikasi.id_user)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;
    
    Ok(())
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
