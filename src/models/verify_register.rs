use serde::{Deserialize, Serialize};
use chrono::{NaiveDateTime};
use sqlx::FromRow;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct VerifyRegister {
    pub id: String,
    pub id_user: String,
    pub email: String,
    pub aktif: i64,
    pub created_date: NaiveDateTime,  // ✅ wajib ada saat insert
}
