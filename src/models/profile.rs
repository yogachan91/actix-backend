use serde::{Deserialize, Serialize};
use chrono::{NaiveDateTime};
use sqlx::FromRow;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Profile {
    pub id: String,
    pub id_user: String,
    pub gender: Option<String>,
    pub no_telp: Option<String>,
    pub company: Option<String>,
    pub alamat: Option<String>,
    pub kelurahan: Option<String>,
    pub kecamatan: Option<String>,
    pub kota: Option<String>,
    pub provinsi: Option<String>,
    pub kode_pos: Option<String>,
}

#[derive(Deserialize)]
pub struct ProfileRequest {
    pub id: String,
    pub id_user: String,
    pub gender: Option<String>,
    pub no_telp: Option<String>,
    pub company: Option<String>,
    pub alamat: Option<String>,
    pub kelurahan: Option<String>,
    pub kecamatan: Option<String>,
    pub kota: Option<String>,
    pub provinsi: Option<String>,
    pub kode_pos: Option<String>,
}
