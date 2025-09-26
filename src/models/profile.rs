use serde::{Deserialize, Serialize};
use chrono::{NaiveDateTime};
use sqlx::FromRow;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Profile {
    pub id: String,
    pub id_user: String,
    pub gender: String,
    pub no_telp: String,
    pub company: String,
    pub alamat: String,
    pub kelurahan: String,
    pub kecamatan: String,
    pub kota: String,
    pub provinsi: String,
    pub koda_pos: String,
}

#[derive(Deserialize)]
pub struct ProfileRequest {
    pub id: String,
    pub id_user: String,
    pub gender: String,
    pub no_telp: String,
    pub company: String,
    pub alamat: String,
    pub kelurahan: String,
    pub kecamatan: String,
    pub kota: String,
    pub provinsi: String,
    pub koda_pos: String,
}
