use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Sistem {
    pub id: String,
    pub nama: String,
    pub value_int: Option<i64>,
    pub value_char: Option<String>,
}
