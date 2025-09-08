use sqlx::{Pool, Postgres};
use std::env;
use redis::Client as RedisClient;

pub type DbPool = Pool<Postgres>;

pub async fn get_db_pool() -> DbPool {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set");
    sqlx::PgPool::connect(&database_url).await.expect("Failed to connect to DB")
}

pub fn get_redis_client() -> RedisClient {
    let redis_url = env::var("REDIS_URL").unwrap_or("redis://127.0.0.1/".to_string());
    RedisClient::open(redis_url).expect("Failed to connect to Redis")
}