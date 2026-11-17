mod auth_session;
mod backend;
pub mod db;
pub mod emails;
pub mod routes;
pub mod workfows;

use crate::db::DB_POOL;
use crate::routes::{cloud_routes, public_cloud_routes};
use backend::CloudBackendProvider;
use click_api::backend::ApiStateInner;
use click_api::build_api_router;
use std::env;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Load .env file if present; ignore error if missing in production
    dotenvy::dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL not defined");
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();

    DB_POOL
        .set(pool)
        .expect("Database pool already initialized");

    let backend = CloudBackendProvider();

    let state = ApiStateInner::new(Arc::new(backend));

    let app = build_api_router(state, Some(public_cloud_routes()), Some(cloud_routes()));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();

    axum::serve(listener, app).await.unwrap();
}
