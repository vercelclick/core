mod backend;
pub mod db;

use backend::CloudBackendProvider;
use secretpass_api::{ApiState, create_backend_app};
use secretpass_core::enums::OperationMode;
use std::env;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL not defined");
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();

    let provider = CloudBackendProvider::new(pool);

    let state = ApiState {
        mode: OperationMode::Cloud,
        backend: Arc::new(provider),
    };

    let app = create_backend_app().with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();

    axum::serve(listener, app).await.unwrap();
}
