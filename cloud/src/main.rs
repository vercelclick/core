mod backend;
pub mod db;

use backend::CloudBackendProvider;
use secretpass_api::{ApiState, create_backend_app};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let pool = sqlx::PgPool::connect("").await.unwrap();

    let provider = CloudBackendProvider::new(pool);

    let state = ApiState {
        backend: Arc::new(provider),
    };

    let app = create_backend_app().with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();

    axum::serve(listener, app).await.unwrap();
}
