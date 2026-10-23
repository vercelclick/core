mod auth;
pub mod types;

use crate::ApiState;
use crate::routes::auth::auth_router;
use axum::http::header;
use axum::http::{HeaderValue, Method};
use axum::{Router, http};
use tower_cookies::CookieManagerLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

const HOST_ORIGIN: &str = env!("UI_ORIGIN");

pub fn create_backend_app() -> Router<ApiState> {
    subscribe_tracing();

    let allowed_origin = HOST_ORIGIN.parse::<HeaderValue>().unwrap();
    let cors = CorsLayer::new()
        .allow_origin(allowed_origin)
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::ACCEPT,
            header::CONTENT_TYPE,
            header::ACCEPT_ENCODING,
            header::ACCEPT_ENCODING,
        ])
        .allow_private_network(true);

    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(|request: &axum::extract::Request| {
            tracing::info_span!(
                "http_request",
                method = ?request.method(),
                uri = ?request.uri()
            )
        })
        .on_response(
            |response: &http::Response<_>, latency: std::time::Duration, _span: &tracing::Span| {
                tracing::info!(
                    "Response generated with status: {:?} in {:?}",
                    response.status(),
                    latency
                );
            },
        );

    Router::new()
        .nest("/api/auth", auth_router())
        .layer(CookieManagerLayer::new())
        .layer(cors)
        .layer(trace_layer)
}

fn subscribe_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=debug"));

    // 2. Build the subscriber explicitly pointing to stdout
    tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer().with_writer(std::io::stdout), // Forces output to stdout
                                                       // .json() // Uncomment this line if you want structured JSON logs
        )
        .init();
}
