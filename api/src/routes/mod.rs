pub mod auth;
pub mod projects;
pub mod utils;

use crate::backend::{ApiState, ApiStateInner};
use crate::routes::auth::auth_router;
use crate::routes::auth::middleware::AuthLayer;
use crate::routes::projects::{project_routes, public_project_routes};
use crate::routes::utils::{add_version_header, health_endpoint, ping_endpoint};
use axum::http::header;
use axum::http::{HeaderValue, Method};
use axum::routing::{get, post};
use axum::{Router, http};
use click_core::constants::RP_ORIGIN;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

fn cors_layer() -> CorsLayer {
    let allowed_origin: HeaderValue = RP_ORIGIN.parse().unwrap();

    CorsLayer::new()
        .allow_origin(allowed_origin)
        .allow_credentials(false)
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
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT_ENCODING,
            header::ACCEPT_ENCODING,
        ])
        .allow_private_network(true)
}

pub fn build_api_router(
    state: ApiStateInner,
    additional_public_router: Option<Router<ApiState>>,
    additional_authenticated_router: Option<Router<ApiState>>,
) -> Router {
    subscribe_tracing();

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

    let state = Arc::new(state);

    let mut router =
        Router::new().nest("/api/v1/projects", project_routes().layer(AuthLayer::new()));

    if let Some(authenticated_router) = additional_authenticated_router {
        router = router.nest("/api/v1", authenticated_router.layer(AuthLayer::new()));
    }

    if let Some(public_router) = additional_public_router {
        router = router.nest("/api/v1", public_router);
    }

    router
        .nest("/api/v1/projects", public_project_routes())
        .nest("/api/v1/auth", auth_router())
        .route("/health", get(health_endpoint))
        .route("/ping", post(ping_endpoint))
        .layer(cors_layer())
        .layer(trace_layer)
        .layer(axum::middleware::from_fn(add_version_header))
        .with_state(state)
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
