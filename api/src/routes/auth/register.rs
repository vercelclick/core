use crate::api_types::HttpResponse;
use crate::utils::error_mapper;
use crate::{ApiState, CreateUserParams, SessionResponse, utils};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use reqwest::Client;
use secretpass_core::enums::OperationMode;
use std::sync::LazyLock;
use tower_cookies::cookie::SameSite;
use tower_cookies::{Cookie, Cookies};

static REQWEST_CLIENT: LazyLock<Client> = LazyLock::new(Client::new);

#[axum::debug_handler]
pub async fn create_user(
    State(state): State<ApiState>,
    cookies: Cookies,
    Json(params): Json<CreateUserParams>,
) -> HttpResponse<Json<SessionResponse>> {
    // No authentication needed for this call - for now
    // TODO: Add Captcha verification
    // TODO: Add passkey generation from registration response instead of receiving a ready passkey

    let result = if state.mode == OperationMode::Local {
        // Create a global client
        let response = REQWEST_CLIENT
            .post(utils::cloud_proxy_url("/api/auth/register"))
            .json(&params)
            .send()
            .await;

        let result = utils::parse_proxied_response::<SessionResponse>(response).await?;
        state
            .backend
            .record_session(result.user.clone(), result.session.clone())
            .await
            .map_err(error_mapper(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error recording session",
            ))?;

        result
    } else {
        state
            .backend
            .create_user(params)
            .await
            .map_err(error_mapper(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error creating user",
            ))?
    };

    let cookie = Cookie::build(("session_token", result.session.id.clone()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build();

    cookies.add(cookie);

    Ok(Json(result))
}
