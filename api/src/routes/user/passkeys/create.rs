use crate::routes::auth::register::{
    PasskeyCreateValidationRequest, validate_passkey_creation_details,
};
use crate::utils::CloudProxy;
use crate::{ApiState, SessionPackage};
use axum::extract::State;
use axum::{Extension, Json};
use secretpass_core::passkeys::create::PasskeyCreationResult;
use secretpass_core::passkeys::public_key::PublicKeyGenerateResult;
use secretpass_core::{InternalResult, Passkey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreatePasskeyRequest {
    name: String,
    confirmation_code: String,
    create_response: PasskeyCreationResult,
    public_key_result: PublicKeyGenerateResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreatePasskeyResponse {
    passkey: Passkey,
}

pub async fn create_passkey_handler(
    State(state): State<ApiState>,
    Extension(proxy): Extension<CloudProxy>,
    Extension(package): Extension<Arc<SessionPackage>>,
    Json(request): Json<CreatePasskeyRequest>,
) -> InternalResult<Json<CreatePasskeyResponse>> {
    if proxy.is_local() {
        let result: CreatePasskeyResponse = proxy.send_json(&request).await?;

        let mut passkeys = (*package.passkeys).clone();

        passkeys.push(result.passkey.clone());
        state
            .backend
            .record_session(SessionPackage {
                user: package.user.clone(),
                passkeys: Arc::new(passkeys),
                session: package.session.clone(),
            })
            .await?;

        return Ok(Json(result));
    }

    let rp_config = state.get_rp_config(proxy.is_proxied());

    let (cred_id, web_public_key) = validate_passkey_creation_details(
        false,
        &state,
        rp_config,
        PasskeyCreateValidationRequest {
            create_result: request.create_response,
            email_address: package.user.email.clone(),
            auth_result: request.public_key_result.auth_response.clone(),
            user_id: package.user.id,
            confirmation_code: request.confirmation_code,
        },
    )
    .await?;

    let passkey = state
        .backend
        .save_passkey(
            &package.user,
            rp_config.passkey_type,
            request.name,
            cred_id,
            web_public_key,
            request.public_key_result,
        )
        .await?;

    Ok(Json(CreatePasskeyResponse { passkey }))
}
