use secretpass_api::backend::ApiState;
use secretpass_core::enums::ChallengeKind;
use secretpass_core::passkeys::authorize::PasskeyAuthorizationResult;
use secretpass_core::passkeys::create::PasskeyCreationResult;
use secretpass_core::{InternalError, InternalResult, StatusCode};
use uuid::Uuid;

pub struct PasskeyCreateValidationRequest {
    pub user_id: Uuid,
    pub email_address: String,
    pub confirmation_code: String,
    pub create_result: PasskeyCreationResult,
    pub auth_result: PasskeyAuthorizationResult,
}
pub async fn validate_passkey_creation_details(
    is_signup: bool,
    state: &ApiState,
    request: PasskeyCreateValidationRequest,
) -> InternalResult<(String, String)> {
    let email_challenge = state
        .backend
        .get_pending_challenge(
            if is_signup {
                ChallengeKind::EmailSignup
            } else {
                ChallengeKind::EmailAuthorize
            },
            &request.email_address,
        )
        .await?
        .ok_or_else(|| InternalError::new(StatusCode::NOT_FOUND, "Email challenge not found"))?;

    if !email_challenge.verify_challenge(request.confirmation_code) {
        return Err(InternalError::new(
            StatusCode::FORBIDDEN,
            "Invalid email confirmation code",
        ));
    }

    let passkey_challenge = state
        .backend
        .get_pending_challenge(
            if is_signup {
                ChallengeKind::PasskeySignup
            } else {
                ChallengeKind::PasskeyCreate
            },
            &request.email_address,
        )
        .await?
        .ok_or_else(|| InternalError::new(StatusCode::NOT_FOUND, "Passkey challenge not found"))?;

    let (passkey_cred_id, passkey_public_key) = request
        .create_result
        .response
        .validate(&passkey_challenge.value_hash)?;

    request.auth_result.validate(
        request.user_id,
        &passkey_public_key,
        &passkey_challenge.value_hash,
    )?;

    Ok((passkey_cred_id, passkey_public_key))
}
