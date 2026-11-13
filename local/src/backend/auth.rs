use crate::backend::challenge::get_challenge;
use click_core::enums::WebauthnChallengeKind;
use click_core::passkeys::authorize::PasskeyAuthorizationResult;
use click_core::{AuthSession, InternalError, InternalResult, StatusCode, caller};

pub async fn validate_passkey_auth(
    session: &AuthSession,
    auth_result: &PasskeyAuthorizationResult,
) -> InternalResult<()> {
    let challenge = get_challenge(WebauthnChallengeKind::PasskeyAuthorize, &session.user.email)
        .await
        .ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::CONFLICT,
                "Passkey challenge not found",
            )
        })?;

    let passkey = session
        .passkeys
        .iter()
        .find(|key| key.cred_id == auth_result.id && key.user_id == session.user.id)
        .ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::BAD_REQUEST,
                "Passkey did not match the user's known passkeys",
            )
        })?;

    auth_result.validate(&passkey.web_public_key, &challenge.value_hash)
}
