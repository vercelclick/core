use crate::auth_session::create_backend_session_token;
use crate::backend::auth::passkey::retrieve_passkey_by_cred_id;
use crate::backend::auth::user::{get_user_by_email, get_user_by_id};
use crate::db;
use crate::db::workflows::session::CreateSessionWorkflow;
use crate::db::workflows::{
    UpsertWebauthnChallengeWorkflow, UseEmailChallengeWorkflow, UseWebauthnChallengeWorkflow,
};
use crate::db::{Transaction, TransactionOperation, with_transaction};
use async_trait::async_trait;
use axum::Json;
use axum::http::StatusCode;
use click_api::backend::auth::{
    AuthTokenResponse, EmailSignInRequest, PasskeySignInRequest, WebauthnChallengeAnonymousResponse,
};
use click_core::enums::{EmailChallengeKind, WebauthnChallengeKind};
use click_core::passkeys::authorize::PasskeyAuthorizationResult;
use click_core::{InternalError, InternalResult, WebauthnChallenge, caller};
use uuid::Uuid;

struct SignInWithEmailWorkflow {
    request: EmailSignInRequest,
}

#[async_trait]
impl TransactionOperation<String> for SignInWithEmailWorkflow {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<String> {
        let user = get_user_by_email(&mut **tx, self.request.email_address.clone())
            .await?
            .ok_or_else(|| {
                InternalError::new(caller!(), StatusCode::NOT_FOUND, "User not found")
            })?;

        UseEmailChallengeWorkflow {
            owner: self.request.email_address,
            kind: EmailChallengeKind::EmailSignIn,
            confirmation_code: self.request.confirmation_code,
        }
        .execute(tx)
        .await?;

        let (session, user, passkeys) = CreateSessionWorkflow { user }.execute(tx).await?;

        let token = create_backend_session_token(session, user, passkeys)?;

        Ok(token)
    }
}

pub async fn signin_with_email(
    Json(request): Json<EmailSignInRequest>,
) -> InternalResult<Json<AuthTokenResponse>> {
    let token = db::with_transaction(SignInWithEmailWorkflow { request }).await?;

    Ok(Json(AuthTokenResponse { token }))
}

struct SignInWithPasskeyWorkflow {
    owner: String,
    auth_result: PasskeyAuthorizationResult,
}

#[async_trait]
impl TransactionOperation<String> for SignInWithPasskeyWorkflow {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<String> {
        let passkey =
            retrieve_passkey_by_cred_id(tx, self.auth_result.id.clone(), self.auth_result.user_id)
                .await?
                .ok_or_else(|| {
                    InternalError::new(caller!(), StatusCode::NOT_FOUND, "Passkey not found")
                })?;
        let user = get_user_by_id(&mut **tx, self.auth_result.user_id)
            .await?
            .ok_or_else(|| {
                InternalError::new(caller!(), StatusCode::NOT_FOUND, "User not found")
            })?;

        UseWebauthnChallengeWorkflow {
            owner: self.owner,
            kind: WebauthnChallengeKind::PasskeySignIn,
            public_key: passkey.public_key,
            result: self.auth_result,
        }
        .execute(tx)
        .await?;

        let (session, user, passkeys) = CreateSessionWorkflow { user }.execute(tx).await?;

        let token = create_backend_session_token(session, user, passkeys)?;

        Ok(token)
    }
}

pub async fn signin_with_passkey(
    Json(request): Json<PasskeySignInRequest>,
) -> InternalResult<Json<AuthTokenResponse>> {
    let token = db::with_transaction(SignInWithPasskeyWorkflow {
        owner: request.owner,
        auth_result: request.auth_response,
    })
    .await?;

    Ok(Json(AuthTokenResponse { token }))
}

pub async fn signin_with_passkey_challenge()
-> InternalResult<Json<WebauthnChallengeAnonymousResponse>> {
    let owner = format!("anon-{}@click.temp", Uuid::now_v7());
    let (challenge, hash) = WebauthnChallenge::generate();

    with_transaction(UpsertWebauthnChallengeWorkflow {
        owner: owner.clone(),
        kind: WebauthnChallengeKind::PasskeySignIn,
        hash,
    })
    .await?;

    Ok(Json(WebauthnChallengeAnonymousResponse {
        challenge,
        owner,
    }))
}
