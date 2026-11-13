use crate::auth_session::create_backend_session_token;
use crate::backend::auth::user::{get_user_by_email, get_user_by_id};
use crate::db;
use crate::db::workflows::session::CreateSessionWorkflow;
use crate::db::workflows::{UpsertWebauthnChallengeWorkflow, UseEmailChallengeWorkflow};
use crate::db::{Transaction, TransactionOperation, with_transaction};
use crate::workfows::passkeys::PasskeyValidationWorkflow;
use async_trait::async_trait;
use axum::Json;
use axum::http::StatusCode;
use click_api::backend::auth::{
    AuthTokenResponse, EmailSignInRequest, PasskeySignInRequest, WebauthnChallengeAnonymousResponse,
};
use click_core::enums::{EmailChallengeKind, WebauthnChallengeKind};
use click_core::passkeys::authorize::PasskeyAuthorizationResult;
use click_core::{InternalError, InternalResult, WebauthnChallenge, caller};
use std::sync::Arc;
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
    auth_result: Arc<PasskeyAuthorizationResult>,
}

#[async_trait]
impl TransactionOperation<String> for SignInWithPasskeyWorkflow {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<String> {
        let user_id = PasskeyValidationWorkflow {
            owner: self.owner,
            auth_result: self.auth_result,
            kind: WebauthnChallengeKind::PasskeySignIn,
        }
        .execute(tx)
        .await?;

        let user = get_user_by_id(&mut **tx, user_id).await?.ok_or_else(|| {
            InternalError::new(caller!(), StatusCode::NOT_FOUND, "User not found")
        })?;

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
