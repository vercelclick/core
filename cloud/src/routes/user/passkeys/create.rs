use crate::auth_session::create_backend_session_token;
use crate::backend::projects::passkeys::SavePasskeyWorkflow;
use crate::db;
use crate::db::workflows::session::CreateSessionWorkflow;
use crate::db::workflows::{UpsertWebauthnChallengeWorkflow, UseEmailChallengeWorkflow};
use crate::db::{Transaction, TransactionOperation, with_transaction};
use crate::workfows::passkeys::NewPasskeyValidationWorkflow;
use async_trait::async_trait;
use axum::{Extension, Json};
use click_api::backend::auth::{AuthTokenResponse, WebauthnChallengeResponse};
use click_core::enums::{EmailChallengeKind, WebauthnChallengeKind};
use click_core::passkeys::authorize::PasskeyAuthorizationResult;
use click_core::passkeys::create::PasskeyCreationResult;
use click_core::{AuthSession, InternalResult, User, WebauthnChallenge};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreatePasskeyRequest {
    name: String,
    salt: String,
    confirmation_code: String,
    create_result: PasskeyCreationResult,
    public_key: String,
    auth_result: PasskeyAuthorizationResult,
}

struct CreatePasskeyWorkflow {
    user: User,
    request: CreatePasskeyRequest,
}

#[async_trait]
impl TransactionOperation<String> for CreatePasskeyWorkflow {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<String> {
        UseEmailChallengeWorkflow {
            owner: self.user.email.clone(),
            kind: EmailChallengeKind::EmailAuthorize,
            confirmation_code: self.request.confirmation_code.clone(),
        }
        .execute(tx)
        .await?;

        let (cred_id, web_public_key) = NewPasskeyValidationWorkflow {
            kind: WebauthnChallengeKind::PasskeyCreate,
            user_id: self.user.id,
            email_address: self.user.email.clone(),
            create_result: self.request.create_result,
            auth_result: self.request.auth_result,
        }
        .execute(tx)
        .await?;

        SavePasskeyWorkflow {
            public_key: self.request.public_key,
            name: self.request.name,
            user_id: self.user.id,
            salt: self.request.salt,
            cred_id,
            web_public_key,
        }
        .execute(tx)
        .await?;

        let (session, user, passkeys) = CreateSessionWorkflow { user: self.user }
            .execute(tx)
            .await?;

        create_backend_session_token(session, user, passkeys)
    }
}

pub async fn passkey_create_handler(
    Extension(auth_session): Extension<Arc<AuthSession>>,
    Json(request): Json<CreatePasskeyRequest>,
) -> InternalResult<Json<AuthTokenResponse>> {
    let token = db::with_transaction(CreatePasskeyWorkflow {
        user: auth_session.user.clone(),
        request,
    })
    .await?;

    Ok(Json(AuthTokenResponse { token }))
}
pub async fn passkey_create_challenge(
    Extension(auth_session): Extension<Arc<AuthSession>>,
) -> InternalResult<Json<WebauthnChallengeResponse>> {
    let (challenge, hash) = WebauthnChallenge::generate();

    with_transaction(UpsertWebauthnChallengeWorkflow {
        owner: auth_session.user.email.clone(),
        kind: WebauthnChallengeKind::PasskeySignIn,
        hash,
    })
    .await?;

    Ok(Json(WebauthnChallengeResponse { challenge }))
}
