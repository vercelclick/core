use crate::backend::auth::passkey::retrieve_passkey_by_cred_id;
use crate::db::workflows::UseWebauthnChallengeWorkflow;
use crate::db::{Transaction, TransactionOperation};
use async_trait::async_trait;
use click_core::enums::WebauthnChallengeKind;
use click_core::passkeys::authorize::PasskeyAuthorizationResult;
use click_core::passkeys::create::PasskeyCreationResult;
use click_core::{InternalError, InternalResult, StatusCode, WebauthnChallenge, caller};
use std::sync::Arc;
use uuid::Uuid;

pub struct NewPasskeyValidationWorkflow {
    pub kind: WebauthnChallengeKind,
    pub user_id: Uuid,
    pub email_address: String,
    pub create_result: PasskeyCreationResult,
    pub auth_result: Arc<PasskeyAuthorizationResult>,
}

#[async_trait]
impl TransactionOperation<(String, String)> for NewPasskeyValidationWorkflow {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<(String, String)> {
        let challenge: Option<WebauthnChallenge> = sqlx::query_as(r#"SELECT * FROM "WebauthnChallenge" WHERE kind=$1 AND owner=$2 AND expires_on >= now()"#, )
            .bind(self.kind)
            .bind(&self.email_address)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|err| {
                InternalError::trace(caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Internal error getting {} challenge", self.kind),
                    err,
                )
            })?;

        let challenge = challenge.ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::NOT_FOUND,
                &format!("{} challenge not found", self.kind),
            )
        })?;

        let (passkey_cred_id, passkey_public_key) = self
            .create_result
            .response
            .validate(&challenge.value_hash)?;

        UseWebauthnChallengeWorkflow {
            kind: self.kind,
            owner: self.email_address,
            result: self.auth_result,
            public_key: passkey_public_key.clone(),
        }
        .execute(tx)
        .await?;

        Ok((passkey_cred_id, passkey_public_key))
    }
}

pub struct PasskeyValidationWorkflow {
    pub owner: String,
    pub kind: WebauthnChallengeKind,
    pub auth_result: Arc<PasskeyAuthorizationResult>,
}

#[async_trait]
impl TransactionOperation<Uuid> for PasskeyValidationWorkflow {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<Uuid> {
        let passkey =
            retrieve_passkey_by_cred_id(tx, self.auth_result.id.clone(), self.auth_result.user_id)
                .await?
                .ok_or_else(|| {
                    InternalError::new(caller!(), StatusCode::NOT_FOUND, "Passkey not found")
                })?;

        UseWebauthnChallengeWorkflow {
            kind: self.kind,
            owner: self.owner,
            public_key: passkey.web_public_key,
            result: self.auth_result,
        }
        .execute(tx)
        .await
    }
}
