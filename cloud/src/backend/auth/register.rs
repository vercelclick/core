use crate::auth_session::create_backend_session_token;
use crate::backend::projects::passkeys::SavePasskeyWorkflow;
use crate::db;
use crate::routes::auth::signup::SignupRequest;
use crate::workfows::passkeys::NewPasskeyValidationWorkflow;
use click_core::enums::WebauthnChallengeKind;
use click_core::{InternalError, InternalResult, Session, StatusCode, User, caller};
use sqlx::{Postgres, Transaction};

pub struct CreateUserWorkflow {
    pub request: SignupRequest,
}

#[async_trait::async_trait]
impl db::TransactionOperation<String> for CreateUserWorkflow {
    async fn execute(self, tx: &mut Transaction<'_, Postgres>) -> InternalResult<String> {
        let user: User = sqlx::query_as(r#"INSERT INTO "Users" (id, name, email, key_salt) VALUES ($1, $2, $3, $4) RETURNING *"#)
            .bind(self.request.id)
            .bind(&self.request.name)
            .bind(self.request.email.to_lowercase())
            .bind(&self.request.user_salt)
            .fetch_one(&mut **tx)
            .await
            .map_err(|err| {
                InternalError::trace(caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error creating user",
                    err,
                )
            })?;

        let (cred_id, web_public_key) = NewPasskeyValidationWorkflow {
            kind: WebauthnChallengeKind::PasskeySignup,
            user_id: self.request.id,
            email_address: self.request.email,
            create_result: self.request.passkey_result,
            auth_result: self.request.auth_result,
        }
        .execute(tx)
        .await?;

        let passkey = SavePasskeyWorkflow {
            user_id: user.id,
            name: self.request.passkey_name.clone(),
            salt: self.request.passkey_salt.clone(),
            cred_id,
            public_key: self.request.public_key,
            web_public_key,
        }
        .execute(tx)
        .await?;

        let session: Session =
            sqlx::query_as(r#"INSERT INTO "Sessions" (user_id) VALUES ($1) RETURNING *"#)
                .bind(user.id)
                .fetch_one(&mut **tx)
                .await
                .map_err(|err| {
                    InternalError::trace(
                        caller!(),
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal error establishing a new session",
                        err,
                    )
                })?;

        let passkeys = vec![passkey];

        create_backend_session_token(session, user, passkeys)
    }
}
