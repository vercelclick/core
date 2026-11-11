use crate::backend::projects::passkeys::SavePasskeyWorkflow;
use crate::db;
use crate::db::queries::auth::CREATE_SESSION_QUERY;
use crate::routes::auth::register::BackendCreateUserRequest;
use secretpass_core::{InternalError, InternalResult, Passkey, Session, StatusCode, User};
use sqlx::{Postgres, Transaction};

// language=sql
const CREATE_USER_QUERY: &str = r#"
    INSERT INTO "Users" (id, name, email, key_salt) VALUES ($1, $2, $3, $4) RETURNING *
"#;

struct CreateUserWorkflow {
    request: BackendCreateUserRequest,
}

#[async_trait::async_trait]
impl db::TransactionOperation<(Session, User, Vec<Passkey>)> for CreateUserWorkflow {
    async fn execute(
        self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> InternalResult<(Session, User, Vec<Passkey>)> {
        let user: User = sqlx::query_as(CREATE_USER_QUERY)
            .bind(self.request.user_id)
            .bind(&self.request.user_name)
            .bind(&self.request.user_email)
            .bind(&self.request.user_salt)
            .fetch_one(&mut **tx)
            .await
            .map_err(|err| {
                InternalError::trace(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error creating user",
                    err,
                )
            })?;

        let passkey = SavePasskeyWorkflow {
            user_id: user.id,
            name: self.request.passkey_name.clone(),
            salt: self.request.passkey_salt.clone(),
            cred_id: self.request.passkey_cred_id.clone(),
            public_key: self.request.passkey_public_key.clone(),
            web_public_key: self.request.passkey_web_public_key.clone(),
        }
        .execute(tx)
        .await?;

        let session: Session = sqlx::query_as(CREATE_SESSION_QUERY)
            .bind(user.id)
            .fetch_one(&mut **tx)
            .await
            .map_err(|err| {
                InternalError::trace(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error establishing a new session",
                    err,
                )
            })?;

        let passkeys = vec![passkey];

        Ok((session, user, passkeys))
    }
}

pub async fn create_user(
    request: BackendCreateUserRequest,
) -> InternalResult<(Session, User, Vec<Passkey>)> {
    let result = db::with_transaction(CreateUserWorkflow { request }).await?;

    Ok(result)
}
