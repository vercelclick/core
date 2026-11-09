use crate::db::queries::auth::{CREATE_PASSKEY_QUERY, CREATE_SESSION_QUERY};
use secretpass_api::SessionPackage;
use secretpass_api::auth::BackendCreateUserRequest;
use secretpass_core::{InternalError, InternalResult, Passkey, Session, StatusCode, User, source};
use sqlx::PgPool;
use std::sync::Arc;

// language=sql
const CREATE_USER_QUERY: &str = r#"
    INSERT INTO "Users" (id, name, email, key_salt) VALUES ($1, $2, $3, $4) RETURNING *
"#;

pub async fn create_user(
    pool: &PgPool,
    request: BackendCreateUserRequest,
) -> InternalResult<SessionPackage> {
    let mut tx = pool.begin().await.map_err(|err| {
        InternalError::trace(
            source!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error establishing a transaction",
            err,
        )
    })?;

    let user: User = sqlx::query_as(CREATE_USER_QUERY)
        .bind(request.user_id)
        .bind(&request.user_name)
        .bind(&request.user_email)
        .bind(&request.user_salt)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| {
            InternalError::trace(
                source!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error creating user",
                err,
            )
        })?;

    let passkey: Passkey = sqlx::query_as(CREATE_PASSKEY_QUERY)
        .bind(user.id)
        .bind(&request.passkey_name)
        .bind(&request.passkey_cred_id)
        .bind(&request.passkey_salt)
        .bind(&request.passkey_public_key)
        .bind(&request.passkey_web_public_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| {
            InternalError::trace(
                source!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error creating passkey",
                err,
            )
        })?;

    let session: Session = sqlx::query_as(CREATE_SESSION_QUERY)
        .bind(user.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| {
            InternalError::trace(
                source!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error establishing a new session",
                err,
            )
        })?;

    tx.commit().await.map_err(|err| {
        InternalError::trace(
            source!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error committing user creation",
            err,
        )
    })?;

    let passkeys = vec![passkey];
    let result = SessionPackage {
        user: Arc::new(user),
        session: Arc::new(session),
        passkeys: Arc::new(passkeys),
    };
    Ok(result)
}
