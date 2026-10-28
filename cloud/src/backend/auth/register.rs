use crate::db::queries::auth::{CREATE_PASSKEY_QUERY, CREATE_SESSION_QUERY};
use secretpass_api::SessionPackage;
use secretpass_api::auth::BackendCreateUserRequest;
use secretpass_core::{Passkey, Session, User};
use sqlx::PgPool;
use std::sync::Arc;

// language=sql
const CREATE_USER_QUERY: &str = r#"
    INSERT INTO "Users" (id, name, email) VALUES ($1, $2, $3) RETURNING *
"#;

pub async fn create_user(
    pool: &PgPool,
    request: BackendCreateUserRequest,
) -> anyhow::Result<SessionPackage> {
    let mut tx = pool.begin().await?;

    let user: User = sqlx::query_as(CREATE_USER_QUERY)
        .bind(request.user_id)
        .bind(&request.user_name)
        .bind(&request.user_email)
        .fetch_one(&mut *tx)
        .await?;

    let passkey: Passkey = sqlx::query_as(CREATE_PASSKEY_QUERY)
        .bind(request.passkey_id)
        .bind(user.id)
        .bind(&request.passkey_name)
        .bind(&request.passkey_cred_id)
        .bind(request.passkey_type)
        .bind(&request.passkey_ecc)
        .bind(&request.passkey_kem)
        .bind(&request.passkey_public_key)
        .fetch_one(&mut *tx)
        .await?;

    let session: Session = sqlx::query_as(CREATE_SESSION_QUERY)
        .bind(user.id)
        .fetch_one(&mut *tx)
        .await?;

    tx.commit().await?;

    let passkeys = vec![passkey];
    let result = SessionPackage {
        user: Arc::new(user),
        session: Arc::new(session),
        passkeys: Arc::new(passkeys),
    };
    Ok(result)
}
