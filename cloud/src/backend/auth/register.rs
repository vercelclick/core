use crate::backend::auth::session::get_user_passkeys_by_type;
use crate::db::queries::auth::{CREATE_PASSKEY_QUERY, CREATE_SESSION_QUERY};
use secretpass_api::SessionPackage;
use secretpass_api::auth::BackendCreateUserRequest;
use secretpass_core::{SpassSession, SpassUser};
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

    let user: SpassUser = sqlx::query_as(CREATE_USER_QUERY)
        .bind(request.user_id)
        .bind(&request.user_name)
        .bind(&request.user_email)
        .fetch_one(&mut *tx)
        .await?;

    sqlx::query(CREATE_PASSKEY_QUERY)
        .bind(request.passkey_id)
        .bind(user.id)
        .bind(&request.passkey_name)
        .bind(&request.passkey_cred_id)
        .bind(request.passkey_type)
        .bind(&request.passkey_ecc)
        .bind(&request.passkey_kem)
        .bind(&request.passkey_public_key)
        .execute(&mut *tx)
        .await?;

    let session: SpassSession = sqlx::query_as(CREATE_SESSION_QUERY)
        .bind(user.id)
        .fetch_one(&mut *tx)
        .await?;

    let passkeys = get_user_passkeys_by_type(pool, request.passkey_type, user.id).await?;

    tx.commit().await?;

    let result = SessionPackage {
        user: Arc::new(user),
        session: Arc::new(session),
        passkeys: Arc::new(passkeys),
    };
    Ok(result)
}
