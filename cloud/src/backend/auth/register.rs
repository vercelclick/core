use crate::backend::auth::session::get_user_passkeys_by_type;
use crate::db::queries::auth::{CREATE_PASSKEY_QUERY, CREATE_SESSION_QUERY};
use crate::db::user::{parse_session_from_row_with_user_id, parse_user_from_row};
use secretpass_api::SessionPackage;
use secretpass_api::auth::BackendCreateUserRequest;
use sqlx::PgPool;
use std::sync::Arc;

// language=sql
const CREATE_USER_QUERY: &str = r#"
    INSERT INTO "Users" (external_id, name, email) VALUES ($1, $2, $3) RETURNING *
"#;

pub async fn create_user(
    pool: &PgPool,
    request: BackendCreateUserRequest,
) -> anyhow::Result<SessionPackage> {
    let mut tx = pool.begin().await?;

    let row = sqlx::query(CREATE_USER_QUERY)
        .bind(request.user_id)
        .bind(&request.user_name)
        .bind(&request.user_email)
        .fetch_one(&mut *tx)
        .await?;

    let (user_id, user) = parse_user_from_row(&row);

    sqlx::query(CREATE_PASSKEY_QUERY)
        .bind(&request.passkey_cred_id)
        .bind(user_id)
        .bind(&request.passkey_name)
        .bind(request.passkey_type)
        .bind(&request.passkey_public_key)
        .execute(&mut *tx)
        .await?;

    let row = sqlx::query(CREATE_SESSION_QUERY)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;

    let session = parse_session_from_row_with_user_id(&row, user.id);

    let passkeys = get_user_passkeys_by_type(pool, request.passkey_type, user_id, user.id).await?;

    tx.commit().await?;

    let result = SessionPackage {
        user: Arc::new(user),
        session: Arc::new(session),
        passkeys: Arc::new(passkeys),
    };
    Ok(result)
}
