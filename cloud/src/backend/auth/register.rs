use crate::db::queries::auth::{CREATE_PASSKEY_QUERY, CREATE_SESSION_QUERY};
use crate::db::user::{parse_session_from_row_with_user_id, parse_user_from_row};
use secretpass_api::{CreateUserParams, SessionResponse};
use sqlx::PgPool;

// language=sql
const CREATE_USER_QUERY: &str = r#"
    INSERT INTO "Users" (external_id, name, email) VALUES ($1, $2, $3) RETURNING *
"#;

pub async fn create_user(
    pool: &PgPool,
    params: CreateUserParams,
) -> anyhow::Result<SessionResponse> {
    let mut tx = pool.begin().await?;

    let row = sqlx::query(CREATE_USER_QUERY)
        .bind(&params.generated_id)
        .bind(&params.name)
        .bind(&params.email)
        .fetch_one(&mut *tx)
        .await?;

    let (user_id, user) = parse_user_from_row(&row);

    let passkey = &params.passkey;
    sqlx::query(CREATE_PASSKEY_QUERY)
        .bind(&passkey.id)
        .bind(user_id)
        .bind(&passkey.name)
        .bind(passkey.type_.to_string())
        .bind(&passkey.public_key)
        .execute(&mut *tx)
        .await?;

    let row = sqlx::query(CREATE_SESSION_QUERY)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
    let session = parse_session_from_row_with_user_id(&row, user_id, user.id.clone())?;

    let result = SessionResponse { user, session };
    Ok(result)
}
