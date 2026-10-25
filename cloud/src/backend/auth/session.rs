use crate::backend::auth::user::retrieve_user_by_email;
use crate::db::queries::auth::{CREATE_SESSION_QUERY, LIST_USER_PASSKEYS_BY_TYPE};
use crate::db::queries::user::{GET_USER_BY_EXTERNAL_ID_QUERY, GET_USER_BY_ID_QUERY};
use crate::db::user::{
    parse_passkey_from_row_with_user_id, parse_session_from_row_with_user_id, parse_user_from_row,
};
use secretpass_api::SessionPackage;
use secretpass_core::enums::PasskeyType;
use secretpass_core::{SecretpassPasskey, SecretpassUserSession};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

// language=sql
const GET_SESSION_QUERY: &str = r#"
    UPDATE "UserSessions" SET last_seen = now() WHERE "id" = $1 AND expires_on > now() RETURNING *
"#;

pub async fn get_session(
    pool: &PgPool,
    passkey_type: PasskeyType,
    id: Uuid,
) -> anyhow::Result<Option<SessionPackage>> {
    // TODO: Collapse these queries to one
    let session_row = sqlx::query(GET_SESSION_QUERY)
        .bind(id)
        .fetch_optional(pool)
        .await?;

    let session_row = match session_row {
        Some(row) => row,
        None => return Ok(None),
    };

    let id: i32 = session_row.get("user_id");
    let user_row = sqlx::query(GET_USER_BY_ID_QUERY)
        .bind(id)
        .fetch_one(pool)
        .await?;
    let (user_id, user) = parse_user_from_row(&user_row);

    let session = parse_session_from_row_with_user_id(&session_row, user.id);

    let passkeys = get_user_passkeys_by_type(pool, passkey_type, user_id, user.id).await?;

    Ok(Some(SessionPackage {
        user: Arc::new(user),
        session: Arc::new(session),
        passkeys: Arc::new(passkeys),
    }))
}

pub async fn create_session_by_email(
    pool: &PgPool,
    passkey_type: PasskeyType,
    email: String,
) -> anyhow::Result<SessionPackage> {
    let (user_id, user) = retrieve_user_by_email(pool, email)
        .await?
        .ok_or_else(|| anyhow::anyhow!("User not found"))?;

    let session_row = sqlx::query(CREATE_SESSION_QUERY)
        .bind(user_id)
        .fetch_one(pool)
        .await?;
    let session = parse_session_from_row_with_user_id(&session_row, user.id);
    let passkeys = get_user_passkeys_by_type(pool, passkey_type, user_id, user.id).await?;
    Ok(SessionPackage {
        user: Arc::new(user),
        session: Arc::new(session),
        passkeys: Arc::new(passkeys),
    })
}

pub async fn create_session_by_user_id(
    pool: &PgPool,
    passkey_type: PasskeyType,
    user_id: Uuid,
) -> anyhow::Result<SessionPackage> {
    let user_row = sqlx::query(GET_USER_BY_EXTERNAL_ID_QUERY)
        .bind(user_id)
        .fetch_one(pool)
        .await?;

    let (user_id, user) = parse_user_from_row(&user_row);

    let session_row = sqlx::query(CREATE_SESSION_QUERY)
        .bind(user_id)
        .fetch_one(pool)
        .await?;

    let session = parse_session_from_row_with_user_id(&session_row, user.id);
    let passkeys = get_user_passkeys_by_type(pool, passkey_type, user_id, user.id).await?;
    Ok(SessionPackage {
        user: Arc::new(user),
        session: Arc::new(session),
        passkeys: Arc::new(passkeys),
    })
}

pub async fn get_user_passkeys_by_type(
    pool: &PgPool,
    passkey_type: PasskeyType,
    user_id: i32,
    external_user_id: Uuid,
) -> anyhow::Result<Vec<SecretpassPasskey>> {
    let rows = sqlx::query(LIST_USER_PASSKEYS_BY_TYPE)
        .bind(passkey_type)
        .bind(user_id)
        .fetch_all(pool)
        .await?;

    let mut passkeys: Vec<SecretpassPasskey> = Vec::with_capacity(rows.len());
    for row in rows.iter() {
        let (_, passkey) = parse_passkey_from_row_with_user_id(row, external_user_id);
        passkeys.push(passkey);
    }

    Ok(passkeys)
}

// language=sql
const EXPIRE_SESSION_QUERY: &str = r#"UPDATE "UserSessions" SET expires_on=now() WHERE id=$1"#;

pub async fn expire_session(pool: &PgPool, session: &SecretpassUserSession) -> anyhow::Result<()> {
    sqlx::query(EXPIRE_SESSION_QUERY)
        .bind(session.id)
        .execute(pool)
        .await?;
    Ok(())
}
