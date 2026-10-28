use crate::backend::auth::user::retrieve_user_by_email;
use crate::db::queries::auth::{CREATE_SESSION_QUERY, LIST_USER_PASSKEYS_BY_TYPE};
use crate::db::queries::user::GET_USER_BY_ID_QUERY;
use secretpass_api::SessionPackage;
use secretpass_core::enums::PasskeyType;
use secretpass_core::{Passkey, Session, User};
use sqlx::PgPool;
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
    let session: Option<Session> = sqlx::query_as(GET_SESSION_QUERY)
        .bind(id)
        .fetch_optional(pool)
        .await?;

    let session = match session {
        Some(session) => session,
        None => return Ok(None),
    };

    let user: User = sqlx::query_as(GET_USER_BY_ID_QUERY)
        .bind(id)
        .fetch_one(pool)
        .await?;

    let passkeys = get_passkeys_by_user_id(pool, passkey_type, user.id).await?;

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
    let user = retrieve_user_by_email(pool, email)
        .await?
        .ok_or_else(|| anyhow::anyhow!("User not found"))?;

    let session: Session = sqlx::query_as(CREATE_SESSION_QUERY)
        .bind(user.id)
        .fetch_one(pool)
        .await?;

    let passkeys = get_passkeys_by_user_id(pool, passkey_type, user.id).await?;
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
    let user: User = sqlx::query_as(GET_USER_BY_ID_QUERY)
        .bind(user_id)
        .fetch_one(pool)
        .await?;

    let session: Session = sqlx::query_as(CREATE_SESSION_QUERY)
        .bind(user_id)
        .fetch_one(pool)
        .await?;

    let passkeys = get_passkeys_by_user_id(pool, passkey_type, user_id).await?;
    Ok(SessionPackage {
        user: Arc::new(user),
        session: Arc::new(session),
        passkeys: Arc::new(passkeys),
    })
}

pub async fn get_passkeys_by_user_id(
    pool: &PgPool,
    passkey_type: PasskeyType,
    user_id: Uuid,
) -> anyhow::Result<Vec<Passkey>> {
    let passkeys: Vec<Passkey> = sqlx::query_as(LIST_USER_PASSKEYS_BY_TYPE)
        .bind(passkey_type)
        .bind(user_id)
        .fetch_all(pool)
        .await?;

    Ok(passkeys)
}

// language=sql
const EXPIRE_SESSION_QUERY: &str = r#"UPDATE "UserSessions" SET expires_on=now() WHERE id=$1"#;

pub async fn expire_session(pool: &PgPool, session: &Session) -> anyhow::Result<()> {
    sqlx::query(EXPIRE_SESSION_QUERY)
        .bind(session.id)
        .execute(pool)
        .await?;
    Ok(())
}
