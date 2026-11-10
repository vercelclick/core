use crate::backend::auth::user::retrieve_user_by_email;
use crate::db::queries::auth::{CREATE_SESSION_QUERY, LIST_USER_PASSKEYS_BY_USER_ID};
use crate::db::queries::user::GET_USER_BY_ID_QUERY;
use secretpass_core::{InternalError, InternalResult, Passkey, Session, StatusCode, User};
use sqlx::PgPool;
use uuid::Uuid;

// language=sql
const GET_SESSION_QUERY: &str = r#"
    UPDATE "Sessions" SET last_seen = now() WHERE "id" = $1 AND user_id = $2 AND expires_on > now() RETURNING id
"#;

pub async fn get_session(
    pool: &PgPool,
    id: Uuid,
    user_id: Uuid,
) -> InternalResult<Option<Session>> {
    // TODO: Collapse these queries to one
    let session: Option<Session> = sqlx::query_as(GET_SESSION_QUERY)
        .bind(id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error getting session",
                err,
            )
        })?;

    Ok(session)
}

pub async fn create_session_by_email(
    pool: &PgPool,
    email: String,
) -> InternalResult<(Session, User, Vec<Passkey>)> {
    let user = retrieve_user_by_email(pool, email)
        .await?
        .ok_or_else(|| InternalError::new(StatusCode::NOT_FOUND, "User not found"))?;

    let session: Session = sqlx::query_as(CREATE_SESSION_QUERY)
        .bind(user.id)
        .fetch_one(pool)
        .await
        .map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error creating session",
                err,
            )
        })?;

    let passkeys = get_passkeys_by_user_id(pool, user.id).await?;
    Ok((session, user, passkeys))
}

pub async fn create_session_by_user_id(
    pool: &PgPool,
    user_id: Uuid,
) -> InternalResult<(Session, User, Vec<Passkey>)> {
    let user: User = sqlx::query_as(GET_USER_BY_ID_QUERY)
        .bind(user_id)
        .fetch_one(pool)
        .await
        .map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error getting user details",
                err,
            )
        })?;

    let session: Session = sqlx::query_as(CREATE_SESSION_QUERY)
        .bind(user_id)
        .fetch_one(pool)
        .await
        .map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error establishing a session",
                err,
            )
        })?;

    let passkeys = get_passkeys_by_user_id(pool, user_id).await?;
    Ok((session, user, passkeys))
}

pub async fn get_passkeys_by_user_id(pool: &PgPool, user_id: Uuid) -> InternalResult<Vec<Passkey>> {
    let passkeys: Vec<Passkey> = sqlx::query_as(LIST_USER_PASSKEYS_BY_USER_ID)
        .bind(user_id)
        .fetch_all(pool)
        .await
        .map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error getting user passkeys",
                err,
            )
        })?;

    Ok(passkeys)
}

// language=sql
const EXPIRE_SESSION_QUERY: &str =
    r#"UPDATE "Sessions" SET last_seen=now(), expires_on=now() WHERE id=$1"#;

pub async fn expire_session(pool: &PgPool, session: &Session) -> InternalResult<()> {
    sqlx::query(EXPIRE_SESSION_QUERY)
        .bind(session.id)
        .execute(pool)
        .await
        .map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error expiring session",
                err,
            )
        })?;
    Ok(())
}
