use crate::backend::auth::session::get_passkeys_by_user_id;
use crate::db::queries::user::GET_USER_BY_EMAIL_QUERY;
use secretpass_core::{InternalError, InternalResult, Passkey, StatusCode, User};
use sqlx::PgPool;

pub async fn retrieve_user_and_known_passkeys(
    pool: &PgPool,
    email: String,
) -> InternalResult<Option<(User, Vec<Passkey>)>> {
    let user = match retrieve_user_by_email(pool, email).await? {
        Some(res) => res,
        None => return Ok(None),
    };

    let passkeys = get_passkeys_by_user_id(pool, user.id).await?;

    Ok(Some((user, passkeys)))
}

pub async fn retrieve_user_by_email(pool: &PgPool, email: String) -> InternalResult<Option<User>> {
    let user: Option<User> = sqlx::query_as(GET_USER_BY_EMAIL_QUERY)
        .bind(email)
        .fetch_optional(pool)
        .await
        .map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error getting user details",
                err,
            )
        })?;

    Ok(user)
}
