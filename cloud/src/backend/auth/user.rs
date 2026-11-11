use crate::backend::auth::session::get_passkeys_by_user_id;
use crate::db;
use crate::db::queries::user::GET_USER_BY_EMAIL_QUERY;
use secretpass_core::{InternalError, InternalResult, Passkey, StatusCode, User};

pub async fn get_user_by_email_with_passkeys(
    email: String,
) -> InternalResult<Option<(User, Vec<Passkey>)>> {
    let user = match get_user_by_email(email).await? {
        Some(res) => res,
        None => return Ok(None),
    };

    let passkeys = get_passkeys_by_user_id(user.id).await?;

    Ok(Some((user, passkeys)))
}

pub async fn get_user_by_email(email: String) -> InternalResult<Option<User>> {
    let user: Option<User> = sqlx::query_as(GET_USER_BY_EMAIL_QUERY)
        .bind(email)
        .fetch_optional(db::pool())
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
