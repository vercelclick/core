use crate::backend::auth::session::get_passkeys_by_user_id;
use crate::db::queries::user::GET_USER_BY_EMAIL_QUERY;
use secretpass_core::enums::PasskeyType;
use secretpass_core::{SpassPasskey, SpassUser};
use sqlx::PgPool;

pub async fn retrieve_user_and_known_passkeys(
    pool: &PgPool,
    email: String,
    passkey_type: PasskeyType,
) -> anyhow::Result<Option<(SpassUser, Vec<SpassPasskey>)>> {
    let user = match retrieve_user_by_email(pool, email).await? {
        Some(res) => res,
        None => return Ok(None),
    };

    let passkeys = get_passkeys_by_user_id(pool, passkey_type, user.id).await?;

    Ok(Some((user, passkeys)))
}

pub async fn retrieve_user_by_email(
    pool: &PgPool,
    email: String,
) -> anyhow::Result<Option<SpassUser>> {
    let user: Option<SpassUser> = sqlx::query_as(GET_USER_BY_EMAIL_QUERY)
        .bind(email)
        .fetch_optional(pool)
        .await?;

    Ok(user)
}
