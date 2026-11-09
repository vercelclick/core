use crate::db::queries::auth::CREATE_PASSKEY_QUERY;
use secretpass_core::enums::PasskeyType;
use secretpass_core::passkeys::public_key::PublicKeyGenerateResult;
use secretpass_core::{InternalError, InternalResult, Passkey, StatusCode, User, source};
use sqlx::PgPool;

// language=sql
const PASSKEY_USER_ID_PUBLIC_KEY_QUERY: &str = r#"
    SELECT
        PK.*
    FROM "Passkeys" PK INNER JOIN "Users" U on U.id = PK.user_id
    WHERE cred_id = $1 AND U.email = $2
"#;

pub async fn retrieve_passkey_by_cred_id(
    pool: &PgPool,
    cred_id: String,
    email: String,
) -> InternalResult<Option<Passkey>> {
    let passkey: Option<Passkey> = sqlx::query_as(PASSKEY_USER_ID_PUBLIC_KEY_QUERY)
        .bind(cred_id)
        .bind(email)
        .fetch_optional(pool)
        .await
        .map_err(|err| {
            InternalError::trace(
                source!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error getting passkey details",
                err,
            )
        })?;

    Ok(passkey)
}

pub async fn create_passkey(
    pool: &PgPool,
    user: &User,
    passkey_type: PasskeyType,
    passkey_name: String,
    cred_id: String,
    web_public_key: String,
    public_key_result: PublicKeyGenerateResult,
) -> InternalResult<Passkey> {
    let passkey: Passkey = sqlx::query_as(CREATE_PASSKEY_QUERY)
        .bind(user.id)
        .bind(passkey_name)
        .bind(cred_id)
        .bind(passkey_type)
        .bind(public_key_result.public_key)
        .bind(web_public_key)
        .fetch_one(pool)
        .await
        .map_err(|err| {
            InternalError::trace(
                source!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error creating passkey",
                err,
            )
        })?;

    Ok(passkey)
}
