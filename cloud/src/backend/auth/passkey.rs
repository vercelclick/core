use crate::db;
use secretpass_core::{InternalError, InternalResult, Passkey, StatusCode};

// language=sql
const PASSKEY_USER_ID_PUBLIC_KEY_QUERY: &str = r#"
    SELECT
        PK.*
    FROM "Passkeys" PK INNER JOIN "Users" U on U.id = PK.user_id
    WHERE cred_id = $1 AND U.email = $2
"#;

pub async fn retrieve_passkey_by_cred_id(
    cred_id: String,
    email: String,
) -> InternalResult<Option<Passkey>> {
    let passkey: Option<Passkey> = sqlx::query_as(PASSKEY_USER_ID_PUBLIC_KEY_QUERY)
        .bind(cred_id)
        .bind(email)
        .fetch_optional(db::pool())
        .await
        .map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error getting passkey details",
                err,
            )
        })?;

    Ok(passkey)
}
