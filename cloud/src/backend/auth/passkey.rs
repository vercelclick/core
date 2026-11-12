use crate::db;
use click_core::{InternalError, InternalResult, Passkey, StatusCode, caller};
use uuid::Uuid;

pub async fn retrieve_passkey_by_cred_id(
    connection: &mut db::Connection,
    cred_id: String,
    user_id: Uuid,
) -> InternalResult<Option<Passkey>> {
    let passkey: Option<Passkey> =
        sqlx::query_as(r#"SELECT * FROM "Passkeys" WHERE cred_id = $1 AND user_id = $2"#)
            .bind(cred_id)
            .bind(user_id)
            .fetch_optional(connection)
            .await
            .map_err(|err| {
                InternalError::trace(
                    caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error getting passkey details",
                    err,
                )
            })?;

    Ok(passkey)
}
