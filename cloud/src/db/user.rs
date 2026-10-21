use secretpass_core::enums::PasskeyType;
use secretpass_core::{SecretpassPasskey, SecretpassUser, SecretpassUserSession};
use sqlx::Row;
use sqlx::postgres::PgRow;
use std::str::FromStr;

pub fn parse_user_from_row(row: &PgRow) -> (i64, SecretpassUser) {
    let internal_id: i64 = row.get("id");

    let user = SecretpassUser {
        id: row.get("external_id"),
        name: row.get("name"),
        email: row.get("email"),
        created_at: row.get("created_at"),
    };

    (internal_id, user)
}

pub fn parse_passkey_from_row_with_user_id(
    row: &PgRow,
    user_id: i64,
    external_user_id: String,
) -> anyhow::Result<(i64, SecretpassPasskey)> {
    let internal_id: i64 = row.get("id");

    let key_type: String = row.get("type");
    let type_: PasskeyType = PasskeyType::from_str(&key_type)?;
    let passkey_user_id: i64 = row.get("user_id");
    if passkey_user_id != user_id {
        return Err(anyhow::anyhow!("Passkey user id mismatch"));
    }

    let passkey = SecretpassPasskey {
        id: row.get("cred_id"),
        user_id: external_user_id,
        type_,
        name: row.get("name"),
        public_key: row.get("public_key"),
        created_at: row.get("created_at"),
    };

    Ok((internal_id, passkey))
}

pub fn parse_session_from_row_with_user_id(
    row: &PgRow,
    user_id: i64,
    external_user_id: String,
) -> anyhow::Result<SecretpassUserSession> {
    let session_user_id: i64 = row.get("user_id");
    if session_user_id != user_id {
        return Err(anyhow::anyhow!("Session user id mismatch"));
    }
    let session = SecretpassUserSession {
        id: row.get("id"),
        user_id: external_user_id,
        created_on: row.get("created_on"),
        last_seen: row.get("last_seen"),
        expires_on: row.get("expires_on"),
    };

    Ok(session)
}
