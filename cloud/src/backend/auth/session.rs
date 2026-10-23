use crate::db::queries::auth::{
    CREATE_SESSION_QUERY, GET_PASSKEY_BY_CRED_ID_QUERY, LIST_USER_PASSKEYS_BY_TYPE,
};
use crate::db::queries::user::{
    GET_USER_BY_EMAIL_QUERY, GET_USER_BY_EXTERNAL_ID_QUERY, GET_USER_BY_ID_QUERY,
};
use crate::db::user::{
    parse_passkey_from_row_with_user_id, parse_session_from_row_with_user_id, parse_user_from_row,
};
use secretpass_api::SessionPackage;
use secretpass_core::SecretpassPasskey;
use secretpass_core::enums::PasskeyType;
use sqlx::{PgPool, Row};

// language=sql
const GET_SESSION_QUERY: &str = r#"
    UPDATE "UserSessions" SET last_seen = now() WHERE "id" = $1 AND expires_on > now() RETURNING *
"#;

pub async fn get_session(
    pool: &PgPool,
    passkey_type: PasskeyType,
    id: String,
) -> anyhow::Result<SessionPackage> {
    // TODO: Collapse these queries to one
    let session_row = sqlx::query(GET_SESSION_QUERY)
        .bind(&id)
        .fetch_one(pool)
        .await?;

    let id: i64 = session_row.get("user_id");
    let user_row = sqlx::query(GET_USER_BY_ID_QUERY)
        .bind(id)
        .fetch_one(pool)
        .await?;
    let (user_id, user) = parse_user_from_row(&user_row);

    let session = parse_session_from_row_with_user_id(&session_row, user_id, user.id.clone())?;

    let passkeys = get_user_passkeys_by_type(pool, passkey_type, user_id, user.id.clone()).await?;

    Ok(SessionPackage {
        user,
        session,
        passkeys,
    })
}

pub async fn create_session_by_email(
    pool: &PgPool,
    passkey_type: PasskeyType,
    email: String,
) -> anyhow::Result<SessionPackage> {
    let user_row = sqlx::query(GET_USER_BY_EMAIL_QUERY)
        .bind(email)
        .fetch_one(pool)
        .await?;

    let (user_id, user) = parse_user_from_row(&user_row);

    let session_row = sqlx::query(CREATE_SESSION_QUERY)
        .bind(user_id)
        .fetch_one(pool)
        .await?;
    let session = parse_session_from_row_with_user_id(&session_row, user_id, user.id.clone())?;
    let passkeys = get_user_passkeys_by_type(pool, passkey_type, user_id, user.id.clone()).await?;
    Ok(SessionPackage {
        user,
        session,
        passkeys,
    })
}

pub async fn create_session_by_user_and_cred_id(
    pool: &PgPool,
    passkey_type: PasskeyType,
    user_id: String,
    cred_id: String,
) -> anyhow::Result<SessionPackage> {
    let user_row = sqlx::query(GET_USER_BY_EXTERNAL_ID_QUERY)
        .bind(user_id)
        .fetch_one(pool)
        .await?;

    let (user_id, user) = parse_user_from_row(&user_row);

    let session_row = sqlx::query(GET_PASSKEY_BY_CRED_ID_QUERY)
        .bind(cred_id)
        .bind(user_id)
        .fetch_one(pool)
        .await?;

    let session = parse_session_from_row_with_user_id(&session_row, user_id, user.id.clone())?;
    let passkeys = get_user_passkeys_by_type(pool, passkey_type, user_id, user.id.clone()).await?;
    Ok(SessionPackage {
        user,
        session,
        passkeys,
    })
}

pub async fn get_user_passkeys_by_type(
    pool: &PgPool,
    passkey_type: PasskeyType,
    user_id: i64,
    external_user_id: String,
) -> anyhow::Result<Vec<SecretpassPasskey>> {
    let rows = sqlx::query(LIST_USER_PASSKEYS_BY_TYPE)
        .bind(passkey_type.to_string())
        .bind(user_id)
        .fetch_all(pool)
        .await?;

    let mut passkeys: Vec<SecretpassPasskey> = Vec::with_capacity(rows.len());
    for row in rows.iter() {
        let (_, passkey) =
            parse_passkey_from_row_with_user_id(row, user_id, external_user_id.clone())?;
        passkeys.push(passkey);
    }

    Ok(passkeys)
}
