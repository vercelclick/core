use crate::db::queries::auth::CREATE_PASSKEY_QUERY;
use secretpass_core::enums::PasskeyType;
use secretpass_core::passkeys::public_key::PublicKeyGenerateResult;
use secretpass_core::{Passkey, User};
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
) -> anyhow::Result<Option<Passkey>> {
    let passkey: Option<Passkey> = sqlx::query_as(PASSKEY_USER_ID_PUBLIC_KEY_QUERY)
        .bind(cred_id)
        .bind(email)
        .fetch_optional(pool)
        .await?;

    Ok(passkey)
}

pub async fn create_passkey(
    pool: &PgPool,
    user: &User,
    passkey_type: PasskeyType,
    passkey_name: String,
    cred_id: String,
    public_key: String,
    public_key_result: PublicKeyGenerateResult,
) -> anyhow::Result<Passkey> {
    let passkey: Passkey = sqlx::query_as(CREATE_PASSKEY_QUERY)
        .bind(user.id)
        .bind(passkey_name)
        .bind(cred_id)
        .bind(passkey_type)
        .bind(public_key_result.ecc)
        .bind(public_key_result.kem)
        .bind(public_key)
        .fetch_one(pool)
        .await?;

    Ok(passkey)
}
