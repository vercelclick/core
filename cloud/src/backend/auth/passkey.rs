use secretpass_core::enums::PasskeyType;
use sqlx::{PgPool, Row};

// language=sql
const PASSKEY_USER_ID_PUBLIC_KEY_QUERY: &str = r#"
    SELECT
        U.external_id as "user_id", PK.public_key as "public_key"
    FROM "UserPasskeys" PK INNER JOIN "Users" U on U.id = PK.user_id
    WHERE PK.type = $1 AND cred_id = $2
"#;

pub async fn retrieve_user_id_and_public_key(
    pool: &PgPool,
    passkey_type: PasskeyType,
    cred_id: String,
) -> anyhow::Result<(String, String)> {
    let row = sqlx::query(PASSKEY_USER_ID_PUBLIC_KEY_QUERY)
        .bind(passkey_type.to_string())
        .bind(cred_id)
        .fetch_one(pool)
        .await?;

    let user_id: String = row.get("user_id");
    let public_key: String = row.get("public_key");

    Ok((user_id, public_key))
}
