use secretpass_core::enums::PasskeyType;
use sqlx::{PgPool, Row};
use uuid::Uuid;

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
) -> anyhow::Result<Option<(Uuid, String)>> {
    let row = sqlx::query(PASSKEY_USER_ID_PUBLIC_KEY_QUERY)
        .bind(passkey_type)
        .bind(cred_id)
        .fetch_optional(pool)
        .await?;

    let row = match row {
        Some(row) => row,
        None => return Ok(None),
    };

    let user_id: Uuid = row.get("user_id");
    let public_key: String = row.get("public_key");

    Ok(Some((user_id, public_key)))
}
