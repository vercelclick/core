// language=sql
pub const CREATE_PASSKEY_QUERY: &str = r#"
    INSERT INTO "Passkeys" (user_id, name, cred_id, type, ecc, kem, public_key)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    RETURNING *
"#;

// language=sql
pub const CREATE_SESSION_QUERY: &str = r#"
    INSERT INTO "Sessions" (user_id) VALUES ($1) RETURNING *
"#;

// language=sql
pub const GET_PASSKEY_BY_CRED_ID_QUERY: &str = r#"
    SELECT * FROM "Passkeys" WHERE cred_id = $1 AND user_id = $2
"#;

// language=sql
pub const LIST_USER_PASSKEYS_BY_TYPE: &str = r#"
    SELECT * FROM "Passkeys" WHERE type = $1 AND user_id = $2
"#;
