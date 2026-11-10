// language=sql
pub const CREATE_PASSKEY_QUERY: &str = r#"
    INSERT INTO secretpass.public."Passkeys" (user_id, name, cred_id, key_salt, public_key, web_public_key)
    VALUES ($1, $2, $3, $4, $5, $6) RETURNING *
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
pub const LIST_USER_PASSKEYS_BY_USER_ID: &str = r#"
    SELECT * FROM "Passkeys" WHERE user_id = $1
"#;
