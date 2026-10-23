// language=sql
pub const CREATE_PASSKEY_QUERY: &str = r#"
    INSERT INTO "UserPasskeys" (cred_id, user_id, name, "type", public_key)
        VALUES ($1, $2, $3, $4::"PasskeyType", $5)
    RETURNING *
"#;

// language=sql
pub const CREATE_SESSION_QUERY: &str = r#"
    INSERT INTO "UserSessions" (user_id) VALUES ($1) RETURNING *
"#;

// language=sql
pub const GET_PASSKEY_BY_CRED_ID_QUERY: &str = r#"
    SELECT * FROM "UserPasskeys" WHERE cred_id = $1 AND user_id = $2
"#;


// language=sql
pub const LIST_USER_PASSKEYS_BY_TYPE: &str = r#"
    SELECT * FROM "UserPasskeys" WHERE "type" = $1::"PasskeyType" AND user_id = $2
"#;