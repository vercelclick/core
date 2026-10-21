// language=sql
pub const CREATE_PASSKEY_QUERY: &str = r#"
    INSERT INTO "UserPasskeys" (cred_id, user_id, name, "type", public_key)
        VALUES ($1, $2, $3, $4, $5::"PasskeyType")
    RETURNING *
"#;

// language=sql
pub const CREATE_SESSION_QUERY: &str = r#"
    INSERT INTO "UserSessions" (user_id) VALUES ($1) RETURNING *
"#;
