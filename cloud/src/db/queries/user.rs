// language=sql
pub const GET_USER_BY_ID_QUERY: &str = r#"
    SELECT * FROM "Users" WHERE id=$1
"#;

// language=sql
pub const GET_USER_BY_EMAIL_QUERY: &str = r#"
    SELECT * FROM "Users" WHERE email=$1
"#;
