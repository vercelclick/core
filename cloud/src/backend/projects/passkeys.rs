use secretpass_core::enums::AccessGrant;
use secretpass_core::{SpassPasskey, SpassProject, SpassUser};
use sqlx::types::chrono::Utc;
use sqlx::{Postgres, QueryBuilder};

// language=sql
const CREATE_PROJECT_PASSKEYS_QUERY: &str = r#"
INSERT INTO "ProjectUserPasskey"
    (name, user_id, passkey_id, access, ecc, kem, granted_by, granted_on)
"#;

pub fn project_passkeys_insert_query_builder(
    user: &SpassUser,
    project: &SpassProject,
    passkeys: &[SpassPasskey],
) -> QueryBuilder<Postgres> {
    let mut query_builder: QueryBuilder<Postgres> =
        QueryBuilder::new(CREATE_PROJECT_PASSKEYS_QUERY);

    query_builder.push_values(passkeys, |mut b, passkey| {
        b.push_bind(format!("{} - {}", user.email, passkey.name))
            .push_bind(user.id)
            .push_bind(passkey.id)
            .push_bind(AccessGrant::Granted)
            .push_bind(project.algorithm.is_ecc().then_some(passkey.ecc.clone()))
            .push_bind(project.algorithm.is_kem().then_some(passkey.kem.clone()))
            .push_bind(user.email.clone())
            .push_bind(Utc::now());
    });

    query_builder.push(" RETURNING *");

    query_builder
}
