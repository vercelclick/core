use secretpass_core::enums::AccessGrant;
use secretpass_core::{Contributor, Passkey, Project, User};
use sqlx::types::chrono::Utc;
use sqlx::{Postgres, QueryBuilder};

// language=sql
const CREATE_CONTRIBUTOR_PUBLIC_KEY_QUERY: &str = r#"
INSERT INTO "ContributorPublicKeys" (name, user_id, cred_id, contributor_id, access, ecc, kem, granted_by, granted_on)
"#;

pub fn contributor_public_key_insert_query_builder(
    user: &User,
    contributor: &Contributor,
    project: &Project,
    passkeys: &[Passkey],
) -> QueryBuilder<Postgres> {
    let mut query_builder: QueryBuilder<Postgres> =
        QueryBuilder::new(CREATE_CONTRIBUTOR_PUBLIC_KEY_QUERY);

    query_builder.push_values(passkeys, |mut b, passkey| {
        b.push_bind(format!("{} - {}", user.email, passkey.name))
            .push_bind(user.id)
            .push_bind(passkey.cred_id.clone())
            .push_bind(contributor.id)
            .push_bind(AccessGrant::Granted)
            .push_bind(project.algorithm.is_ecc().then_some(passkey.ecc.clone()))
            .push_bind(project.algorithm.is_kem().then_some(passkey.kem.clone()))
            .push_bind(user.email.clone())
            .push_bind(Utc::now());
    });

    query_builder.push(" RETURNING *");

    query_builder
}
