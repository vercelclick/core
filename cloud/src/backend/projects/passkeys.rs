use crate::db::{Transaction, TransactionOperation};
use secretpass_core::enums::AccessGrant;
use secretpass_core::{Contributor, InternalError, InternalResult, Passkey, StatusCode, User};
use sqlx::types::chrono::Utc;
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

// language=sql
const CREATE_CONTRIBUTOR_PUBLIC_KEY_QUERY: &str = r#"
INSERT INTO secretpass.public."ContributorPublicKeys"
    (name, user_id, cred_id, contributor_id, access, user_salt, passkey_salt, public_key, granted_by, granted_on)
"#;

pub fn contributor_public_key_insert_query_builder(
    user: User,
    contributor: Contributor,
    passkeys: Vec<Passkey>,
) -> QueryBuilder<Postgres> {
    let mut query_builder: QueryBuilder<Postgres> =
        QueryBuilder::new(CREATE_CONTRIBUTOR_PUBLIC_KEY_QUERY);

    query_builder.push_values(passkeys, |mut b, passkey| {
        b.push_bind(format!("{} - {}", user.email, passkey.name))
            .push_bind(user.id)
            .push_bind(&passkey.cred_id)
            .push_bind(contributor.id)
            .push_bind(AccessGrant::Granted)
            .push_bind(&user.key_salt)
            .push_bind(&passkey.key_salt)
            .push_bind(&passkey.public_key)
            .push_bind(&user.email)
            .push_bind(Utc::now());
    });

    query_builder.push(" RETURNING *");

    query_builder
}

// language=sql
pub const CREATE_PASSKEY_QUERY: &str = r#"
    INSERT INTO secretpass.public."Passkeys" (user_id, name, cred_id, key_salt, public_key, web_public_key)
    VALUES ($1, $2, $3, $4, $5, $6) RETURNING *
"#;

pub struct SavePasskeyWorkflow {
    pub user_id: Uuid,
    pub name: String,
    pub salt: String,
    pub cred_id: String,
    pub public_key: String,
    pub web_public_key: String,
}

#[async_trait::async_trait]
impl TransactionOperation<Passkey> for SavePasskeyWorkflow {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<Passkey> {
        let passkey: Passkey = sqlx::query_as(CREATE_PASSKEY_QUERY)
            .bind(self.user_id)
            .bind(&self.name)
            .bind(&self.cred_id)
            .bind(&self.salt)
            .bind(&self.public_key)
            .bind(&self.web_public_key)
            .fetch_one(&mut **tx)
            .await
            .map_err(|err| {
                InternalError::trace(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error creating passkey",
                    err,
                )
            })?;

        Ok(passkey)
    }
}
