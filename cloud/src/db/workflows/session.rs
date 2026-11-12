use crate::db::{Transaction, TransactionOperation};
use async_trait::async_trait;
use click_core::{InternalError, InternalResult, Passkey, Session, StatusCode, User, caller};

pub struct CreateSessionWorkflow {
    pub user: User,
}

#[async_trait]
impl TransactionOperation<(Session, User, Vec<Passkey>)> for CreateSessionWorkflow {
    async fn execute(
        self,
        tx: &mut Transaction<'_>,
    ) -> InternalResult<(Session, User, Vec<Passkey>)> {
        let session: Session =
            sqlx::query_as(r#"INSERT INTO "Sessions" (user_id) VALUES ($1) RETURNING *"#)
                .bind(self.user.id)
                .fetch_one(&mut **tx)
                .await
                .map_err(|err| {
                    InternalError::trace(
                        caller!(),
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal error creating session",
                        err,
                    )
                })?;

        let passkeys: Vec<Passkey> =
            sqlx::query_as(r#"SELECT * FROM "Passkeys" WHERE user_id = $1"#)
                .bind(self.user.id)
                .fetch_all(&mut **tx)
                .await
                .map_err(|err| {
                    InternalError::trace(
                        caller!(),
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal error getting user passkeys",
                        err,
                    )
                })?;

        Ok((session, self.user, passkeys))
    }
}
