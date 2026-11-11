use secretpass_core::{InternalError, InternalResult, StatusCode};
use sqlx::{PgConnection, PgPool, Postgres, Transaction as SqlxTransaction};
use std::sync::OnceLock;

pub mod queries;

pub static DB_POOL: OnceLock<PgPool> = OnceLock::new();

pub fn pool() -> &'static PgPool {
    DB_POOL.get().unwrap()
}

pub type Connection = PgConnection;
pub type Transaction<'a> = SqlxTransaction<'a, Postgres>;

#[async_trait::async_trait]
pub trait TransactionOperation<T> {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<T>;
}

pub async fn with_transaction<T, Op>(op: Op) -> InternalResult<T>
where
    Op: TransactionOperation<T>,
{
    let mut transaction = pool().begin().await.map_err(|err| {
        InternalError::trace(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error establishing a transaction",
            err,
        )
    })?;

    match op.execute(&mut transaction).await {
        Ok(res) => {
            transaction.commit().await.map_err(|err| {
                InternalError::trace(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error committing database transaction",
                    err,
                )
            })?;
            Ok(res)
        }
        Err(e) => {
            transaction.rollback().await.map_err(|err| {
                InternalError::trace(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error rolling back database transaction",
                    err,
                )
            })?;
            Err(e)
        }
    }
}
