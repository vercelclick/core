use click_core::{InternalError, InternalResult, StatusCode, User, caller};
use sqlx::{Executor, Postgres};
use uuid::Uuid;

pub async fn get_user_by_email<'e, E>(executor: E, email: String) -> InternalResult<Option<User>>
where
    E: Executor<'e, Database = Postgres>,
{
    let user: Option<User> = sqlx::query_as(r#"SELECT * FROM "Users" WHERE email=$1"#)
        .bind(email)
        .fetch_optional(executor)
        .await
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error getting user details",
                err,
            )
        })?;

    Ok(user)
}

pub async fn get_user_by_id<'e, E>(executor: E, id: Uuid) -> InternalResult<Option<User>>
where
    E: Executor<'e, Database = Postgres>,
{
    let user: Option<User> = sqlx::query_as(
        r#"
            SELECT * FROM "Users" WHERE id=$1
        "#,
    )
    .bind(id)
    .fetch_optional(executor)
    .await
    .map_err(|err| {
        InternalError::trace(
            caller!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error getting user details",
            err,
        )
    })?;

    Ok(user)
}
