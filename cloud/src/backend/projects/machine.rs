use crate::backend::projects::project::get_contributor_by_id;
use crate::backend::projects::secrets::create::machine_values_insert_query_builder;
use axum::http::StatusCode;
use secretpass_api::secrets::CreateMachinePublicKeyRequest;
use secretpass_core::{InternalError, InternalResult, MachinePublicKey, User, source};
use sqlx::PgPool;
use uuid::Uuid;

// language=sql
const INSERT_MACHINE_PUBLIC_QUERY: &str = r#"
    INSERT INTO "MachinePublicKeys"
        (id, name, description, project_id, environments, ecc, kem, generated_by)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    RETURNING *
"#;

pub async fn create_machine_public_key(
    pool: &PgPool,
    user: &User,
    project_id: Uuid,
    request: CreateMachinePublicKeyRequest,
) -> InternalResult<MachinePublicKey> {
    let mut tx = pool.begin().await.map_err(|err| {
        InternalError::trace(
            source!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error establishing a transaction",
            err,
        )
    })?;

    let contributor = get_contributor_by_id(pool, user, project_id)
        .await?
        .ok_or_else(|| {
            InternalError::new(
                source!(),
                StatusCode::FORBIDDEN,
                "You do not have access to this project",
            )
        })?;

    contributor.is_admin().ok_or_else(|| {
        InternalError::new(
            source!(),
            StatusCode::FORBIDDEN,
            "Only admins can create direct access keys",
        )
    })?;

    let machine_key = sqlx::query_as(INSERT_MACHINE_PUBLIC_QUERY)
        .bind(request.id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(project_id)
        .bind(request.access.clone())
        .bind(request.public_key)
        .bind(&user.email)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| {
            InternalError::trace(
                source!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error creating direct access key",
                err,
            )
        })?;

    // TODO: Verify that the targets are matching
    if !request.encrypted_values.is_empty() {
        machine_values_insert_query_builder(project_id, &request.encrypted_values)
            .build()
            .execute(&mut *tx)
            .await
            .map_err(|err| {
                InternalError::trace(
                    source!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error adding access key values",
                    err,
                )
            })?;
    }

    tx.commit().await.map_err(|err| {
        InternalError::trace(
            source!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error committing access key creation",
            err,
        )
    })?;

    Ok(machine_key)
}
