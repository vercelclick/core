use crate::backend::projects::project::get_contributor_by_id;
use crate::backend::projects::secrets::create::{
    contributor_values_insert_query_builder, machine_values_insert_query_builder,
};
use secretpass_api::constants::{LATEST_SECRET_TAG, PREVIOUS_SECRET_TAG};
use secretpass_api::environments::SecretWithEncryptedValues;
use secretpass_api::secrets::{
    ProjectSecretPathParams, UpdateSecretRequest, UpdateSecretValueRequest,
};
use secretpass_core::{ContributorPublicKey, ContributorSecretValue, SecretDefinition, User};
use sqlx::PgPool;
use uuid::Uuid;

pub async fn update_secret(
    pool: &PgPool,
    user: &User,
    params: ProjectSecretPathParams,
    request: UpdateSecretRequest,
) -> anyhow::Result<SecretWithEncryptedValues> {
    let contributor = get_contributor_by_id(pool, user, params.project_id)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("You don't have access to this project under the current user")
        })?;

    contributor
        .can_access(&params.env_name)
        .ok_or_else(|| anyhow::anyhow!("You don't have access to this environment"))?;

    let definition: SecretDefinition = sqlx::query_as(
        r#"UPDATE "SecretDefinitions" SET comments=$1, updated_at=now() WHERE project_id=$2 AND env_name=$3 AND name=$4 RETURNING *"#
    ).bind(request.comments).bind(params.project_id).bind(&params.env_name).bind(&params.secret_name).fetch_one(pool).await?;

    build_return_value(pool, contributor.id, definition).await
}

pub async fn update_secret_value(
    pool: &PgPool,
    user: &User,
    params: ProjectSecretPathParams,
    request: UpdateSecretValueRequest,
) -> anyhow::Result<SecretWithEncryptedValues> {
    let contributor = get_contributor_by_id(pool, user, params.project_id)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("You don't have access to this project under the current user")
        })?;

    contributor
        .can_access(&params.env_name)
        .ok_or_else(|| anyhow::anyhow!("You don't have access to this environment"))?;

    let mut tx = pool.begin().await?;

    let definition: SecretDefinition = sqlx::query_as(r#"UPDATE "SecretDefinitions" SET updated_at=now() WHERE project_id=$1 AND env_name=$2 AND name=$3 RETURNING *"#)
        .bind(params.project_id)
        .bind(&params.env_name)
        .bind(&params.secret_name)
        .fetch_one(&mut *tx)
        .await?;

    // Delete previous values
    sqlx::query(r#"DELETE FROM "ContributorSecretValues" WHERE project_id=$1 AND env_name=$2 AND name=$3 AND tag=$4"#).bind(params.project_id)
        .bind(&params.env_name)
        .bind(&params.secret_name).bind(PREVIOUS_SECRET_TAG).execute(&mut *tx).await?;

    sqlx::query(r#"DELETE FROM "MachineSecretValues" WHERE project_id=$1 AND env_name=$2 AND name=$3 AND tag=$4"#).bind(params.project_id)
        .bind(&params.env_name)
        .bind(&params.secret_name).bind(PREVIOUS_SECRET_TAG).execute(&mut *tx).await?;

    // Set latest values to previous values
    sqlx::query(
        r#"UPDATE "ContributorSecretValues" SET tag=$1 WHERE project_id=$2 AND env_name=$3 AND name=$4 AND tag=$5"#
    ).bind(PREVIOUS_SECRET_TAG).bind(params.project_id)
        .bind(&params.env_name)
        .bind(&params.secret_name).bind(LATEST_SECRET_TAG).execute(&mut *tx).await?;

    sqlx::query(
        r#"UPDATE "MachineSecretValues" SET tag=$1 WHERE project_id=$2 AND env_name=$3 AND name=$4 AND tag=$5"#
    ).bind(PREVIOUS_SECRET_TAG).bind(params.project_id)
        .bind(&params.env_name)
        .bind(&params.secret_name).bind(LATEST_SECRET_TAG).execute(&mut *tx).await?;

    contributor_values_insert_query_builder(params.project_id, &request.contributors_values)
        .build()
        .execute(&mut *tx)
        .await?;
    if !request.machines_values.is_empty() {
        machine_values_insert_query_builder(params.project_id, &request.machines_values)
            .build()
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;

    build_return_value(pool, contributor.id, definition).await
}

async fn build_return_value(
    pool: &PgPool,
    contributor_id: Uuid,
    definition: SecretDefinition,
) -> anyhow::Result<SecretWithEncryptedValues> {
    let contributor_values: Vec<ContributorSecretValue> = sqlx::query_as(
        r#"SELECT * FROM "ContributorSecretValues" WHERE target=$1 AND env_name=$2 AND name=$3"#,
    )
    .bind(definition.project_id)
    .bind(&definition.env_name)
    .bind(&definition.name)
    .fetch_all(pool)
    .await?;

    let contributor_keys: Vec<ContributorPublicKey> =
        sqlx::query_as(r#"SELECT * FROM "ContributorPublicKeys" WHERE contributor_id=$1"#)
            .bind(contributor_id)
            .fetch_all(pool)
            .await?;

    Ok(SecretWithEncryptedValues::extract(
        &definition,
        &contributor_keys,
        &contributor_values,
    ))
}
