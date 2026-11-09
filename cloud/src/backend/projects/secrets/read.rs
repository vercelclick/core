use secretpass_api::secrets::ProjectAccessKeyParams;
use secretpass_core::{
    AccessKey, InternalError, InternalResult, SecretDefinition, SecretValue, StatusCode, source,
};
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

pub async fn get_secret_by_name(
    pool: &PgPool,
    project_id: Uuid,
    env_name: &str,
    secret_name: &str,
) -> InternalResult<Option<SecretDefinition>> {
    let definition: Option<SecretDefinition> = sqlx::query_as(
        r#"SELECT * FROM "SecretDefinitions" WHERE project_id=$1 AND env_name=$2 AND name=$3"#,
    )
    .bind(project_id)
    .bind(env_name)
    .bind(secret_name)
    .fetch_optional(pool)
    .await
    .map_err(|err| {
        InternalError::trace(
            source!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error getting secret details",
            err,
        )
    })?;

    Ok(definition)
}

pub async fn get_access_key_secrets(
    pool: &PgPool,
    params: ProjectAccessKeyParams,
) -> InternalResult<HashMap<String, String>> {
    let access_key: Option<AccessKey> = sqlx::query_as(
        r#"SELECT * FROM "AccessKeys"
         WHERE project_id = $1 AND id = $2"#,
    )
    .bind(params.project_id)
    .bind(params.key_id)
    .fetch_optional(pool)
    .await
    .map_err(|err| {
        InternalError::trace(
            source!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error getting access key details",
            err,
        )
    })?;

    let access_key = access_key.ok_or_else(|| {
        InternalError::new(source!(), StatusCode::NOT_FOUND, "Public key not found")
    })?;
    let access = access_key.get_access(&params.env_name).ok_or_else(|| {
        InternalError::new(
            source!(),
            StatusCode::FORBIDDEN,
            "Access key does not have access to this environment",
        )
    })?;

    let values: Vec<SecretValue> = sqlx::query_as(
        r#"SELECT * FROM "MachineSecretValues"
         WHERE project_id = $1 AND target = $2 AND env_name = $3 AND tag = $4"#,
    )
    .bind(access_key.project_id)
    .bind(access_key.id)
    .bind(&params.env_name)
    .bind(&params.tag_name)
    .fetch_all(pool)
    .await
    .map_err(|err| {
        InternalError::trace(
            source!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error getting secret values",
            err,
        )
    })?;

    let values: Vec<SecretValue> = values
        .iter()
        .filter(|value| access.can_read_secret(&value.name))
        .cloned()
        .collect();

    let mut encrypted_secrets: HashMap<String, String> = HashMap::new();
    for value in values {
        encrypted_secrets.insert(value.name, value.encrypted_value);
    }

    Ok(encrypted_secrets)
}
