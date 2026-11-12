use crate::db;
use click_api::backend::secrets::ProjectAccessKeyParams;
use click_core::{
    AccessKey, InternalError, InternalResult, SecretDefinition, SecretValue, StatusCode, caller,
};
use std::collections::HashMap;
use uuid::Uuid;

pub async fn get_secret_by_name(
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
    .fetch_optional(db::pool())
    .await
    .map_err(|err| {
        InternalError::trace(
            caller!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error getting secret details",
            err,
        )
    })?;

    Ok(definition)
}

pub async fn get_access_key_secrets(
    params: ProjectAccessKeyParams,
) -> InternalResult<HashMap<String, String>> {
    let access_key: Option<AccessKey> = sqlx::query_as(
        r#"SELECT * FROM "AccessKeys"
         WHERE project_id = $1 AND id = $2"#,
    )
    .bind(params.project_id)
    .bind(params.key_id)
    .fetch_optional(db::pool())
    .await
    .map_err(|err| {
        InternalError::trace(
            caller!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error getting access key details",
            err,
        )
    })?;

    let access_key = access_key.ok_or_else(|| {
        InternalError::new(caller!(), StatusCode::NOT_FOUND, "Public key not found")
    })?;
    let access = access_key.get_access(&params.env_name).ok_or_else(|| {
        InternalError::new(
            caller!(),
            StatusCode::FORBIDDEN,
            "Access key does not have access to this environment",
        )
    })?;

    let values: Vec<SecretValue> = sqlx::query_as(
        r#"SELECT * FROM "SecretValues"
         WHERE project_id = $1 AND target = $2 AND env_name = $3 AND tag = $4"#,
    )
    .bind(access_key.project_id)
    .bind(access_key.id)
    .bind(&params.env_name)
    .bind(&params.tag_name)
    .fetch_all(db::pool())
    .await
    .map_err(|err| {
        InternalError::trace(
            caller!(),
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
