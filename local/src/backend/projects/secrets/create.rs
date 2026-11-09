use crate::config::LocalServiceConfig;
use crate::service::keys::LocalKeysConfig;
use crate::service::secrets::LocalSecretConfig;
use chrono::Utc;
use secretpass_api::environments::SecretWithEncryptedValues;
use secretpass_api::secrets::{CreateSecretRequest, ProjectEnvPathParams};
use secretpass_core::{InternalError, InternalResult, SecretDefinition, StatusCode, User, source};

pub async fn create_secret(
    user: &User,
    params: ProjectEnvPathParams,
    request: CreateSecretRequest,
) -> InternalResult<SecretWithEncryptedValues> {
    let local_config = LocalServiceConfig::load()?;

    let (path, project_conf, contributor) =
        local_config.get_project_and_contributor(params.project_id, user.id)?;

    let access = contributor.get_access(&params.env_name).ok_or_else(|| {
        InternalError::new(
            source!(),
            StatusCode::FORBIDDEN,
            "You don't have access to this environment",
        )
    })?;

    access.is_env_admin().ok_or_else(|| {
        InternalError::new(
            source!(),
            StatusCode::FORBIDDEN,
            "You do not have permission to add secrets to this environment",
        )
    })?;

    let environment = project_conf
        .get_environment(&params.env_name)
        .ok_or_else(|| {
            InternalError::new(
                source!(),
                StatusCode::NOT_FOUND,
                &format!("Environment '{}' not found", params.env_name),
            )
        })?;

    // Avoid overwriting existing secrets
    LocalSecretConfig::load(&path, &params.env_name, &request.name)?
        .is_none()
        .ok_or_else(|| {
            InternalError::new(
                source!(),
                StatusCode::CONFLICT,
                &format!(
                    "Secret {}/{} already exists",
                    &params.env_name, &request.name
                ),
            )
        })?;

    let definition = SecretDefinition {
        name: request.name.clone(),
        env_name: environment.name.clone(),
        project_id: params.project_id,
        comments: request.comments,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        tags: vec![],
    };

    let secret_config = LocalSecretConfig {
        definition,
        values: request.encrypted_values,
    };

    let keys_config = LocalKeysConfig::load(&path)?;

    secret_config.write(&path)?;

    Ok(secret_config
        .build_values_for_contributors(&keys_config.get_contributor_keys(contributor.id)))
}
