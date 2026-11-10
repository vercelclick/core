use crate::config::LocalServiceConfig;
use crate::service::keys::LocalKeysConfig;
use crate::service::secrets::LocalSecretConfig;
use chrono::Utc;
use secretpass_api::backend::environments::SecretWithEncryptedValues;
use secretpass_api::backend::secrets::{
    ProjectSecretPathParams, UpdateSecretRequest, UpdateSecretValueRequest,
};
use secretpass_api::constants::{LATEST_SECRET_TAG, PREVIOUS_SECRET_TAG};
use secretpass_core::{Contributor, InternalError, InternalResult, StatusCode, User};

fn get_permitted_secret(
    path: &str,
    contributor: &Contributor,
    params: &ProjectSecretPathParams,
) -> InternalResult<LocalSecretConfig> {
    let access = contributor.get_access(&params.env_name).ok_or_else(|| {
        InternalError::new(
            StatusCode::FORBIDDEN,
            "You don't have access to this environment",
        )
    })?;

    access
        .can_write_secret(&params.secret_name)
        .ok_or_else(|| {
            InternalError::new(
                StatusCode::FORBIDDEN,
                "You do not have permission to update this secret",
            )
        })?;

    LocalSecretConfig::load(&path, &params.env_name, &params.secret_name)?.ok_or_else(|| {
        InternalError::new(
            StatusCode::NOT_FOUND,
            &format!(
                "Secret {}/{} not found",
                &params.env_name, &params.secret_name
            ),
        )
    })
}

pub async fn update_secret(
    user: &User,
    params: ProjectSecretPathParams,
    request: UpdateSecretRequest,
) -> InternalResult<SecretWithEncryptedValues> {
    let local_config = LocalServiceConfig::load()?;

    let (path, _, contributor) =
        local_config.get_project_and_contributor(params.project_id, user.id)?;

    let keys_config = LocalKeysConfig::load(&path)?;

    let mut secret_config = get_permitted_secret(&path, &contributor, &params)?;

    secret_config.definition.comments = request.comments;

    secret_config.definition.updated_at = Utc::now();
    secret_config.write(&path)?;

    let keys = keys_config.get_contributor_keys(contributor.id);

    Ok(secret_config.build_values_for_contributors(&keys))
}

pub async fn update_secret_value(
    user: &User,
    params: ProjectSecretPathParams,
    request: UpdateSecretValueRequest,
) -> InternalResult<SecretWithEncryptedValues> {
    let local_config = LocalServiceConfig::load()?;

    let (path, _, contributor) =
        local_config.get_project_and_contributor(params.project_id, user.id)?;

    let keys_config = LocalKeysConfig::load(&path)?;

    let mut secret_config = get_permitted_secret(&path, &contributor, &params)?;

    // Update the latest values to previous and remove all previous values
    for value in secret_config.values.iter_mut() {
        if value.tag == LATEST_SECRET_TAG {
            value.tag = PREVIOUS_SECRET_TAG.to_string();
        }
    }

    secret_config
        .values
        .extend_from_slice(&request.encrypted_values);

    secret_config.definition.updated_at = Utc::now();
    secret_config.write(&path)?;

    let keys = keys_config.get_contributor_keys(contributor.id);

    Ok(secret_config.build_values_for_contributors(&keys))
}
