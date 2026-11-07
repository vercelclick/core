use crate::config::LocalServiceConfig;
use crate::service::keys::LocalKeysConfig;
use crate::service::secrets::LocalSecretConfig;
use chrono::Utc;
use secretpass_api::constants::{LATEST_SECRET_TAG, PREVIOUS_SECRET_TAG};
use secretpass_api::environments::SecretWithEncryptedValues;
use secretpass_api::secrets::{
    ProjectSecretPathParams, UpdateSecretRequest, UpdateSecretValueRequest,
};
use secretpass_core::{ContributorSecretValue, MachineSecretValue, User};

pub async fn update_secret(
    user: &User,
    params: ProjectSecretPathParams,
    request: UpdateSecretRequest,
) -> anyhow::Result<SecretWithEncryptedValues> {
    let local_config = LocalServiceConfig::load()?;

    let (path, _, contributor) =
        local_config.get_project_and_contributor(params.project_id, user.id)?;

    let keys_config = LocalKeysConfig::load(&path)?;

    contributor
        .can_access(&params.env_name)
        .ok_or_else(|| anyhow::anyhow!("You don't have access to this environment"))?;

    let mut secret_config = LocalSecretConfig::load(&path, &params.env_name, &params.secret_name)?
        .ok_or_else(|| anyhow::anyhow!("Secret not found"))?;

    secret_config.definition.comments = request.comments;

    secret_config.definition.updated_at = Utc::now();
    secret_config.write(&path, &params.env_name)?;

    let keys = keys_config.get_contributor_keys(contributor.id);

    Ok(secret_config.build_values_for_contributors(&keys))
}

pub async fn update_secret_value(
    user: &User,
    params: ProjectSecretPathParams,
    request: UpdateSecretValueRequest,
) -> anyhow::Result<SecretWithEncryptedValues> {
    let local_config = LocalServiceConfig::load()?;

    let (path, _, contributor) =
        local_config.get_project_and_contributor(params.project_id, user.id)?;

    let keys_config = LocalKeysConfig::load(&path)?;

    contributor
        .can_access(&params.env_name)
        .ok_or_else(|| anyhow::anyhow!("You don't have access to this environment"))?;

    let mut secret_config = LocalSecretConfig::load(&path, &params.env_name, &params.secret_name)?
        .ok_or_else(|| anyhow::anyhow!("Secret not found"))?;

    // Update the latest values to previous and remove all previous values
    for value in secret_config.machine_values.iter_mut() {
        if value.tag == LATEST_SECRET_TAG {
            value.tag = PREVIOUS_SECRET_TAG.to_string();
        }
    }
    for value in secret_config.contributor_values.iter_mut() {
        if value.tag == LATEST_SECRET_TAG {
            value.tag = PREVIOUS_SECRET_TAG.to_string();
        }
    }

    for value in request.machines_values {
        secret_config.machine_values.push(MachineSecretValue {
            name: value.name,
            tag: LATEST_SECRET_TAG.to_string(),
            encrypted_value: value.encrypted_value,
            env_name: value.environment,
            project_id: params.project_id,
            created_at: Utc::now(),
            data_type: value.data_type,
            target: value.target,
        });
    }

    for value in request.contributors_values {
        secret_config
            .contributor_values
            .push(ContributorSecretValue {
                name: value.name,
                tag: LATEST_SECRET_TAG.to_string(),
                encrypted_value: value.encrypted_value,
                env_name: value.environment,
                project_id: params.project_id,
                created_at: Utc::now(),
                data_type: value.data_type,
                target: value.target,
            });
    }

    secret_config.definition.updated_at = Utc::now();
    secret_config.write(&path, &params.env_name)?;

    let keys = keys_config.get_contributor_keys(contributor.id);

    Ok(secret_config.build_values_for_contributors(&keys))
}
