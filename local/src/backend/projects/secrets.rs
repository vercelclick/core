use crate::config::LocalServiceConfig;
use crate::service::keys::LocalKeysConfig;
use crate::service::secrets::LocalSecretConfig;
use chrono::Utc;
use secretpass_api::constants::LATEST_SECRET_TAG;
use secretpass_api::environments::SecretWithEncryptedValues;
use secretpass_api::secrets::{CreateSecretRequest, ProjectEnvPathParams};
use secretpass_core::enums::SecretDataType;
use secretpass_core::{ContributorSecretValue, MachineSecretValue, SecretDefinition, User};

pub async fn create_secret(
    user: &User,
    params: ProjectEnvPathParams,
    request: CreateSecretRequest,
) -> anyhow::Result<SecretWithEncryptedValues> {
    let local_config = LocalServiceConfig::load()?;

    let (path, project_conf) = local_config
        .get_project_by_id(params.project_id)?
        .ok_or_else(|| anyhow::anyhow!("Project not found, confirm if the project is attached"))?;

    let contributor = project_conf
        .get_contributor_by_user_id(user.id)
        .ok_or_else(|| {
            anyhow::anyhow!("You don't have access to this project under the current user")
        })?;

    contributor
        .can_access(&params.env_name)
        .ok_or_else(|| anyhow::anyhow!("You don't have access to this environment"))?;

    // Avoid overwriting existing secrets
    LocalSecretConfig::load(&path, &params.env_name, &request.name)?
        .is_none()
        .ok_or_else(|| anyhow::format_err!("{} already exists", request.name))?;

    let environment = project_conf
        .get_environment(&params.env_name)
        .ok_or_else(|| anyhow::format_err!("Environment '{}' not found", params.env_name))?;

    let contributor_values = request
        .contributors_values
        .iter()
        .map(|value| ContributorSecretValue {
            name: request.name.clone(),
            env_name: environment.name.clone(),
            tag: LATEST_SECRET_TAG.to_string(),
            target: value.target,
            encrypted_value: value.encrypted_value.clone(),
            project_id: params.project_id,
            data_type: SecretDataType::Text,
            created_at: Utc::now(),
        })
        .collect();

    let machine_values = request
        .machines_values
        .iter()
        .map(|value| MachineSecretValue {
            name: request.name.clone(),
            env_name: environment.name.clone(),
            tag: LATEST_SECRET_TAG.to_string(),
            target: value.target.clone(),
            encrypted_value: value.encrypted_value.clone(),
            project_id: params.project_id,
            data_type: SecretDataType::Text,
            created_at: Utc::now(),
        })
        .collect();

    let definition = SecretDefinition {
        name: request.name.clone(),
        env_name: environment.name.clone(),
        project_id: params.project_id,
        comments: request.comments,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let secret_config = LocalSecretConfig {
        definition,
        machine_values,
        contributor_values,
    };

    let keys_config = LocalKeysConfig::load(&path)?;

    secret_config.write(&path, &environment.name)?;

    Ok(secret_config
        .build_values_for_contributors(&keys_config.get_contributor_keys(contributor.id)))
}
