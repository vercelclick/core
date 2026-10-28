use crate::config::LocalServiceConfig;
use crate::service::keys::LocalKeysConfig;
use crate::service::secrets::LocalSecretConfig;
use chrono::Utc;
use secretpass_api::constants::LATEST_SECRET_TAG;
use secretpass_api::environments::SecretWithEncryptedValues;
use secretpass_api::secrets::{CreateSecretParams, CreateSecretRequest};
use secretpass_core::{
    MachineSecretValue, PasskeySecretValue, SecretDataType, SecretDefinition, SpassUser,
};

pub async fn create_secret(
    user: &SpassUser,
    params: CreateSecretParams,
    request: CreateSecretRequest,
) -> anyhow::Result<SecretWithEncryptedValues> {
    let local_config = LocalServiceConfig::load()?;

    let (path, project_conf) = local_config
        .get_project_by_id(params.project_id)?
        .ok_or_else(|| anyhow::anyhow!("Project not found, confirm if the project is attached"))?;

    let project_user = project_conf.get_user(user.id).ok_or_else(|| {
        anyhow::anyhow!("You don't have access to this project under the current user")
    })?;

    project_user
        .can_access(&params.env_name)
        .ok_or_else(|| anyhow::anyhow!("You don't have access to this environment"))?;

    // Avoid overwriting existing secrets
    LocalSecretConfig::load(&path, &params.env_name, &request.name)?
        .is_none()
        .ok_or_else(|| anyhow::format_err!("{} already exists", request.name))?;

    let environment = project_conf
        .get_environment(&params.env_name)
        .ok_or_else(|| anyhow::format_err!("Environment '{}' not found", params.env_name))?;

    let passkey_values = request
        .user_values
        .iter()
        .map(|value| PasskeySecretValue {
            name: request.name.clone(),
            env_name: environment.name.clone(),
            tag: LATEST_SECRET_TAG.to_string(),
            passkey_id: value.passkey_id,
            encrypted_value: value.encrypted_value.clone(),
            project_id: params.project_id,
            data_type: SecretDataType::Text,
            created_at: Utc::now(),
        })
        .collect();

    let machine_values = request
        .machine_values
        .iter()
        .map(|value| MachineSecretValue {
            name: request.name.clone(),
            env_name: environment.name.clone(),
            tag: LATEST_SECRET_TAG.to_string(),
            machine_id: value.machine_id.clone(),
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
        passkey_values,
    };

    let keys_config = LocalKeysConfig::load(&path)?;

    secret_config.write(&path, &environment.name)?;

    Ok(secret_config.build_values_for_user(&keys_config.get_user_keys(project_user.id)))
}
