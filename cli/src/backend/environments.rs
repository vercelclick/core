use crate::config::LocalServiceConfig;
use crate::service::keys::LocalKeysConfig;
use crate::service::secrets::LocalSecretConfig;
use secretpass_api::environments::{GetEnvironmentRequest, GetEnvironmentResult};
use secretpass_core::SpassUser;

pub async fn get_environment_by_name(
    user: &SpassUser,
    request: &GetEnvironmentRequest,
) -> anyhow::Result<Option<GetEnvironmentResult>> {
    let local_config = LocalServiceConfig::load()?;

    let (path, project_config) = match local_config.get_project_by_id(request.project_id)? {
        Some(res) => res,
        None => return Ok(None),
    };

    let project_user = match project_config.get_user(user.id) {
        Some(res) => res,
        None => return Ok(None),
    };

    if !project_user.can_access(&request.env_name) {
        return Ok(None);
    }

    let environment = match project_config.get_environment(&request.env_name) {
        Some(res) => res,
        None => return Ok(None),
    };

    let secret_configs = LocalSecretConfig::load_env(&path, &environment.name)?;

    let keys_config = LocalKeysConfig::load(&path)?;

    let current_user_keys = keys_config.get_user_keys(project_user.id);

    let secrets = secret_configs
        .iter()
        .map(|config| config.build_values_for_user(&current_user_keys))
        .collect();

    let (passkeys, machines) = keys_config
        .get_environment_machine_keys(&request.env_name, &project_config.project_users());

    Ok(Some(GetEnvironmentResult {
        environment,
        secrets,
        machines,
        passkeys,
    }))
}
