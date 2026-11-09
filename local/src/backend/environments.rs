use crate::config::LocalServiceConfig;
use crate::service::keys::LocalKeysConfig;
use crate::service::secrets::LocalSecretConfig;
use secretpass_api::environments::{GetEnvironmentRequest, GetEnvironmentResult};
use secretpass_core::{InternalResult, User};

pub async fn get_environment_by_name(
    user: &User,
    request: &GetEnvironmentRequest,
) -> InternalResult<Option<GetEnvironmentResult>> {
    let local_config = LocalServiceConfig::load()?;

    let (path, project_config) = match local_config.get_project_by_id(request.project_id)? {
        Some(res) => res,
        None => return Ok(None),
    };

    let contributor = match project_config.get_contributor_by_user_id(user.id) {
        Some(res) => res,
        None => return Ok(None),
    };

    if contributor.get_access(&request.env_name).is_none() {
        return Ok(None);
    }

    let environment = match project_config.get_environment(&request.env_name) {
        Some(res) => res,
        None => return Ok(None),
    };

    let secret_configs = LocalSecretConfig::load_env(&path, &environment.name)?;

    let keys_config = LocalKeysConfig::load(&path)?;

    let contributor_keys = keys_config.get_contributor_keys(contributor.id);

    let secrets = secret_configs
        .iter()
        .map(|config| config.build_values_for_contributors(&contributor_keys))
        .collect();

    Ok(Some(GetEnvironmentResult {
        environment,
        secrets,
    }))
}
