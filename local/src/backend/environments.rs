use crate::backend::auth::validate_passkey_auth;
use crate::config::LocalServiceConfig;
use crate::service::keys::LocalKeysConfig;
use crate::service::secrets::LocalSecretConfig;
use chrono::Utc;
use click_api::backend::environments::{
    CreateEnvironmentRequest, GetEnvironmentRequest, GetEnvironmentResult,
};
use click_core::{
    AuthSession, Environment, InternalError, InternalResult, StatusCode, User, caller,
};
use uuid::Uuid;

pub(crate) async fn get_environment_by_name(
    user: &User,
    request: &GetEnvironmentRequest,
) -> InternalResult<Option<GetEnvironmentResult>> {
    let local_config = LocalServiceConfig::load()?;

    let (path, project_conf, contributor) =
        local_config.get_project_and_contributor(request.project_id, user.id)?;

    if contributor.get_access(&request.env_name).is_none() {
        return Ok(None);
    }

    let environment = match project_conf.get_environment(&request.env_name) {
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

pub(crate) async fn create_environment(
    session: &AuthSession,
    project_id: Uuid,
    request: CreateEnvironmentRequest,
) -> InternalResult<GetEnvironmentResult> {
    validate_passkey_auth(session, &request.auth_result).await?;

    let local_config = LocalServiceConfig::load()?;

    let (path, mut project_conf, contributor) =
        local_config.get_project_and_contributor(project_id, session.user.id)?;

    contributor.is_admin().ok_or_else(|| {
        InternalError::new(
            caller!(),
            StatusCode::FORBIDDEN,
            "Only admins can create new environments",
        )
    })?;

    project_conf
        .get_environment(&request.name)
        .is_none()
        .ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::FORBIDDEN,
                "An environment by this name already exists",
            )
        })?;

    let environment = Environment {
        name: request.name,
        description: request.description,
        project_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        tags: vec![],
    };

    project_conf.environments.push(environment.clone());

    project_conf.write(&path)?;

    Ok(GetEnvironmentResult {
        environment,
        secrets: vec![],
    })
}
