use crate::config::LocalServiceConfig;
use crate::service::keys::LocalKeysConfig;
use crate::service::secrets::LocalSecretConfig;
use chrono::Utc;
use secretpass_api::backend::secrets::CreateAccessKeyRequest;
use secretpass_core::{AccessKey, InternalError, InternalResult, StatusCode, User};
use uuid::Uuid;

pub async fn create_access_key(
    user: &User,
    project_id: Uuid,
    request: CreateAccessKeyRequest,
) -> InternalResult<AccessKey> {
    let local_config = LocalServiceConfig::load()?;

    let (path, project_conf) = local_config.get_project_by_id(project_id)?.ok_or_else(|| {
        InternalError::new(
            StatusCode::NOT_FOUND,
            "Project not found, ensure the project is attached",
        )
    })?;

    project_conf
        .get_contributor_by_user_id(user.id)
        .ok_or_else(|| InternalError::new(StatusCode::FORBIDDEN, "User not found in project"))?;

    let mut keys_config = LocalKeysConfig::load(&path)?;

    let access_key = AccessKey {
        id: request.id,
        name: request.name.clone(),
        description: request.description.clone(),
        project_id,
        public_key: request.public_key,
        access: request.access.clone(),
        generated_by: user.email.clone(),
        generated_on: Utc::now(),
    };

    keys_config.access_keys.push(access_key.clone());
    keys_config.write(&path)?;

    for value in request.encrypted_values.iter() {
        let mut secret_config = LocalSecretConfig::load(&path, &value.env_name, &value.name)?
            .ok_or_else(|| {
                InternalError::new(
                    StatusCode::NOT_FOUND,
                    &format!("Secret {}/{} not found", value.env_name, value.name),
                )
            })?;
        secret_config.values.push(value.clone());

        secret_config.write(&path)?;
    }

    Ok(access_key)
}
