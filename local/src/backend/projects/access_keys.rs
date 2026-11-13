use crate::backend::auth::validate_passkey_auth;
use crate::config::LocalServiceConfig;
use crate::service::keys::LocalKeysConfig;
use crate::service::secrets::LocalSecretConfig;
use chrono::Utc;
use click_api::backend::secrets::CreateAccessKeyRequest;
use click_core::{AccessKey, AuthSession, InternalError, InternalResult, StatusCode, caller};
use uuid::Uuid;

pub async fn create_access_key(
    session: &AuthSession,
    project_id: Uuid,
    request: CreateAccessKeyRequest,
) -> InternalResult<AccessKey> {
    validate_passkey_auth(session, &request.auth_result).await?;
    let local_config = LocalServiceConfig::load()?;

    let (path, project_conf) = local_config.get_project_by_id(project_id)?.ok_or_else(|| {
        InternalError::new(
            caller!(),
            StatusCode::NOT_FOUND,
            "Project not found, ensure the project is attached",
        )
    })?;

    project_conf
        .get_contributor_by_user_id(session.user.id)
        .ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::FORBIDDEN,
                "User not found in project",
            )
        })?;

    let mut keys_config = LocalKeysConfig::load(&path)?;

    let access_key = AccessKey {
        id: request.id,
        name: request.name.clone(),
        description: request.description.clone(),
        project_id,
        public_key: request.public_key,
        access: request.access.clone(),
        generated_by: session.user.email.clone(),
        generated_on: Utc::now(),
    };

    keys_config.access_keys.push(access_key.clone());
    keys_config.write(&path)?;

    for value in request.encrypted_values.iter() {
        let mut secret_config = LocalSecretConfig::load(&path, &value.env_name, &value.name)?
            .ok_or_else(|| {
                InternalError::new(
                    caller!(),
                    StatusCode::NOT_FOUND,
                    &format!("Secret {}/{} not found", value.env_name, value.name),
                )
            })?;
        secret_config.values.push(value.clone());

        secret_config.write(&path)?;
    }

    Ok(access_key)
}
