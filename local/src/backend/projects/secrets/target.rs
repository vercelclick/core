use crate::config::LocalServiceConfig;
use crate::service::keys::LocalKeysConfig;
use click_api::backend::secrets::ProjectSecretPathParams;
use click_core::{AuthSession, InternalResult, TargetedPublicKey};
use uuid::Uuid;

pub async fn get_secret_targets(
    session: &AuthSession,
    params: ProjectSecretPathParams,
) -> InternalResult<Vec<TargetedPublicKey>> {
    let service_config = LocalServiceConfig::load()?;

    let (path, project_config, _) =
        service_config.get_project_and_contributor(params.project_id, session.user.id)?;

    let keys_config = LocalKeysConfig::load(&path)?;

    let allowed_contributors: Vec<Uuid> = project_config
        .contributors
        .iter()
        .filter(|(_, cont)| match cont.get_access(&params.env_name) {
            Some(access) => access.can_read_secret(&params.secret_name),
            None => false,
        })
        .map(|(_, cont)| cont.id)
        .collect();

    let mut target_keys: Vec<TargetedPublicKey> = vec![];
    for key in keys_config.access_keys.iter() {
        if let Some(access) = key.get_access(&params.env_name)
            && access.can_read_secret(&params.secret_name)
        {
            target_keys.push(TargetedPublicKey {
                target: key.id,
                value: key.public_key.clone(),
            })
        }
    }

    for key in keys_config.contributors_keys.iter() {
        if allowed_contributors.contains(&key.contributor_id) {
            target_keys.push(TargetedPublicKey {
                target: key.id,
                value: key.public_key.clone(),
            })
        }
    }

    Ok(target_keys)
}
