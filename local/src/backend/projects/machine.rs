use crate::config::LocalServiceConfig;
use crate::service::keys::LocalKeysConfig;
use crate::service::secrets::LocalSecretConfig;
use chrono::Utc;
use secretpass_api::secrets::CreateMachinePublicKeyRequest;
use secretpass_core::{MachinePublicKey, MachineSecretValue, User};
use uuid::Uuid;

pub async fn create_machine_public_key(
    user: &User,
    project_id: Uuid,
    request: CreateMachinePublicKeyRequest,
) -> anyhow::Result<MachinePublicKey> {
    let local_config = LocalServiceConfig::load()?;

    let (path, project_conf) = local_config
        .get_project_by_id(project_id)?
        .ok_or_else(|| anyhow::anyhow!("Project not found, ensure the project is attached"))?;

    project_conf
        .get_contributor_by_user_id(user.id)
        .ok_or_else(|| anyhow::anyhow!("User not found in project"))?;

    let mut keys_config = LocalKeysConfig::load(&path)?;

    let machine_key = MachinePublicKey {
        id: request.public_key.id,
        name: request.name.clone(),
        description: request.description.clone(),
        project_id,
        ecc: request.public_key.ecc.clone(),
        kem: request.public_key.kem.clone(),
        environments: request.environments.clone(),
        generated_by: user.email.clone(),
        generated_on: Utc::now(),
    };

    keys_config.machines_keys.push(machine_key.clone());
    keys_config.write(&path)?;

    for value in request.machine_secrets.iter() {
        let mut secret_config = LocalSecretConfig::load(&path, &value.environment, &value.name)?
            .ok_or_else(|| {
                anyhow::format_err!("Secret {}/{} not found", value.environment, value.name)
            })?;
        secret_config.machine_values.push(MachineSecretValue {
            name: value.name.clone(),
            tag: value.tag.clone(),
            target: value.target.clone(),
            project_id,
            env_name: value.environment.clone(),
            data_type: value.data_type,
            created_at: Utc::now(),
            encrypted_value: value.encrypted_value.clone(),
        });

        secret_config.write(&path, &value.environment)?;
    }

    Ok(machine_key)
}
