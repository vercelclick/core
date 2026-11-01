use crate::service::keys::LocalKeysConfig;
use crate::service::project::LocalProjectConfig;
use crate::service::secrets::LocalSecretConfig;
use secretpass_core::enums::EncryptionAlgorithm;
use secretpass_core::{PrivateKey, PrivateKeySeed};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use uuid::Uuid;

fn parse_machine_key(private_key: String) -> (Uuid, PrivateKey) {
    let (project_id, seed) = PrivateKeySeed::from_machine_key(private_key).expect(
        "Error parsing private, ensure that this is a valid Secretpass Machine Private Key",
    );

    let private_key = PrivateKey::from_seed(seed).expect("Error deriving seeding private key, please raise a support ticket through support@secretpass.cloud");
    (project_id, private_key)
}

pub fn get_values_from_local_project(
    project_dir: Option<String>,
    private_key: String,
    env: String,
    tag: String,
) -> (PrivateKey, HashMap<String, String>) {
    let (project_id, private_key) = parse_machine_key(private_key);

    let project_dir = if let Some(relative) = project_dir {
        fs::canonicalize(Path::new(&relative))
            .expect("Error resolving provided project directory, confirm the directory exists")
    } else {
        env::current_dir().expect("Error getting the current directory, please check permissions")
    };

    let path = &format!("{}", project_dir.display());

    let local_conf = LocalProjectConfig::load(path)
        .unwrap()
        .ok_or_else(|| anyhow::format_err!("Secretpass not found under {path}"))
        .unwrap();

    if local_conf.project.id != project_id {
        panic!("Project ID mismatch, this private key does not belong in this project.")
    }

    let environment = local_conf
        .get_environment(&env)
        .ok_or_else(|| anyhow::format_err!("Environment {env} not found"))
        .unwrap();

    let public_key = private_key.public_key(local_conf.project.algorithm);
    let key_id = &public_key.machine_key_id();

    let keys_conf = LocalKeysConfig::load(path).unwrap();
    let machine_key = keys_conf
        .machines_keys
        .iter()
        .find(|key| &key.id == key_id)
        .expect("Private key not found in this project");

    if !machine_key.can_access(&environment.name) {
        panic!("Key does not have access to {}", env)
    }

    let secrets_configs = LocalSecretConfig::load_env(path, &environment.name).unwrap();

    let mut encrypted_values: HashMap<String, String> = HashMap::new();
    for secret_conf in secrets_configs {
        let value = secret_conf
            .machine_values
            .iter()
            .find(|value| &value.target == key_id && value.tag == tag)
            .ok_or_else(|| {
                anyhow::format_err!(
                    "{} not found in {}:{}",
                    secret_conf.definition.name,
                    secret_conf.definition.env_name,
                    tag
                )
            })
            .unwrap();

        encrypted_values.insert(secret_conf.definition.name, value.encrypted_value.clone());
    }

    (private_key, encrypted_values)
}

pub fn get_values_from_cloud_project(
    endpoint: String,
    private_key: String,
    env: String,
    tag: String,
) -> (PrivateKey, HashMap<String, String>) {
    let (project_id, private_key) = parse_machine_key(private_key);
    let ecc_id = private_key
        .public_key(EncryptionAlgorithm::ECC)
        .machine_key_id();
    let kem_id = private_key
        .public_key(EncryptionAlgorithm::KEM)
        .machine_key_id();
    let hybrid_id = private_key
        .public_key(EncryptionAlgorithm::Hybrid)
        .machine_key_id();

    let url = format!(
        "{endpoint}/project/{}/env/{env}/tag/{tag}/machine-values/{ecc_id}/{kem_id}/{hybrid_id}",
        project_id.to_string()
    );

    let response = reqwest::blocking::get(url)
        .map_err(|err| anyhow::format_err!("Error fetching cloud secrets: {:?}", err))
        .unwrap();

    if !response.status().is_success() {
        eprintln!("Error {} reading secrets", response.status().to_string());
        panic!("{}", response.text().unwrap())
    }

    let encrypted_values: HashMap<String, String> = response
        .json()
        .map_err(|err| anyhow::format_err!("Error decoding cloud response: {:?}", err))
        .unwrap();

    (private_key, encrypted_values)
}
