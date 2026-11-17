use crate::service::keys::LocalKeysConfig;
use crate::service::project::LocalProjectConfig;
use crate::service::secrets::LocalSecretConfig;
use click_core::{InternalError, KeyPair, PrivateKeySeed, StatusCode, caller};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use uuid::Uuid;

fn parse_access_key(access_key: String) -> (Uuid, KeyPair) {
    let (project_id, seed) = PrivateKeySeed::from_access_key(access_key)
        .expect("Error parsing private, ensure that this is a valid Click Vault Access Key");

    let private_key = KeyPair::from_seed(seed).expect("Error deriving seeding access key, please raise a support ticket through support@vercel.click");
    (project_id, private_key)
}

pub fn get_values_from_local_project(
    project_dir: Option<String>,
    access_key: String,
    env: String,
    tag: String,
) -> HashMap<String, String> {
    let (project_id, private_key) = parse_access_key(access_key);

    let project_dir = if let Some(relative) = project_dir {
        fs::canonicalize(Path::new(&relative))
            .expect("Error resolving provided project directory, confirm the directory exists")
    } else {
        env::current_dir().expect("Error getting the current directory, please check permissions")
    };

    let path = &format!("{}", project_dir.display());

    let local_conf = LocalProjectConfig::load(path)
        .unwrap()
        .ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::NOT_FOUND,
                &format!("Click Local Vault not found under {path}"),
            )
        })
        .unwrap();

    if local_conf.project.id != project_id {
        panic!("Project ID mismatch, this access key does not belong in this project.")
    }

    let environment = local_conf
        .get_environment(&env)
        .ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::NOT_FOUND,
                &format!("Environment {env} not found"),
            )
        })
        .unwrap();

    let public_key = private_key.public_key();
    let key_id = public_key.access_key_id();

    let keys_conf = LocalKeysConfig::load(path).unwrap();
    let access_key = keys_conf
        .access_keys
        .iter()
        .find(|key| key.id == key_id)
        .expect("Access key not found in this project");

    if access_key.get_access(&environment.name).is_none() {
        panic!("Key does not have access to {}", env)
    }

    let secrets_configs = LocalSecretConfig::load_env(path, &environment.name).unwrap();

    let mut encrypted_values: HashMap<String, String> = HashMap::new();
    for secret_conf in secrets_configs {
        let value = secret_conf
            .values
            .iter()
            .find(|value| value.target == key_id && value.tag == tag)
            .ok_or_else(|| {
                InternalError::new(
                    caller!(),
                    StatusCode::NOT_FOUND,
                    &format!(
                        "{} not found in {}:{}",
                        secret_conf.definition.name, secret_conf.definition.env_name, tag
                    ),
                )
            })
            .unwrap();

        encrypted_values.insert(secret_conf.definition.name, value.encrypted_value.clone());
    }

    private_key.decrypt_package(&encrypted_values).unwrap()
}

#[cfg(debug_assertions)]
const DEFAULT_ENDPOINT: &str = "http://localhost:8080";

#[cfg(not(debug_assertions))]
const DEFAULT_ENDPOINT: &str = "https://api.vercel.click";

pub fn get_values_from_cloud_project(
    endpoint: Option<String>,
    private_key: String,
    env_name: String,
    tag_name: String,
) -> HashMap<String, String> {
    let (project_id, private_key) = parse_access_key(private_key);
    let key_id = private_key.public_key().access_key_id();

    let endpoint = endpoint.unwrap_or(DEFAULT_ENDPOINT.to_string());

    let url = format!(
        "{endpoint}/api/projects/{project_id}/access-keys/{key_id}/env/{env_name}/tag/{tag_name}"
    );

    let response = reqwest::blocking::get(url)
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error fetching cloud secrets",
                err,
            )
        })
        .unwrap();

    if !response.status().is_success() {
        eprintln!("Error {} reading secrets", response.status());
        panic!("{}", response.text().unwrap())
    }

    let encrypted_values: HashMap<String, String> = response
        .json()
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error decoding cloud response",
                err,
            )
        })
        .unwrap();

    private_key.decrypt_package(&encrypted_values).unwrap()
}
