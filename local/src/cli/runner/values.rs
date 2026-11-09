use crate::cli::runner::human::get_values_from_web;
use crate::cli::runner::machines::{get_values_from_cloud_project, get_values_from_local_project};
use secretpass_core::KeyPair;
use std::collections::HashMap;

pub fn get_local_values(
    project_dir: Option<String>,
    private_key: Option<String>,
    env: Option<String>,
    command: Option<String>,
) -> (KeyPair, HashMap<String, String>) {
    if let Some(key) = private_key {
        let env = env.expect("Environment value required when using a private key");
        get_values_from_local_project(project_dir, key, env, "latest".to_string())
    } else {
        get_values_from_web(command)
    }
}

pub fn get_cloud_values(
    endpoint: String,
    private_key: Option<String>,
    env: Option<String>,
    command: Option<String>,
) -> (KeyPair, HashMap<String, String>) {
    if let Some(key) = private_key {
        let env = env.expect("Environment value required when using a private key");
        get_values_from_cloud_project(endpoint, key, env, "latest".to_string())
    } else {
        get_values_from_web(command)
    }
}
