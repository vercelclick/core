use crate::cli::runner::access_keys::{
    get_values_from_cloud_project, get_values_from_local_project,
};
use click_core::KeyPair;
use std::collections::HashMap;

pub fn get_local_values(
    project_dir: Option<String>,
    access_key: String,
    env: String,
) -> (KeyPair, HashMap<String, String>) {
    get_values_from_local_project(project_dir, access_key, env, "latest".to_string())
}

pub fn get_cloud_values(
    endpoint: Option<String>,
    access_key: String,
    env: String,
) -> (KeyPair, HashMap<String, String>) {
    get_values_from_cloud_project(endpoint, access_key, env, "latest".to_string())
}
