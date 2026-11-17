use crate::backend::ApiState;
use crate::routes::projects::access_keys::create_access_key_handler;
use crate::routes::projects::environments::{create_environment, get_environment_by_name};
use crate::routes::projects::project::{create_project, get_project_by_id, list_projects};
use crate::routes::projects::secrets::access_keys::{get_access_key_secrets, get_secret_targets};
use crate::routes::projects::secrets::create::{create_secret, update_secret, update_secret_value};
use axum::Router;
use axum::routing::{get, patch, post};

pub mod access_keys;
pub mod environments;
pub mod project;
pub mod secrets;

pub fn project_routes() -> Router<ApiState> {
    Router::new()
        .route("/", get(list_projects).post(create_project))
        .route("/{project_id}", get(get_project_by_id))
        .route("/{project_id}/env", post(create_environment))
        .route("/{project_id}/env/{env_name}", get(get_environment_by_name))
        .route("/{project_id}/env/{env_name}/secrets", post(create_secret))
        .route(
            "/{project_id}/env/{env_name}/secrets/{secret_name}",
            patch(update_secret),
        )
        .route(
            "/{project_id}/env/{env_name}/secrets/{secret_name}/targets",
            get(get_secret_targets),
        )
        .route(
            "/{project_id}/env/{env_name}/secrets/{secret_name}/value",
            patch(update_secret_value),
        )
        .route("/{project_id}/access-keys", post(create_access_key_handler))
}

pub fn public_project_routes() -> Router<ApiState> {
    Router::new().route(
        "/{project_id}/access-keys/{key_id}/env/{env_name}/tag/{tag_name}",
        get(get_access_key_secrets),
    )
}
