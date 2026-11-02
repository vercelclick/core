use crate::ApiState;
use crate::routes::projects::environments::get_environment_by_name;
use crate::routes::projects::machine::create_machine_public_key_handler;
use crate::routes::projects::project::{create_project, get_project_by_id, list_projects};
use crate::routes::projects::secrets::create::create_secret;
use crate::routes::projects::secrets::machine::get_machine_secrets;
use axum::Router;
use axum::routing::{get, post};

pub mod environments;
pub mod machine;
pub mod project;
pub mod secrets;

pub fn project_routes() -> Router<ApiState> {
    Router::new()
        .route("/", get(list_projects).post(create_project))
        .route("/{project_id}", get(get_project_by_id))
        .route("/{project_id}/env/{env_name}", get(get_environment_by_name))
        .route("/{project_id}/env/{env_name}/secrets", post(create_secret))
        .route(
            "/{project_id}/machines",
            post(create_machine_public_key_handler),
        )
}

pub fn public_project_routes() -> Router<ApiState> {
    Router::new().route(
        "/{project_id}/env/{env_name}/tag/{tag_name}/secrets/machine/{key_a}/{key_b}/{key_c}",
        get(get_machine_secrets),
    )
}
