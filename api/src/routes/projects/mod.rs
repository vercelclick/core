use crate::ApiState;
use crate::routes::projects::environments::get_environment_by_name;
use crate::routes::projects::project::{create_project, get_project_by_id, list_projects};
use axum::Router;
use axum::routing::get;

pub mod environments;
pub mod project;

pub fn project_routes() -> Router<ApiState> {
    Router::new()
        .route("/", get(list_projects).post(create_project))
        .route("/{project_id}", get(get_project_by_id))
        .route("/{project_id}/env/{env_name}", get(get_environment_by_name))
}
