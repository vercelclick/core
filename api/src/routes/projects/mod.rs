use crate::ApiState;
use crate::routes::projects::project::list_projects;
use axum::Router;
use axum::routing::get;

pub mod project;

pub fn project_routes() -> Router<ApiState> {
    Router::new().route("/", get(list_projects))
}
