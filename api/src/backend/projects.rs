use secretpass_core::{SecretpassProject, SecretpassProjectUserPublicKey, SecretpassWorkspace};
use secretpass_web::AuthorizationResponse;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProjectPath {
    path: String,
    short_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProjectListItem {
    project: SecretpassProject,
    path: Option<ProjectPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WorkspaceProjectListItem {
    workspace: SecretpassWorkspace,
    projects: Vec<SecretpassProject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ListProjectsResult {
    pending: Vec<ProjectPath>,
    projects: Vec<ProjectListItem>,
    workspaces: Vec<WorkspaceProjectListItem>,
    inaccessible: Vec<ProjectListItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreateProjectRequest {
    path: Option<String>,
    project: SecretpassProject,
    public_key: SecretpassProjectUserPublicKey,
    auth_response: AuthorizationResponse,
}
