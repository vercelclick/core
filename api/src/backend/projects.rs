use secretpass_core::{SecretpassProject, SecretpassProjectUserPublicKey, SecretpassWorkspace};
use secretpass_web::PasskeyAuthorizationResponse;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProjectPath {
    pub path: String,
    pub short_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProjectListItem {
    pub project: SecretpassProject,
    pub path: Option<ProjectPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WorkspaceProjectListItem {
    pub workspace: SecretpassWorkspace,
    pub projects: Vec<SecretpassProject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ListProjectsResult {
    pub pending: Vec<ProjectPath>,
    pub projects: Vec<ProjectListItem>,
    pub workspaces: Vec<WorkspaceProjectListItem>,
    pub inaccessible: Vec<ProjectListItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreateProjectRequest {
    pub path: Option<String>,
    pub project: SecretpassProject,
    pub public_key: SecretpassProjectUserPublicKey,
    pub auth_response: PasskeyAuthorizationResponse,
}
