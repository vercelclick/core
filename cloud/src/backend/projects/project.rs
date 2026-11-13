use crate::backend::projects::environments::environments_insert_query_builder;
use crate::backend::projects::passkeys::contributor_public_key_insert_query_builder;
use crate::db;
use crate::db::{Transaction, TransactionOperation};
use click_api::backend::projects::{
    CreateProjectRequest, GetProjectResult, ListProjectsResult, ProjectListItem,
};
use click_core::enums::{ContributorRole, ContributorStatus};
use click_core::{
    AccessKey, AuthSession, Contributor, Environment, EnvironmentAccess, FederatedAccessKey,
    InternalError, InternalResult, Passkey, Project, StatusCode, User, caller,
};
use sqlx::{FromRow, Row};
use uuid::Uuid;

// language=sql
const CREATE_PROJECT_QUERY: &str = r#"
    INSERT INTO "Projects" (name, description)
    VALUES ($1, $2)
    RETURNING *
"#;

struct CreateProjectWorkflow {
    user: User,
    passkeys: Vec<Passkey>,
    request: CreateProjectRequest,
}

#[async_trait::async_trait]
impl TransactionOperation<Project> for CreateProjectWorkflow {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<Project> {
        let project: Project = sqlx::query_as(CREATE_PROJECT_QUERY)
            .bind(&self.request.name)
            .bind(&self.request.description)
            .fetch_one(&mut **tx)
            .await
            .map_err(|err| {
                InternalError::trace(
                    caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error creating project",
                    err,
                )
            })?;

        environments_insert_query_builder(&project, &self.request.environments)
            .build()
            .execute(&mut **tx)
            .await
            .map_err(|err| {
                InternalError::trace(
                    caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error creating environments",
                    err,
                )
            })?;

        let contributor: Contributor = sqlx::query_as(
            r#"
            INSERT INTO "Contributors" (user_id, status, project_id, role, environments)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
        "#,
        )
        .bind(self.user.id)
        .bind(ContributorStatus::Active)
        .bind(project.id)
        .bind(ContributorRole::Admin)
        .bind(Vec::<EnvironmentAccess>::new())
        .fetch_one(&mut **tx)
        .await
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error adding a contributor",
                err,
            )
        })?;

        contributor_public_key_insert_query_builder(self.user, contributor, self.passkeys)
            .build()
            .execute(&mut **tx)
            .await
            .map_err(|err| {
                InternalError::trace(
                    caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error adding public keys",
                    err,
                )
            })?;

        Ok(project)
    }
}

pub async fn create_project(
    session: &AuthSession,
    request: CreateProjectRequest,
) -> InternalResult<Project> {
    db::with_transaction(CreateProjectWorkflow {
        user: session.user.clone(),
        passkeys: session.passkeys.to_vec(),
        request: request.clone(),
    })
    .await
}

// language=sql
const LIST_PROJECTS_BY_USER_ID: &str = r#"
    SELECT project.* FROM "Projects" as project INNER JOIN "Contributors" as users
    ON users.project_id = project.id
    WHERE users.user_id = $1
"#;

pub async fn list_projects(user: &User) -> InternalResult<ListProjectsResult> {
    let projects: Vec<Project> = sqlx::query_as(LIST_PROJECTS_BY_USER_ID)
        .bind(user.id)
        .fetch_all(db::pool())
        .await
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error listing projects",
                err,
            )
        })?;

    let projects = projects
        .iter()
        .map(|project| ProjectListItem {
            path: None,
            project: project.clone(),
        })
        .collect();

    Ok(ListProjectsResult {
        projects,
        inaccessible: vec![],
        pending: vec![],
        workspaces: vec![],
    })
}

// language=sql
const GET_PROJECT_BY_CONTRIBUTOR_ID: &str = r#"
    SELECT project.* FROM "Projects" as project INNER JOIN "Contributors" as contributor
    ON contributor.project_id = project.id
    WHERE project.id = $1 AND contributor.user_id = $2
"#;

// language=sql
const GET_CONTRIBUTOR_BY_USER_ID: &str = r#"
    SELECT * FROM "Contributors"
    WHERE project_id = $1 AND user_id = $2
"#;

// language=sql
const GET_ENVIRONMENTS_BY_PROJECT_ID: &str = r#"
    SELECT * FROM "Environments"
    WHERE project_id = $1
"#;

// language=sql
const GET_CONTRIBUTORS_QUERY: &str = r#"
    SELECT
        contributors.*,
        users.name as user_name, users.email as user_email, users.updated_at as user_updated_at,
        users.key_salt as user_key_salt
    FROM "Contributors" contributors
        INNER JOIN "Users" users ON contributors.user_id = users.id
    WHERE
        project_id = $1
"#;

// language=sql
const GET_ACCESS_KEYS_QUERY: &str = r#"
    SELECT * FROM "AccessKeys" WHERE project_id = $1
"#;

// language=sql
const GET_FEDERATED_ACCESS_KEYS_QUERY: &str = r#"
    SELECT * FROM "FederatedAccessKeys" WHERE project_id = $1
"#;

pub async fn get_project_by_id(
    user: &User,
    project_id: Uuid,
) -> InternalResult<Option<GetProjectResult>> {
    let project: Option<Project> = sqlx::query_as(GET_PROJECT_BY_CONTRIBUTOR_ID)
        .bind(project_id)
        .bind(user.id)
        .fetch_optional(db::pool())
        .await
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error getting project details",
                err,
            )
        })?;
    let project = match project {
        Some(result) => result,
        None => return Ok(None),
    };

    let contributor = match get_contributor_by_id(user, project_id).await? {
        Some(pu) => pu,
        None => return Ok(None),
    };

    let environments: Vec<Environment> = sqlx::query_as(GET_ENVIRONMENTS_BY_PROJECT_ID)
        .bind(project_id)
        .fetch_all(db::pool())
        .await
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error getting project environments",
                err,
            )
        })?;

    let environments = environments
        .into_iter()
        .filter(|env| contributor.get_access(&env.name).is_some())
        .collect();

    let rows = sqlx::query(GET_CONTRIBUTORS_QUERY)
        .bind(project_id)
        .fetch_all(db::pool())
        .await
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error getting project contributors",
                err,
            )
        })?;

    let contributors: Vec<(User, Contributor)> = rows
        .iter()
        .map(|row| {
            let user = User {
                id: row.get("user_id"),
                email: row.get("user_email"),
                name: row.get("user_name"),
                key_salt: row.get("user_key_salt"),
                updated_at: row.get("user_updated_at"),
            };
            let contributor = Contributor::from_row(row).unwrap();
            (user, contributor)
        })
        .collect();

    let access_keys: Vec<AccessKey> = sqlx::query_as(GET_ACCESS_KEYS_QUERY)
        .bind(project_id)
        .fetch_all(db::pool())
        .await
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error getting project access keys",
                err,
            )
        })?;

    let federated_keys: Vec<FederatedAccessKey> = sqlx::query_as(GET_FEDERATED_ACCESS_KEYS_QUERY)
        .bind(project_id)
        .fetch_all(db::pool())
        .await
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error getting project federated keys",
                err,
            )
        })?;

    Ok(Some(GetProjectResult {
        path: None,
        project,
        contributor,
        environments,
        contributors,
        access_keys,
        federated_keys,
    }))
}

pub async fn get_contributor_by_id(
    user: &User,
    project_id: Uuid,
) -> InternalResult<Option<Contributor>> {
    let contributor: Option<Contributor> = sqlx::query_as(GET_CONTRIBUTOR_BY_USER_ID)
        .bind(project_id)
        .bind(user.id)
        .fetch_optional(db::pool())
        .await
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error getting contributor details",
                err,
            )
        })?;

    Ok(contributor)
}
