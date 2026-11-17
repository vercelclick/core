use crate::backend::projects::project::get_contributor_by_id;
use crate::db;
use crate::db::{Transaction, TransactionOperation, with_transaction};
use crate::workfows::passkeys::PasskeyValidationWorkflow;
use async_trait::async_trait;
use axum::http::StatusCode;
use click_api::backend::environments::{
    CreateEnvironmentRequest, GetEnvironmentRequest, GetEnvironmentResult,
    SecretWithEncryptedValues,
};
use click_api::backend::projects::CreateEnvironmentWithProjectRequest;
use click_core::enums::WebauthnChallengeKind;
use click_core::{
    AuthSession, ContributorPublicKey, Environment, InternalError, InternalResult, Project,
    SecretDefinition, SecretValue, User, caller,
};
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

pub fn environments_insert_query_builder(
    project: &Project,
    requests: &Vec<CreateEnvironmentWithProjectRequest>,
) -> QueryBuilder<Postgres> {
    // language=sql
    let mut query_builder: QueryBuilder<Postgres> =
        QueryBuilder::new(r#"INSERT INTO "Environments" (name, project_id, description) "#);

    query_builder.push_values(requests, |mut b, request| {
        b.push_bind(request.name.clone())
            .push_bind(project.id)
            .push_bind(request.description.clone());
    });

    query_builder.push(" RETURNING *");

    query_builder
}

pub async fn get_environment_by_name(
    project_id: Uuid,
    env_name: &str,
) -> InternalResult<Option<Environment>> {
    let environment: Option<Environment> =
        sqlx::query_as(r#"SELECT * FROM "Environments" WHERE project_id = $1 AND name = $2"#)
            .bind(project_id)
            .bind(env_name)
            .fetch_optional(db::pool())
            .await
            .map_err(|err| {
                InternalError::trace(
                    caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error getting environment details",
                    err,
                )
            })?;

    Ok(environment)
}

pub async fn get_environment_handler(
    user: &User,
    request: &GetEnvironmentRequest,
) -> InternalResult<Option<GetEnvironmentResult>> {
    let contributor = match get_contributor_by_id(user, request.project_id).await? {
        Some(pu) => pu,
        None => return Ok(None),
    };

    let access = match contributor.get_access(&request.env_name) {
        Some(access) => access,
        None => return Ok(None),
    };

    let environment = get_environment_by_name(contributor.project_id, &request.env_name)
        .await?
        .ok_or_else(|| {
            InternalError::new(caller!(), StatusCode::NOT_FOUND, "Environment not found")
        })?;

    let secret_definitions: Vec<SecretDefinition> = sqlx::query_as(
        r#"SELECT * FROM "SecretDefinitions" WHERE project_id = $1 AND env_name = $2"#,
    )
    .bind(contributor.project_id)
    .bind(&request.env_name)
    .fetch_all(db::pool())
    .await
    .map_err(|err| {
        InternalError::trace(
            caller!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error getting secret definitions",
            err,
        )
    })?;

    let secret_values: Vec<SecretValue> = sqlx::query_as(
        r#"SELECT sv.* FROM "SecretValues" sv
                     INNER JOIN "ContributorPublicKeys" cpk ON cpk.id = sv.target
                     WHERE cpk.contributor_id = $1 AND sv.env_name = $2"#,
    )
    .bind(contributor.id)
    .bind(&request.env_name)
    .fetch_all(db::pool())
    .await
    .map_err(|err| {
        InternalError::trace(
            caller!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error getting secret values",
            err,
        )
    })?;

    let contributor_keys: Vec<ContributorPublicKey> = sqlx::query_as(
        r#"SELECT * FROM "ContributorPublicKeys"
                    WHERE contributor_id = $1"#,
    )
    .bind(contributor.id)
    .fetch_all(db::pool())
    .await
    .map_err(|err| {
        InternalError::trace(
            caller!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error contributors public keys",
            err,
        )
    })?;

    let secrets: Vec<SecretWithEncryptedValues> = secret_definitions
        .iter()
        .filter(|definition| access.can_read_secret(&definition.name))
        .map(|definition| {
            SecretWithEncryptedValues::extract(definition, &contributor_keys, &secret_values)
        })
        .collect();

    Ok(Some(GetEnvironmentResult {
        environment,
        secrets,
    }))
}

struct CreateEnvironmentWorkflow {
    user: User,
    project_id: Uuid,
    request: CreateEnvironmentRequest,
}

#[async_trait]
impl TransactionOperation<Environment> for CreateEnvironmentWorkflow {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<Environment> {
        get_environment_by_name(self.project_id, &self.request.name)
            .await?
            .is_none()
            .ok_or_else(|| {
                InternalError::new(
                    caller!(),
                    StatusCode::CONFLICT,
                    "An environment with this name already exists",
                )
            })?;
        PasskeyValidationWorkflow {
            kind: WebauthnChallengeKind::PasskeyAuthorize,
            owner: self.user.email,
            auth_result: self.request.auth_result.clone(),
        }
        .execute(tx)
        .await?;

        let environment: Environment = sqlx::query_as(
            r#"INSERT INTO "Environments" (name, project_id, description) VALUES ($1, $2, $3) RETURNING *"#,
        )
        .bind(&self.request.name)
        .bind(self.project_id)
        .bind(&self.request.description)
        .fetch_one(&mut **tx)
        .await
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error creating environment, please raise a support ticket if the issue persists",
                err,
            )
        })?;

        Ok(environment)
    }
}

pub async fn create_environment(
    session: &AuthSession,
    project_id: Uuid,
    request: CreateEnvironmentRequest,
) -> InternalResult<GetEnvironmentResult> {
    let contributor = get_contributor_by_id(&session.user, project_id)
        .await?
        .ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::NOT_FOUND,
                "Contributor not found in this project",
            )
        })?;

    contributor.is_admin().ok_or_else(|| {
        InternalError::new(
            caller!(),
            StatusCode::FORBIDDEN,
            "You must be an admin to add new environments",
        )
    })?;

    let environment = with_transaction(CreateEnvironmentWorkflow {
        request,
        project_id,
        user: session.user.clone(),
    })
    .await?;

    Ok(GetEnvironmentResult {
        environment,
        secrets: vec![],
    })
}
