use crate::backend::projects::project::get_contributor_by_id;
use crate::backend::projects::secrets::create::secret_values_insert_query_builder;
use crate::db;
use crate::db::{Transaction, TransactionOperation};
use axum::http::StatusCode;
use click_api::backend::secrets::{
    CreateAccessKeyRequest, CreateFederatedAccessKeyRequest, CreateFederatedAccessKeyResult,
    ProjectPathParams,
};
use click_core::{AccessKey, FederatedAccessKey, InternalError, InternalResult, User, caller};
use uuid::Uuid;

// language=sql
const INSERT_ACCESS_KEY_QUERY: &str = r#"
    INSERT INTO "AccessKeys" (id, name, description, project_id, access, public_key, generated_by)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    RETURNING *
"#;

// language=sql
const INSERT_FEDERATED_ACCESS_KEY_QUERY: &str = r#"
    INSERT INTO "FederatedAccessKeys" (id, name, description, project_id, access, contributors, generated_by)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    RETURNING *
"#;

struct CreateAccessKeyWorkflow {
    email: String,
    project_id: Uuid,
    request: CreateAccessKeyRequest,
}

#[async_trait::async_trait]
impl TransactionOperation<AccessKey> for CreateAccessKeyWorkflow {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<AccessKey> {
        let access_key: AccessKey = sqlx::query_as(INSERT_ACCESS_KEY_QUERY)
            .bind(self.request.id)
            .bind(&self.request.name)
            .bind(&self.request.description)
            .bind(self.project_id)
            .bind(self.request.access.clone())
            .bind(self.request.public_key)
            .bind(&self.email)
            .fetch_one(&mut **tx)
            .await
            .map_err(|err| {
                InternalError::trace(
                    caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error creating direct access key",
                    err,
                )
            })?;

        // TODO: Verify that the targets are matching
        if !self.request.encrypted_values.is_empty() {
            secret_values_insert_query_builder(self.project_id, &self.request.encrypted_values)
                .build()
                .execute(&mut **tx)
                .await
                .map_err(|err| {
                    InternalError::trace(
                        caller!(),
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal error adding access key values",
                        err,
                    )
                })?;
        }

        Ok(access_key)
    }
}

pub async fn create_access_key(
    user: &User,
    project_id: Uuid,
    request: CreateAccessKeyRequest,
) -> InternalResult<AccessKey> {
    let contributor = get_contributor_by_id(user, project_id)
        .await?
        .ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::FORBIDDEN,
                "You do not have access to this project",
            )
        })?;

    contributor.is_admin().ok_or_else(|| {
        InternalError::new(
            caller!(),
            StatusCode::FORBIDDEN,
            "Only admins can create direct access keys",
        )
    })?;

    db::with_transaction(CreateAccessKeyWorkflow {
        project_id,
        email: user.email.clone(),
        request: request.clone(),
    })
    .await
}

pub async fn create_federated_access_key(
    user: &User,
    params: ProjectPathParams,
    request: CreateFederatedAccessKeyRequest,
) -> InternalResult<CreateFederatedAccessKeyResult> {
    let contributor = get_contributor_by_id(user, params.project_id)
        .await?
        .ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::FORBIDDEN,
                "You do not have access to this project",
            )
        })?;

    contributor.is_admin().ok_or_else(|| {
        InternalError::new(
            caller!(),
            StatusCode::FORBIDDEN,
            "Only admins can create federated access keys",
        )
    })?;

    let access_key: FederatedAccessKey = sqlx::query_as(INSERT_FEDERATED_ACCESS_KEY_QUERY)
        .bind(Uuid::now_v7())
        .bind(&request.name)
        .bind(&request.description)
        .bind(params.project_id)
        .bind(request.access.clone())
        .bind(request.contributors.clone())
        .bind(&user.email)
        .fetch_one(db::pool())
        .await
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error creating direct access key",
                err,
            )
        })?;

    let key_id = access_key.encode_key();

    Ok(CreateFederatedAccessKeyResult { key_id, access_key })
}
