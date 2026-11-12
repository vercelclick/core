use crate::backend::projects::environments::get_environment_by_name;
use crate::backend::projects::project::get_contributor_by_id;
use crate::backend::projects::secrets::read::get_secret_by_name;
use crate::db;
use crate::db::{Transaction, TransactionOperation};
use click_api::backend::environments::SecretWithEncryptedValues;
use click_api::backend::secrets::{CreateSecretRequest, ProjectEnvPathParams};
use click_core::enums::SecretDataType;
use click_core::{
    ContributorPublicKey, InternalError, InternalResult, SecretDefinition, SecretValue, StatusCode,
    User, caller,
};
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

// language=sql
const CREATE_SECRET_QUERY: &str = r#"
    INSERT INTO "SecretDefinitions" (name, env_name, project_id, comments, tags)
    VALUES ($1, $2, $3, $4, '{}')
    RETURNING *
"#;

struct CreateSecretWorkflow {
    project_id: Uuid,
    env_name: String,
    request: CreateSecretRequest,
}

#[async_trait::async_trait]
impl TransactionOperation<(SecretDefinition, Vec<SecretValue>)> for CreateSecretWorkflow {
    async fn execute(
        self,
        tx: &mut Transaction<'_>,
    ) -> InternalResult<(SecretDefinition, Vec<SecretValue>)> {
        let definition: SecretDefinition = sqlx::query_as(CREATE_SECRET_QUERY)
            .bind(self.request.name.clone())
            .bind(self.env_name.clone())
            .bind(self.project_id)
            .bind(self.request.comments.clone())
            .fetch_one(&mut **tx)
            .await
            .map_err(|err| {
                InternalError::trace(
                    caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error saving secret definition",
                    err,
                )
            })?;

        let secret_values: Vec<SecretValue> =
            secret_values_insert_query_builder(self.project_id, &self.request.encrypted_values)
                .build_query_as()
                .fetch_all(&mut **tx)
                .await
                .map_err(|err| {
                    InternalError::trace(
                        caller!(),
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal error saving secret values",
                        err,
                    )
                })?;
        Ok((definition, secret_values))
    }
}

pub async fn create_secret(
    user: &User,
    params: ProjectEnvPathParams,
    request: CreateSecretRequest,
) -> InternalResult<SecretWithEncryptedValues> {
    let contributor = get_contributor_by_id(user, params.project_id)
        .await?
        .ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::FORBIDDEN,
                "User not found in project",
            )
        })?;

    let environment = get_environment_by_name(params.project_id, &params.env_name)
        .await?
        .ok_or_else(|| {
            InternalError::new(caller!(), StatusCode::NOT_FOUND, "Environment not found")
        })?;

    let access = contributor.get_access(&params.env_name).ok_or_else(|| {
        InternalError::new(
            caller!(),
            StatusCode::FORBIDDEN,
            "You do not have access to this environment",
        )
    })?;

    access.is_env_admin().ok_or_else(|| {
        InternalError::new(
            caller!(),
            StatusCode::FORBIDDEN,
            "You do not have permission to create secrets in this environment",
        )
    })?;

    get_secret_by_name(params.project_id, &params.env_name, &request.name)
        .await?
        .is_none()
        .ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::FORBIDDEN,
                &format!("{} already exists", request.name),
            )
        })?;

    let (definition, secret_values) = db::with_transaction(CreateSecretWorkflow {
        env_name: environment.name.clone(),
        request: request.clone(),
        project_id: contributor.project_id,
    })
    .await?;

    let contributor_keys: Vec<ContributorPublicKey> =
        sqlx::query_as(r#"SELECT * FROM "ContributorPublicKeys" WHERE contributor_id=$1"#)
            .bind(contributor.id)
            .fetch_all(db::pool())
            .await
            .map_err(|err| {
                InternalError::trace(
                    caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error getting encrypted values",
                    err,
                )
            })?;

    Ok(SecretWithEncryptedValues::extract(
        &definition,
        &contributor_keys,
        &secret_values,
    ))
}

pub fn secret_values_insert_query_builder(
    project_id: Uuid,
    values: &[SecretValue],
) -> QueryBuilder<Postgres> {
    // language=sql
    let mut query_builder: QueryBuilder<Postgres> = QueryBuilder::new(
        r#"INSERT INTO "SecretValues" (name, env_name, target, project_id, tag, data_type, encrypted_value) "#,
    );

    query_builder.push_values(values, |mut b, value| {
        b.push_bind(&value.name)
            .push_bind(&value.env_name)
            .push_bind(value.target)
            .push_bind(project_id)
            .push_bind("latest")
            .push_bind(SecretDataType::Text)
            .push_bind(&value.encrypted_value);
    });

    query_builder.push(" RETURNING *");

    query_builder
}
