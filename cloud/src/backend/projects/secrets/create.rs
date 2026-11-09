use crate::backend::projects::environments::get_environment_by_name;
use crate::backend::projects::project::get_contributor_by_id;
use crate::backend::projects::secrets::read::get_secret_by_name;
use secretpass_api::environments::SecretWithEncryptedValues;
use secretpass_api::secrets::{CreateSecretRequest, ProjectEnvPathParams};
use secretpass_core::enums::SecretDataType;
use secretpass_core::{
    ContributorPublicKey, ContributorSecretValue, InternalError, InternalResult, SecretDefinition,
    SecretValue, StatusCode, User, source,
};
use sqlx::{PgPool, Postgres, QueryBuilder};
use uuid::Uuid;

// language=sql
const CREATE_SECRET_QUERY: &str = r#"
    INSERT INTO "SecretDefinitions" (name, env_name, project_id, comments, tags)
    VALUES ($1, $2, $3, $4, '{}')
    RETURNING *
"#;

pub async fn create_secret(
    pool: &PgPool,
    user: &User,
    params: ProjectEnvPathParams,
    request: CreateSecretRequest,
) -> InternalResult<SecretWithEncryptedValues> {
    let mut tx = pool.begin().await.map_err(|err| {
        InternalError::trace(
            source!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error establishing a transaction",
            err,
        )
    })?;

    let contributor = get_contributor_by_id(pool, user, params.project_id)
        .await?
        .ok_or_else(|| {
            InternalError::new(
                source!(),
                StatusCode::FORBIDDEN,
                "User not found in project",
            )
        })?;

    let environment = get_environment_by_name(pool, params.project_id, &params.env_name)
        .await?
        .ok_or_else(|| {
            InternalError::new(source!(), StatusCode::NOT_FOUND, "Environment not found")
        })?;

    let access = contributor.get_access(&params.env_name).ok_or_else(|| {
        InternalError::new(
            source!(),
            StatusCode::FORBIDDEN,
            "You do not have access to this environment",
        )
    })?;

    access.is_env_admin().ok_or_else(|| {
        InternalError::new(
            source!(),
            StatusCode::FORBIDDEN,
            "You do not have permission to create secrets in this environment",
        )
    })?;

    get_secret_by_name(pool, params.project_id, &params.env_name, &request.name)
        .await?
        .is_none()
        .ok_or_else(|| {
            InternalError::new(
                source!(),
                StatusCode::FORBIDDEN,
                &format!("{} already exists", request.name),
            )
        })?;

    let definition: SecretDefinition = sqlx::query_as(CREATE_SECRET_QUERY)
        .bind(request.name.clone())
        .bind(environment.name.clone())
        .bind(params.project_id)
        .bind(request.comments.clone())
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| {
            InternalError::trace(
                source!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error saving secret definition",
                err,
            )
        })?;

    let (contributors_values, machines_values) =
        SecretValue::separate_targets(&request.encrypted_values);

    let contributor_values: Vec<ContributorSecretValue> =
        contributor_values_insert_query_builder(params.project_id, &contributors_values)
            .build_query_as()
            .fetch_all(&mut *tx)
            .await
            .map_err(|err| {
                InternalError::trace(
                    source!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error saving secret values",
                    err,
                )
            })?;

    if !machines_values.is_empty() {
        machine_values_insert_query_builder(params.project_id, &machines_values)
            .build()
            .execute(&mut *tx)
            .await
            .map_err(|err| {
                InternalError::trace(
                    source!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error saving access key values",
                    err,
                )
            })?;
    }

    tx.commit().await.map_err(|err| {
        InternalError::trace(
            source!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error committing secret creation",
            err,
        )
    })?;

    let contributor_keys: Vec<ContributorPublicKey> =
        sqlx::query_as(r#"SELECT * FROM "ContributorPublicKeys" WHERE contributor_id=$1"#)
            .bind(contributor.id)
            .fetch_all(pool)
            .await
            .map_err(|err| {
                InternalError::trace(
                    source!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error getting encrypted values",
                    err,
                )
            })?;

    Ok(SecretWithEncryptedValues::extract(
        &definition,
        &contributor_keys,
        &contributor_values,
    ))
}

pub fn contributor_values_insert_query_builder(
    project_id: Uuid,
    values: &[SecretValue],
) -> QueryBuilder<Postgres> {
    // language=sql
    let mut query_builder: QueryBuilder<Postgres> = QueryBuilder::new(
        r#"INSERT INTO "ContributorSecretValues" (name, env_name, target, project_id, tag, data_type, encrypted_value) "#,
    );

    query_builder.push_values(values, |mut b, value| {
        b.push_bind(&value.name)
            .push_bind(&value.environment)
            .push_bind(value.target)
            .push_bind(project_id)
            .push_bind("latest")
            .push_bind(SecretDataType::Text)
            .push_bind(&value.encrypted_value);
    });

    query_builder.push(" RETURNING *");

    query_builder
}

pub fn machine_values_insert_query_builder(
    project_id: Uuid,
    values: &[SecretValue],
) -> QueryBuilder<Postgres> {
    // language=sql
    let mut query_builder: QueryBuilder<Postgres> = QueryBuilder::new(
        r#"INSERT INTO "MachineSecretValues" (name, env_name, target, project_id, tag, data_type, encrypted_value) "#,
    );

    query_builder.push_values(values, |mut b, value| {
        b.push_bind(&value.name)
            .push_bind(&value.environment)
            .push_bind(&value.target)
            .push_bind(project_id)
            .push_bind("latest")
            .push_bind(SecretDataType::Text)
            .push_bind(&value.encrypted_value);
    });

    query_builder
}
