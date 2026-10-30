use crate::backend::projects::environments::get_environment_by_name;
use crate::backend::projects::project::get_contributor_by_id;
use crate::backend::projects::secrets::read::get_secret_by_name;
use secretpass_api::environments::SecretWithEncryptedValues;
use secretpass_api::secrets::{CreateSecretParams, CreateSecretRequest};
use secretpass_core::enums::SecretDataType;
use secretpass_core::web::{EncryptedContributorValue, EncryptedMachineValue};
use secretpass_core::{ContributorPublicKey, ContributorSecretValue, SecretDefinition, User};
use sqlx::{PgPool, Postgres, QueryBuilder};

// language=sql
const CREATE_SECRET_QUERY: &str = r#"
    INSERT INTO "SecretDefinitions" (name, env_name, project_id, comments, tags)
    VALUES ($1, $2, $3, $4, '{}')
    RETURNING *
"#;

pub async fn create_secret(
    pool: &PgPool,
    user: &User,
    params: CreateSecretParams,
    request: CreateSecretRequest,
) -> anyhow::Result<SecretWithEncryptedValues> {
    let mut tx = pool.begin().await?;

    let contributor = get_contributor_by_id(pool, user, params.project_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("User not found in project"))?;

    contributor
        .can_access(&params.env_name)
        .ok_or_else(|| anyhow::anyhow!("User does not have access to this environment"))?;

    let environment = get_environment_by_name(pool, params.project_id, &params.env_name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Environment not found"))?;

    get_secret_by_name(pool, params.project_id, &params.env_name, &request.name)
        .await?
        .is_none()
        .ok_or_else(|| anyhow::format_err!("{} already exists", request.name))?;

    let definition: SecretDefinition = sqlx::query_as(CREATE_SECRET_QUERY)
        .bind(request.name.clone())
        .bind(environment.name.clone())
        .bind(params.project_id)
        .bind(request.comments.clone())
        .fetch_one(&mut *tx)
        .await?;

    let contributor_values: Vec<ContributorSecretValue> =
        contributor_values_insert_query_builder(&definition, &request.contributors_values)
            .build_query_as()
            .fetch_all(&mut *tx)
            .await?;

    if !request.machines_values.is_empty() {
        machine_values_insert_query_builder(&definition, &request.machines_values)
            .build()
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;

    let contributor_keys: Vec<ContributorPublicKey> =
        sqlx::query_as(r#"SELECT * FROM "ContributorPublicKeys" WHERE contributor_id=$1"#)
            .bind(contributor.id)
            .fetch_all(pool)
            .await?;

    Ok(SecretWithEncryptedValues::extract(
        &definition,
        &contributor_keys,
        &contributor_values,
    ))
}

pub fn contributor_values_insert_query_builder(
    definition: &SecretDefinition,
    values: &[EncryptedContributorValue],
) -> QueryBuilder<Postgres> {
    // language=sql
    let mut query_builder: QueryBuilder<Postgres> = QueryBuilder::new(
        r#"INSERT INTO "ContributorSecretValues" (name, env_name, target, project_id, tag, data_type, encrypted_value) "#,
    );

    query_builder.push_values(values, |mut b, value| {
        b.push_bind(&definition.name)
            .push_bind(&definition.env_name)
            .push_bind(value.target)
            .push_bind(definition.project_id)
            .push_bind("latest")
            .push_bind(SecretDataType::Text)
            .push_bind(&value.encrypted_value);
    });

    query_builder.push(" RETURNING *");

    query_builder
}

pub fn machine_values_insert_query_builder(
    definition: &SecretDefinition,
    values: &[EncryptedMachineValue],
) -> QueryBuilder<Postgres> {
    // language=sql
    let mut query_builder: QueryBuilder<Postgres> = QueryBuilder::new(
        r#"INSERT INTO "MachineSecretValues" (name, env_name, target, project_id, tag, data_type, encrypted_value) "#,
    );

    query_builder.push_values(values, |mut b, value| {
        b.push_bind(&definition.name)
            .push_bind(&definition.env_name)
            .push_bind(value.target.clone())
            .push_bind(definition.project_id)
            .push_bind("latest")
            .push_bind(SecretDataType::Text)
            .push_bind(&value.encrypted_value);
    });

    query_builder
}
