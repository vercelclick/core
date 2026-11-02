use crate::backend::projects::project::get_contributor_by_id;
use crate::backend::projects::secrets::create::machine_values_insert_query_builder;
use secretpass_api::secrets::CreateMachinePublicKeyRequest;
use secretpass_core::{MachinePublicKey, User};
use sqlx::PgPool;
use uuid::Uuid;

// language=sql
const INSERT_MACHINE_PUBLIC_QUERY: &str = r#"
    INSERT INTO "MachinePublicKeys"
        (id, name, description, project_id, environments, ecc, kem, generated_by)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    RETURNING *
"#;

pub async fn create_machine_public_key(
    pool: &PgPool,
    user: &User,
    project_id: Uuid,
    request: CreateMachinePublicKeyRequest,
) -> anyhow::Result<MachinePublicKey> {
    let mut tx = pool.begin().await?;

    get_contributor_by_id(pool, user, project_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("User not found in project"))?;

    // TODO: Verify that this user has access to all these secrets
    let machine_key = sqlx::query_as(INSERT_MACHINE_PUBLIC_QUERY)
        .bind(&request.public_key.id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(project_id)
        .bind(request.environments.clone())
        .bind(request.public_key.ecc.clone())
        .bind(request.public_key.kem.clone())
        .bind(&user.email)
        .fetch_one(&mut *tx)
        .await?;

    // TODO: Verify that the targets are matching
    if !request.machine_secrets.is_empty() {
        machine_values_insert_query_builder(project_id, &request.machine_secrets)
            .build()
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;

    Ok(machine_key)
}
