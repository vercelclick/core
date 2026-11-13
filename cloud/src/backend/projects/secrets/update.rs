use crate::backend::projects::project::get_contributor_by_id;
use crate::backend::projects::secrets::create::secret_values_insert_query_builder;
use crate::db;
use crate::db::{Transaction, TransactionOperation};
use crate::workfows::passkeys::PasskeyValidationWorkflow;
use click_api::backend::environments::SecretWithEncryptedValues;
use click_api::backend::secrets::{
    ProjectSecretPathParams, UpdateSecretRequest, UpdateSecretValueRequest,
};
use click_api::constants::{LATEST_SECRET_TAG, PREVIOUS_SECRET_TAG};
use click_core::enums::WebauthnChallengeKind;
use click_core::{
    ContributorPublicKey, InternalError, InternalResult, SecretDefinition, SecretValue, StatusCode,
    User, caller,
};
use uuid::Uuid;

pub async fn update_secret(
    user: &User,
    params: ProjectSecretPathParams,
    request: UpdateSecretRequest,
) -> InternalResult<SecretWithEncryptedValues> {
    let contributor = get_contributor_by_id(user, params.project_id)
        .await?
        .ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::FORBIDDEN,
                "You don't have access to this project under the current user",
            )
        })?;

    let access = contributor.get_access(&params.env_name).ok_or_else(|| {
        InternalError::new(
            caller!(),
            StatusCode::FORBIDDEN,
            "You don't have access to this environment",
        )
    })?;

    access
        .can_write_secret(&params.secret_name)
        .ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::FORBIDDEN,
                "You do not have permission to update this secret",
            )
        })?;

    let definition: SecretDefinition = sqlx::query_as(
        r#"UPDATE "SecretDefinitions" SET comments=$1, updated_at=now() WHERE project_id=$2 AND env_name=$3 AND name=$4 RETURNING *"#
    )
        .bind(&request.comments)
        .bind(params.project_id)
        .bind(&params.env_name)
        .bind(&params.secret_name)
        .fetch_one(db::pool()).await.map_err(|err| {
        InternalError::trace(caller!(),

            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error updating secret",
            err,
        )
    })?;

    build_return_value(contributor.id, definition).await
}

struct UpdateSecretValueWorkflow {
    user: User,
    params: ProjectSecretPathParams,
    request: UpdateSecretValueRequest,
}

#[async_trait::async_trait]
impl TransactionOperation<SecretDefinition> for UpdateSecretValueWorkflow {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<SecretDefinition> {
        PasskeyValidationWorkflow {
            owner: self.user.email,
            kind: WebauthnChallengeKind::PasskeyAuthorize,
            auth_result: self.request.auth_result.clone(),
        }
        .execute(tx)
        .await?;

        let definition: SecretDefinition = sqlx::query_as(r#"UPDATE "SecretDefinitions" SET updated_at=now() WHERE project_id=$1 AND env_name=$2 AND name=$3 RETURNING *"#)
            .bind(self.params.project_id)
            .bind(&self.params.env_name)
            .bind(&self.params.secret_name)
            .fetch_one(&mut **tx)
            .await.map_err(|err| {
            InternalError::trace(caller!(),

                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error updating secret definition",
                err,
            )
        })?;

        // Delete previous values
        sqlx::query(
            r#"DELETE FROM "SecretValues" WHERE project_id=$1 AND env_name=$2 AND name=$3 AND tag=$4"#,
        )
            .bind(self.params.project_id)
            .bind(&self.params.env_name)
            .bind(&self.params.secret_name)
            .bind(PREVIOUS_SECRET_TAG.to_string())
            .execute(&mut **tx)
            .await
            .map_err(|err| {
                InternalError::trace(caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error pruning secret values",
                    err,
                )
            })?;

        // Set latest values to previous values
        sqlx::query(
            r#"UPDATE "SecretValues" SET tag=$1 WHERE project_id=$2 AND env_name=$3 AND name=$4 AND tag=$5"#
        ).bind(PREVIOUS_SECRET_TAG.to_string()).bind(self.params.project_id)
            .bind(&self.params.env_name)
            .bind(&self.params.secret_name).bind(LATEST_SECRET_TAG.to_string()).execute(&mut **tx).await.map_err(|err| {
            InternalError::trace(caller!(),

                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error updating previous secret values",
                err,
            )
        })?;

        secret_values_insert_query_builder(self.params.project_id, &self.request.encrypted_values)
            .build()
            .execute(&mut **tx)
            .await
            .map_err(|err| {
                InternalError::trace(
                    caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error adding secret values",
                    err,
                )
            })?;

        Ok(definition)
    }
}

pub async fn update_secret_value(
    user: &User,
    params: ProjectSecretPathParams,
    request: UpdateSecretValueRequest,
) -> InternalResult<SecretWithEncryptedValues> {
    let contributor = get_contributor_by_id(user, params.project_id)
        .await?
        .ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::FORBIDDEN,
                "You don't have access to this project under the current user",
            )
        })?;

    let access = contributor.get_access(&params.env_name).ok_or_else(|| {
        InternalError::new(
            caller!(),
            StatusCode::FORBIDDEN,
            "You don't have access to this environment",
        )
    })?;

    access
        .can_write_secret(&params.secret_name)
        .ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::FORBIDDEN,
                "You do not have permission to update this secret",
            )
        })?;

    let definition = db::with_transaction(UpdateSecretValueWorkflow {
        user: user.clone(),
        params,
        request: request.clone(),
    })
    .await?;

    build_return_value(contributor.id, definition).await
}

async fn build_return_value(
    contributor_id: Uuid,
    definition: SecretDefinition,
) -> InternalResult<SecretWithEncryptedValues> {
    let contributor_values: Vec<SecretValue> = sqlx::query_as(
        r#"SELECT * FROM "SecretValues" WHERE target=$1 AND env_name=$2 AND name=$3"#,
    )
    .bind(contributor_id)
    .bind(&definition.env_name)
    .bind(&definition.name)
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

    let contributor_keys: Vec<ContributorPublicKey> =
        sqlx::query_as(r#"SELECT * FROM "ContributorPublicKeys" WHERE contributor_id=$1"#)
            .bind(contributor_id)
            .fetch_all(db::pool())
            .await
            .map_err(|err| {
                InternalError::trace(
                    caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error contributor public keys",
                    err,
                )
            })?;

    Ok(SecretWithEncryptedValues::extract(
        &definition,
        &contributor_keys,
        &contributor_values,
    ))
}
