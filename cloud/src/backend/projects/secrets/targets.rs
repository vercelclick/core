use crate::backend::projects::project::get_contributor_by_id;
use crate::db;
use click_api::backend::secrets::ProjectSecretPathParams;
use click_core::{
    AccessKey, Contributor, ContributorPublicKey, InternalError, InternalResult, StatusCode,
    TargetedPublicKey, User, caller,
};
use uuid::Uuid;

pub async fn get_secret_targets(
    user: &User,
    params: ProjectSecretPathParams,
) -> InternalResult<Vec<TargetedPublicKey>> {
    get_contributor_by_id(user, params.project_id)
        .await?
        .ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::FORBIDDEN,
                "User not found in this project",
            )
        })?;

    let contributor_keys: Vec<ContributorPublicKey> = sqlx::query_as(
        r#"
        SELECT cpk.* FROM "ContributorPublicKeys" as cpk
            INNER JOIN "Contributors" as contributor
                ON cpk.contributor_id = contributor.id
        WHERE contributor.project_id = $1
    "#,
    )
    .bind(params.project_id)
    .fetch_all(db::pool())
    .await
    .map_err(|err| {
        InternalError::trace(
            caller!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error getting contributor public keys",
            err,
        )
    })?;

    let contributors: Vec<Contributor> =
        sqlx::query_as(r#"SELECT * FROM "Contributors" WHERE project_id=$1"#)
            .bind(params.project_id)
            .fetch_all(db::pool())
            .await
            .map_err(|err| {
                InternalError::trace(
                    caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error getting project contributors",
                    err,
                )
            })?;

    let allowed_contributors: Vec<Uuid> = contributors
        .iter()
        .filter(|cont| match cont.get_access(&params.env_name) {
            Some(access) => access.can_read_secret(&params.secret_name),
            None => false,
        })
        .map(|cont| cont.id)
        .collect();

    let access_keys: Vec<AccessKey> =
        sqlx::query_as(r#"SELECT * FROM "AccessKeys" WHERE project_id=$1"#)
            .bind(params.project_id)
            .fetch_all(db::pool())
            .await
            .map_err(|err| {
                InternalError::trace(
                    caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error getting project access keys",
                    err,
                )
            })?;

    let mut target_keys: Vec<TargetedPublicKey> = vec![];
    for key in access_keys {
        if let Some(access) = key.get_access(&params.env_name)
            && access.can_read_secret(&params.secret_name)
        {
            target_keys.push(TargetedPublicKey {
                target: key.id,
                value: key.public_key,
            })
        }
    }

    for key in contributor_keys {
        if allowed_contributors.contains(&key.contributor_id) {
            target_keys.push(TargetedPublicKey {
                target: key.id,
                value: key.public_key,
            })
        }
    }

    Ok(target_keys)
}
