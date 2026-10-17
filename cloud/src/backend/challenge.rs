use anyhow::Ok;
use secretpass_api::PendingChallenge;
use secretpass_core::enums::ChallengeKind;
use sqlx::PgPool;

use crate::db::queries;

pub async fn insert_or_replace_challenge(
    pool: &PgPool,
    challenge: PendingChallenge,
) -> anyhow::Result<()> {
    sqlx::query(queries::PENDING_CHALLENGE_INSERT)
        .bind(&challenge.owner)
        .bind(&challenge.kind)
        .bind(&challenge.value)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn get_pending_challenge(
    pool: &PgPool,
    kind: ChallengeKind,
    challenge: String,
) -> anyhow::Result<PendingChallenge> {
    let challenge = sqlx::query_as::<_, PendingChallenge>(queries::PENDING_CHALLENGE_RETRIEVE)
        .bind(kind)
        .bind(challenge)
        .fetch_one(pool)
        .await?;

    Ok(challenge)
}
