use anyhow::Ok;
use secretpass_api::PendingChallenge;
use secretpass_core::enums::ChallengeKind;
use sqlx::PgPool;

pub async fn insert_or_replace_challenge(
    pool: &PgPool,
    challenge: PendingChallenge,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"INSERT INTO "PendingChallenge" (owner, kind, value, generated_on) VALUES ($1, $2::"ChallengeKind", $3, now())
            ON CONFLICT (owner, kind)
                DO UPDATE SET value = EXCLUDED.value, generated_on = EXCLUDED.generated_on
            "#
    ).bind(&challenge.owner).bind(&challenge.kind).bind(&challenge.value).execute(pool).await?;

    Ok(())
}

pub async fn get_pending_challenge(
    pool: &PgPool,
    kind: ChallengeKind,
    challenge: String,
) -> anyhow::Result<PendingChallenge> {
    let challenge = sqlx::query_as::<_, PendingChallenge>(
        r#"SELECT * FROM "PendingChallenge" WHERE kind = $1::"ChallengeKind" AND value = $2"#,
    )
    .bind(kind)
    .bind(challenge)
    .fetch_one(pool)
    .await?;

    Ok(challenge)
}
