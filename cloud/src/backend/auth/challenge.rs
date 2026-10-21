use anyhow::Ok;
use chrono::{DateTime, Utc};
use secretpass_api::PendingChallenge;
use secretpass_core::enums::ChallengeKind;
use sqlx::{PgPool, Row};

// language=sql
const PENDING_CHALLENGE_INSERT: &str = r#"
    insert into "PendingChallenge"
        (owner, kind, value_hash)
        values ($1, $2::"ChallengeKind", $3)
    on conflict (owner, kind)
        do update set value_hash = EXCLUDED.value_hash, generated_on = now()
"#;

pub async fn insert_or_replace_challenge(
    pool: &PgPool,
    challenge: PendingChallenge,
) -> anyhow::Result<()> {
    sqlx::query(PENDING_CHALLENGE_INSERT)
        .bind(&challenge.owner)
        .bind(challenge.kind.to_string())
        .bind(&challenge.value_hash)
        .execute(pool)
        .await?;

    Ok(())
}

// language=sql
const PENDING_CHALLENGE_RETRIEVE: &str = r#"
    SELECT * FROM "PendingChallenge" WHERE kind = $1::"ChallengeKind" AND owner = $2
"#;

pub async fn get_pending_challenge(
    pool: &PgPool,
    kind: ChallengeKind,
    owner: String,
) -> anyhow::Result<PendingChallenge> {
    let row = sqlx::query(PENDING_CHALLENGE_RETRIEVE)
        .bind(kind.to_string())
        .bind(&owner)
        .fetch_one(pool)
        .await?;

    let challenge = PendingChallenge {
        kind,
        owner,
        value_hash: row.get("value_hash"),
        generated_on: row.get("generated_on"),
    };

    Ok(challenge)
}
