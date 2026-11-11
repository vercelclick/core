use crate::db;
use secretpass_api::backend::PendingChallenge;
use secretpass_core::enums::ChallengeKind;
use secretpass_core::{InternalError, InternalResult, StatusCode};
use sqlx::Row;

// language=sql
const PENDING_CHALLENGE_INSERT: &str = r#"
    insert into "PendingChallenge"
        (owner, kind, value_hash, attempts_left)
        values ($1, $2, $3, $4)
    on conflict (owner, kind)
        do update set value_hash = EXCLUDED.value_hash, attempts_left = EXCLUDED.attempts_left, generated_on = now()
"#;

pub async fn insert_or_replace_challenge(challenge: &PendingChallenge) -> InternalResult<()> {
    sqlx::query(PENDING_CHALLENGE_INSERT)
        .bind(&challenge.owner)
        .bind(challenge.kind)
        .bind(&challenge.value_hash)
        .bind(challenge.attempts_left)
        .execute(db::pool())
        .await
        .map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Internal error creating {} challenge", challenge.kind),
                err,
            )
        })?;

    Ok(())
}

// language=sql
const PENDING_CHALLENGE_GET: &str = r#"
    SELECT * FROM "PendingChallenge" WHERE kind = $1 AND owner = $2
"#;

// language=sql
const PENDING_CHALLENGE_ATTEMPT: &str = r#"
    UPDATE "PendingChallenge"
        SET attempts_left = (attempts_left - 1)
        WHERE attempts_left > 0 AND kind = $1 AND owner = $2 RETURNING *
"#;

async fn query_pending_challenge(
    query: &'static str,
    kind: ChallengeKind,
    owner: &str,
) -> InternalResult<Option<PendingChallenge>> {
    let row = sqlx::query(query)
        .bind(kind)
        .bind(&owner)
        .fetch_optional(db::pool())
        .await
        .map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Internal error getting {kind} challenge"),
                err,
            )
        })?;

    let row = match row {
        Some(row) => row,
        None => return Ok(None),
    };

    let challenge = PendingChallenge {
        kind,
        owner: owner.to_string(),
        value_hash: row.get("value_hash"),
        generated_on: row.get("generated_on"),
        attempts_left: row.get("attempts_left"),
    };

    Ok(Some(challenge))
}

pub async fn get_pending_challenge(
    kind: ChallengeKind,
    owner: &str,
) -> InternalResult<Option<PendingChallenge>> {
    query_pending_challenge(PENDING_CHALLENGE_GET, kind, owner).await
}

pub async fn attempt_email_challenge(
    kind: ChallengeKind,
    owner: &str,
) -> InternalResult<Option<PendingChallenge>> {
    query_pending_challenge(PENDING_CHALLENGE_ATTEMPT, kind, owner).await
}
