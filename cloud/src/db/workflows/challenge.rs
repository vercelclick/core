use crate::db::{Transaction, TransactionOperation};
use async_trait::async_trait;
use click_core::enums::{EmailChallengeKind, WebauthnChallengeKind};
use click_core::passkeys::authorize::PasskeyAuthorizationResult;
use click_core::{
    EmailChallenge, InternalError, InternalResult, StatusCode, WebauthnChallenge, caller,
};
use std::sync::Arc;
use uuid::Uuid;

pub struct UpsertWebauthnChallengeWorkflow {
    pub owner: String,
    pub kind: WebauthnChallengeKind,
    pub hash: String,
}

#[async_trait]
impl TransactionOperation<WebauthnChallenge> for UpsertWebauthnChallengeWorkflow {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<WebauthnChallenge> {
        let challenge: WebauthnChallenge = sqlx::query_as(
            r#"
            insert into "WebauthnChallenge"
                (owner, kind, value_hash)
                values ($1, $2, $3)
            on conflict (owner, kind)
                do update set value_hash = excluded.value_hash, expires_on = excluded.expires_on
            RETURNING *
        "#,
        )
        .bind(self.owner.to_lowercase())
        .bind(self.kind)
        .bind(self.hash)
        .fetch_one(&mut **tx)
        .await
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Internal error creating {} challenge", self.kind),
                err,
            )
        })?;
        Ok(challenge)
    }
}

pub struct UpsertEmailChallengeWorkflow {
    pub owner: String,
    pub kind: EmailChallengeKind,
    pub hash: String,
}

#[async_trait]
impl TransactionOperation<EmailChallenge> for UpsertEmailChallengeWorkflow {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<EmailChallenge> {
        let challenge: EmailChallenge = sqlx::query_as(r#"
                insert into "EmailChallenge"
                    (owner, kind, value_hash)
                    values ($1, $2, $3)
                on conflict (owner, kind)
                    do update set value_hash = excluded.value_hash, expires_on = excluded.expires_on, attempts_left = excluded.attempts_left
                RETURNING *
            "#)
            .bind(self.owner)
            .bind(self.kind)
            .bind(self.hash)
            .fetch_one(&mut **tx)
            .await
            .map_err(|err| {
                InternalError::trace(caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Internal error creating {} challenge", self.kind),
                    err,
                )
            })?;
        Ok(challenge)
    }
}

pub struct AttemptEmailChallengeWorkflow {
    pub owner: String,
    pub kind: EmailChallengeKind,
}

#[async_trait]
impl TransactionOperation<EmailChallenge> for AttemptEmailChallengeWorkflow {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<EmailChallenge> {
        let challenge: Option<EmailChallenge> = sqlx::query_as(
            r#"
            UPDATE "EmailChallenge" SET attempts_left = (attempts_left - 1)
            WHERE kind=$1 AND owner = $2 AND attempts_left > 0 AND expires_on >= now() RETURNING *"#,
        )
        .bind(self.kind)
        .bind(self.owner)
        .fetch_optional(&mut **tx)
        .await.map_err(|err| {
            InternalError::trace(caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Internal error fetching {} challenge", self.kind),
                err,
            )
        })?;

        challenge.ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::NOT_FOUND,
                &format!("{} challenge not found", self.kind),
            )
        })
    }
}

pub struct UseWebauthnChallengeWorkflow {
    pub owner: String,
    pub kind: WebauthnChallengeKind,
    pub public_key: String,
    pub result: Arc<PasskeyAuthorizationResult>,
}

#[async_trait]
impl TransactionOperation<Uuid> for UseWebauthnChallengeWorkflow {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<Uuid> {
        let challenge: Option<WebauthnChallenge> = sqlx::query_as(
            r#"
            DELETE FROM "WebauthnChallenge"
                   WHERE kind=$1 AND owner=$2 AND expires_on >= now() RETURNING *
            "#,
        )
        .bind(self.kind)
        .bind(self.owner)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Internal error getting {} challenge", self.kind),
                err,
            )
        })?;

        let challenge = challenge.ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::NOT_FOUND,
                &format!("{} challenge not found", self.kind),
            )
        })?;

        self.result
            .validate(&self.public_key, &challenge.value_hash)?;

        Ok(self.result.user_id)
    }
}

pub struct UseEmailChallengeWorkflow {
    pub owner: String,
    pub kind: EmailChallengeKind,
    pub confirmation_code: String,
}

#[async_trait]
impl TransactionOperation<()> for UseEmailChallengeWorkflow {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<()> {
        let challenge: Option<EmailChallenge> = sqlx::query_as(
            r#"
            DELETE FROM "EmailChallenge"
                   WHERE kind=$1 AND owner=$2 AND expires_on >= now()
            "#,
        )
        .bind(self.kind)
        .bind(self.owner)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Internal error getting {} challenge", self.kind),
                err,
            )
        })?;

        let challenge = challenge.ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::NOT_FOUND,
                &format!("{} challenge not found", self.kind),
            )
        })?;

        challenge.validate(&self.confirmation_code).ok_or_else(|| {
            InternalError::new(
                caller!(),
                StatusCode::UNAUTHORIZED,
                "Invalid email confirmation code",
            )
        })?;

        Ok(())
    }
}
