use crate::backend::auth::user::get_user_by_email;
use crate::db;
use crate::db::workflows::{AttemptEmailChallengeWorkflow, UpsertEmailChallengeWorkflow};
use crate::db::{Transaction, TransactionOperation};
use crate::emails::{EmailTemplate, send_email};
use async_trait::async_trait;
use axum::Json;
use click_core::enums::EmailChallengeKind;
use click_core::{EmailChallenge, InternalError, InternalResult, StatusCode, caller};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct EmailChallengeRequest {
    pub kind: EmailChallengeKind,
    pub owner: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub operation: Option<String>,
}

struct SendEmailWorkflow {
    recipient: String,
    template: EmailTemplate,
    db_workflow: UpsertEmailChallengeWorkflow,
}

#[async_trait]
impl TransactionOperation<()> for SendEmailWorkflow {
    async fn execute(self, tx: &mut Transaction<'_>) -> InternalResult<()> {
        let upsert_workflow = self.db_workflow;
        send_email(&self.recipient, self.template).await?;

        upsert_workflow.execute(tx).await?;

        Ok(())
    }
}

#[axum::debug_handler]
pub async fn send_email_challenge_handler(
    Json(request): Json<EmailChallengeRequest>,
) -> InternalResult<()> {
    let user = get_user_by_email(db::pool(), request.owner.clone()).await?;

    let (code, hash) = EmailChallenge::generate();

    let template =
        match request.kind {
            EmailChallengeKind::EmailSignIn => {
                user.is_some().ok_or_else(|| {
                    InternalError::new(caller!(), StatusCode::BAD_REQUEST, "User not found")
                })?;

                EmailTemplate::Confirm {
                    subject: "Click Vault Sign in".to_string(),
                    name: user.unwrap().name,
                    code,
                    operation: "attempted to sign in".to_string(),
                }
            }
            EmailChallengeKind::EmailAuthorize => {
                user.is_some().ok_or_else(|| {
                    InternalError::new(caller!(), StatusCode::BAD_REQUEST, "User not found")
                })?;

                let operation = request.operation.clone().ok_or_else(|| {
                    InternalError::new(
                        caller!(),
                        StatusCode::BAD_REQUEST,
                        "Operation required for email authorize challenge",
                    )
                })?;
                EmailTemplate::Confirm {
                    subject: "Click Vault Confirm".to_string(),
                    name: user.unwrap().name,
                    code,
                    operation,
                }
            }
            EmailChallengeKind::EmailSignup => {
                user.is_none().ok_or_else(|| InternalError::new(caller!(),
                StatusCode::FORBIDDEN,
                "You already have an account under this email address, try to sign in instead.",
            ))?;

                let name = request.name.clone().ok_or_else(|| {
                    InternalError::new(
                        caller!(),
                        StatusCode::BAD_REQUEST,
                        "Name missing for email signup challenge",
                    )
                })?;
                EmailTemplate::Create {
                    subject: "Verify your email".to_string(),
                    name,
                    code,
                }
            }
        };

    db::with_transaction(SendEmailWorkflow {
        recipient: request.owner.clone(),
        template,
        db_workflow: UpsertEmailChallengeWorkflow {
            owner: request.owner.clone(),
            kind: request.kind,
            hash,
        },
    })
    .await
}

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CheckChallengeRequest {
    pub kind: EmailChallengeKind,
    pub owner: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, TS)]
#[ts(export)]
pub struct CheckChallengeResult {
    pub valid: bool,
    pub attempts_left: i32,
}

#[axum::debug_handler]
pub async fn check_challenge_handler(
    Json(request): Json<CheckChallengeRequest>,
) -> InternalResult<Json<CheckChallengeResult>> {
    let challenge = db::with_transaction(AttemptEmailChallengeWorkflow {
        kind: request.kind,
        owner: request.owner.clone(),
    })
    .await?;

    let valid = challenge.validate(&request.value);

    Ok(Json(CheckChallengeResult {
        valid,
        attempts_left: challenge.attempts_left,
    }))
}
