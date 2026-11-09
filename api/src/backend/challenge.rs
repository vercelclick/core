use crate::ApiState;
use chrono::{DateTime, Utc};
use rand::RngExt;
use secretpass_core::InternalResult;
use secretpass_core::enums::ChallengeKind;
use secretpass_core::utils::{bin_encode, fill_random_bytes, get_global_rng, sha256_digest};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use ts_rs::TS;

const CODE_POOL: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Debug, Clone, Deserialize, Serialize, TS)]
#[ts(export)]
pub struct CheckChallengeResult {
    pub valid: bool,
    pub attempts_left: i32,
}

#[derive(Debug, Clone, Deserialize, FromRow)]
pub struct PendingChallenge {
    pub owner: String,
    pub kind: ChallengeKind,
    pub value_hash: String,
    pub generated_on: DateTime<Utc>,
    pub attempts_left: i32,
}

impl PendingChallenge {
    pub(crate) async fn generate_webauthn(kind: ChallengeKind, owner: String) -> (String, Self) {
        let mut challenge = [0u8; 32];
        fill_random_bytes(&mut challenge).await;
        let value = bin_encode(&challenge);
        let digest_value = value.clone();
        let value_hash = sha256_digest(&[digest_value]);

        let pc = Self {
            kind,
            owner,
            value_hash,
            generated_on: Utc::now(),
            attempts_left: 1,
        };

        (value, pc)
    }

    #[allow(unused)]
    pub(crate) async fn send_email_code(
        kind: ChallengeKind,
        owner: String,
        name: String,
        operation: Option<String>,
        is_proxied: bool,
    ) -> InternalResult<(String, Self)> {
        let code = {
            let mut rng = get_global_rng().lock().await;
            let code: String = (0..6)
                .map(|_| {
                    let idx = rng.random_range(0..CODE_POOL.len());
                    CODE_POOL[idx] as char
                })
                .collect();
            code
        };

        #[cfg(feature = "email")]
        {
            use crate::emails;
            use secretpass_core::enums::OperationMode;
            use secretpass_core::{InternalError, StatusCode, source};

            let operation_mode = if is_proxied {
                OperationMode::Local
            } else {
                OperationMode::Cloud
            };

            let name = name.trim().split(" ").next().unwrap().to_string();
            let template = match kind {
                ChallengeKind::EmailSignup => emails::EmailTemplate::Create {
                    subject: "Verify your email".to_string(),
                    name,
                    code: code.clone(),
                    operation_mode,
                },
                ChallengeKind::EmailSignIn => emails::EmailTemplate::Confirm {
                    subject: "Confirm sign in".to_string(),
                    name,
                    code: code.clone(),
                    operation: "attempted to sign in with email".to_string(),
                    operation_mode,
                },
                ChallengeKind::EmailAuthorize => {
                    let operation = operation.ok_or_else(|| {
                        InternalError::new(
                            source!(),
                            StatusCode::BAD_REQUEST,
                            "Operation required for email authorize challenge",
                        )
                    })?;
                    emails::EmailTemplate::Confirm {
                        subject: "Authorize operation".to_string(),
                        name,
                        code: code.clone(),
                        operation,
                        operation_mode,
                    }
                }
                _ => {
                    return Err(InternalError::new(
                        source!(),
                        StatusCode::NOT_IMPLEMENTED,
                        &format!("Email challenge {kind} is not supported"),
                    ));
                }
            };

            emails::send_email(&owner.clone(), template).await?;
        }

        let value_hash = sha256_digest(&[code]);

        let pc = Self {
            kind,
            owner,
            value_hash,
            generated_on: Utc::now(),
            attempts_left: 4,
        };

        Ok(("Sent".to_string(), pc))
    }

    pub fn verify_challenge(&self, value: String) -> bool {
        let hash = sha256_digest(&[value]);

        hash == self.value_hash
    }

    pub(crate) async fn record(&self, state: &ApiState) -> InternalResult<()> {
        state.backend.record_pending_challenge(self).await
    }
}
