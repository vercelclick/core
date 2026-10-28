use crate::enums::{AccessGrant, ContributorRole, ContributorStatus};
use crate::{PublicKey, PublicKeyEncrypt};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;
use ts_rs::TS;
use tsify::Tsify;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, FromRow)]
pub struct Contributor {
    pub id: Uuid,
    pub user_id: Uuid,
    pub status: ContributorStatus,
    pub project_id: Uuid,
    pub role: ContributorRole,
    pub environments: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

impl Contributor {
    pub fn can_access(&self, env_name: &String) -> bool {
        if self.role == ContributorRole::Admin {
            true
        } else {
            self.environments.contains(env_name)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, FromRow)]
pub struct ContributorPublicKey {
    pub id: Uuid,
    pub name: String,
    pub user_id: Uuid,
    pub cred_id: String,
    pub access: AccessGrant,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ecc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kem: Option<String>,
    pub contributor_id: Uuid,
    pub granted_by: Option<String>,
    pub granted_on: Option<DateTime<Utc>>,
}

impl ContributorPublicKey {
    fn public_key(&self) -> anyhow::Result<PublicKey> {
        PublicKey::from_encoded(self.ecc.clone(), self.kem.clone())
    }
}

impl PublicKeyEncrypt for ContributorPublicKey {
    fn encrypt(&self, payload: Vec<u8>) -> anyhow::Result<String> {
        self.public_key()?.encrypt(payload)
    }

    fn encrypt_package(
        &self,
        decrypted_package: HashMap<String, Vec<u8>>,
    ) -> anyhow::Result<HashMap<String, String>> {
        self.public_key()?.encrypt_package(decrypted_package)
    }
}
