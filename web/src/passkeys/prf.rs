use secretpass_core::lock::HashedLock;
use secretpass_core::{EncryptionAlgorithm, SecretpassProject, SecretpassUser};
use serde::{Deserialize, Serialize};
use tsify::Tsify;

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
pub enum PrfEntity {
    Project(SecretpassProject),
}

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
pub struct PrfDeriveConfig {
    pub algorithm: EncryptionAlgorithm,
    pub user: SecretpassUser, // The logged-in secretpass user
    pub entity: PrfEntity,    // Can be workspace or project
}

impl PrfDeriveConfig {
    pub(crate) fn get_salts(&self) -> (Vec<String>, Vec<String>) {
        let user_salt = self.user.salt();
        let entity_salt = match &self.entity {
            PrfEntity::Project(project) => project.salt(),
        };
        (user_salt, entity_salt)
    }
}

pub struct PrfResults {
    pub first: [u8; 32],
    pub second: [u8; 32],
}
