use crate::enums::EncryptionAlgorithm;
use crate::lock::HashedLock;
use crate::workspace::SecretpassWorkspace;
use serde::{Deserialize, Serialize};
use tsify::Tsify;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify)]
pub struct SecretpassProject {
    pub id: String, // Fixed - invalidates keys if changed - uuid v4 local, uuid v7 cloud
    pub name: String,
    pub description: String,
    pub algorithm: EncryptionAlgorithm, // Fixed - invalidates keys if changed
    pub created_at: String,             // Fixed - invalidates keys if changed
    pub workspace: Option<SecretpassWorkspace>,
}

impl HashedLock for SecretpassProject {
    fn salt(&self) -> Vec<String> {
        let mut salt = vec![
            self.id.clone(),
            self.algorithm.to_string(),
            self.created_at.clone(),
        ];
        if let Some(workspace) = &self.workspace {
            salt.append(&mut workspace.salt());
        }

        salt
    }
}
