use crate::lock::HashedLock;
use serde::{Deserialize, Serialize};
use tsify::Tsify;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify)]
pub struct SecretpassWorkspace {
    pub id: String, // Fixed - invalidates keys if changed
    pub name: String,
    pub description: String,
    pub created_at: String,
}

impl HashedLock for SecretpassWorkspace {
    fn salt(&self) -> Vec<String> {
        vec![self.id.clone(), self.created_at.clone()]
    }
}
