use crate::lock::HashedLock;
use crate::{SecretpassEnvironment, SecretpassProject, UserLevel};
use serde::{Deserialize, Serialize};
use tsify::Tsify;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify)]
pub struct SecretpassUser {
    pub id: String,    // Fixed - invalidates keys if changed, UUID v7
    pub email: String, // Fixed - invalidates keys if changed
    pub name: String,
    pub created_at: String, // Fixed - invalidates keys if changed
}

impl HashedLock for SecretpassUser {
    fn salt(&self) -> Vec<String> {
        vec![self.id.clone(), self.email.clone(), self.created_at.clone()]
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify)]
pub struct SecretpassProjectUser {
    pub id: String,
    pub user: SecretpassUser,
    pub project: SecretpassProject,
    pub level: UserLevel,
    pub environments: Vec<SecretpassEnvironment>,
    pub created_at: String,
}

impl HashedLock for SecretpassProjectUser {
    fn salt(&self) -> Vec<String> {
        let mut salt = vec![self.id.clone(), self.created_at.clone()];
        salt.append(&mut self.user.salt());
        salt.append(&mut self.project.salt());

        salt
    }
}
