use serde::{Deserialize, Serialize};
use tsify::Tsify;

// Client response types
#[derive(Serialize, Deserialize, Debug, Clone, Tsify)]
pub struct RegistrationResponse {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: AttestationResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyFlags {
    pub user_present: bool,
    pub user_verified: bool,
    pub attested_data: bool, // Only available during registration
    pub extension_data: bool,
    pub backup_eligible: bool,
    pub backup_completed: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttestationResponse {
    pub client_data_json: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

pub struct PrfResults {
    pub first: [u8; 32],
    pub second: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone, Tsify)]
pub struct LoginResponse {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: AssertionResponse,
}

#[derive(Serialize, Deserialize, Debug, Clone, Tsify)]
pub struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<Vec<u8>>,
}
