use crate::passkeys::helpers::{parse_auth_data, verify_client_data};
use crate::result::{InternalError, InternalResult};
use crate::source;
use crate::utils::bin_encode;
use ciborium::Value;
use coset::{CborSerializable, CoseKey};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use tsify::Tsify;

#[derive(Serialize, Deserialize, Debug, Clone, Tsify, TS)]
pub struct AttestationResponse {
    pub client_data_json: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

// Client response types
#[derive(Serialize, Deserialize, Debug, Clone, Tsify, TS)]
pub struct PasskeyCreationResult {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: AttestationResponse,
}

impl PasskeyCreationResult {
    /// Validates the client response against the stored challenge and RP configuration.
    /// On success, returns the credential ID and the public key
    pub fn validate(
        &self,
        challenge_hash: &str,
        rp_id: &str,
        rp_origin: &str,
    ) -> InternalResult<(String, String)> {
        verify_client_data(
            &self.response.client_data_json,
            challenge_hash,
            "webauthn.create",
            &rp_origin,
        )?;

        // Parse attestation object (CBOR)
        let att_obj: Value = ciborium::from_reader(self.response.attestation_object.as_slice())
            .map_err(|e| {
                InternalError::trace(
                    source!(),
                    StatusCode::CONFLICT,
                    "Error parsing attestation object",
                    e,
                )
            })?;

        let Value::Map(m) = &att_obj else {
            return Err(InternalError::new(
                source!(),
                StatusCode::BAD_REQUEST,
                "Invalid attestation object structure",
            ));
        };

        let (_, auth_data_value) = m
            .iter()
            .find(|(k, _)| k.as_text().is_some_and(|s| s == "authData"))
            .ok_or_else(|| {
                InternalError::new(
                    source!(),
                    StatusCode::BAD_REQUEST,
                    "Missing authentication data",
                )
            })?;

        let auth_data_bytes = auth_data_value.as_bytes().ok_or_else(|| {
            InternalError::new(
                source!(),
                StatusCode::CONFLICT,
                "Invalid authentication data",
            )
        })?;

        let (flags, credential_data) = parse_auth_data(auth_data_bytes, rp_id)?;
        flags.enforce_verification()?;

        let cred_bytes = credential_data.ok_or_else(|| {
            InternalError::new(
                source!(),
                StatusCode::CONFLICT,
                "Attestation data is missing from the credential returned",
            )
        })?;
        let (cred_id, pub_key_cbor) = extract_credential(&cred_bytes)?;
        // Validate the public key parses
        CoseKey::from_slice(pub_key_cbor).map_err(|e| {
            InternalError::trace(
                source!(),
                StatusCode::CONFLICT,
                "Invalid Public Key CBOR",
                e,
            )
        })?;

        // Encode for storage
        let cred_id_b64 = bin_encode(cred_id);
        let pub_key_b64 = bin_encode(pub_key_cbor);

        Ok((cred_id_b64, pub_key_b64))
    }
}

fn extract_credential(data: &[u8]) -> InternalResult<(&[u8], &[u8])> {
    if data.len() < 18 {
        return Err(InternalError::new(
            source!(),
            StatusCode::CONFLICT,
            "Invalid credential data",
        ));
    }
    let cred_id_len = u16::from_be_bytes(data[16..18].try_into().map_err(|err| {
        InternalError::trace(
            source!(),
            StatusCode::CONFLICT,
            "Invalid credential ID",
            err,
        )
    })?) as usize;
    if data.len() < 18 + cred_id_len {
        return Err(InternalError::new(
            source!(),
            StatusCode::CONFLICT,
            "Credential ID incomplete",
        ));
    }
    let cred_id = &data[18..18 + cred_id_len];
    let pub_key_cbor = &data[18 + cred_id_len..];
    Ok((cred_id, pub_key_cbor))
}
