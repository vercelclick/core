use crate::passkeys::helpers::{parse_auth_data, verify_client_data};
use crate::result::{InternalError, InternalResult};

use crate::utils::bin_decode;
use ciborium::Value;
use coset::{CborSerializable, CoseKey, Label};
use http::StatusCode;
use p256::Sec1Point;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ts_rs::TS;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
pub struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
pub struct PasskeyAuthorizationResult {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: AssertionResponse,
}

impl PasskeyAuthorizationResult {
    fn verify_challenge_and_config(&self, challenge_hash: &str) -> InternalResult<String> {
        verify_client_data(
            &self.response.client_data_json,
            challenge_hash,
            "webauthn.get",
        )?;

        let (flags, credential_data) = parse_auth_data(&self.response.authenticator_data)?;
        if credential_data.is_some() {
            return Err(InternalError::new(
                StatusCode::CONFLICT,
                "Invalid credential - login object should not hold attestation data",
            ));
        }

        flags.enforce_verification()?;

        // Verify user handle if present
        if let Some(uh_bytes) = &self.response.user_handle {
            let uid_str = String::from_utf8(uh_bytes.clone()).map_err(|err| {
                InternalError::trace(StatusCode::BAD_REQUEST, "Invalid userHandle utf8", err)
            })?;
            Ok(uid_str)
        } else {
            Err(InternalError::new(
                StatusCode::BAD_REQUEST,
                "Invalid credential - missing user_id details",
            ))
        }
    }

    pub fn validate(
        &self,
        user_id: Uuid,
        public_key: &str,
        challenge_hash: &str,
    ) -> InternalResult<()> {
        let passkey_user_id = self.verify_challenge_and_config(challenge_hash)?;
        if user_id.to_string() != passkey_user_id {
            return Err(InternalError::new(
                StatusCode::CONFLICT,
                "Invalid credential - user_id mismatch!",
            ));
        }

        let client_data_hash = Sha256::digest(&self.response.client_data_json);
        let mut signed_data = Vec::with_capacity(self.response.authenticator_data.len() + 32);
        signed_data.extend_from_slice(&self.response.authenticator_data);
        signed_data.extend_from_slice(&client_data_hash);

        verify_p256_signature(
            &bin_decode(&public_key)?,
            &signed_data,
            &self.response.signature,
        )?;

        Ok(())
    }
}

fn verify_p256_signature(
    pub_key_cbor: &[u8],
    signed_data: &[u8],
    signature_der: &[u8],
) -> InternalResult<()> {
    let cose_key = CoseKey::from_slice(pub_key_cbor).map_err(|err| {
        InternalError::trace(
            StatusCode::CONFLICT,
            "Signature Error, invalid COSE key",
            err,
        )
    })?;

    let x = match cose_key.params.iter().find(|(k, _)| k == &Label::Int(-2)) {
        Some((_, Value::Bytes(b))) => b,
        _ => {
            return Err(InternalError::new(
                StatusCode::CONFLICT,
                "Signature Error, missing x coordinate",
            ));
        }
    };
    let y = match cose_key.params.iter().find(|(k, _)| k == &Label::Int(-3)) {
        Some((_, Value::Bytes(b))) => b,
        _ => {
            return Err(InternalError::new(
                StatusCode::CONFLICT,
                "Signature Error, missing y coordinate",
            ));
        }
    };

    if x.len() != 32 || y.len() != 32 {
        return Err(InternalError::new(
            StatusCode::CONFLICT,
            "Signature Error, invalid coordinate length",
        ));
    }

    let sec_point = Sec1Point::from_affine_coordinates(
        x.as_slice().try_into().map_err(|err| {
            InternalError::trace(
                StatusCode::CONFLICT,
                "Signature error, invalid x coordinates",
                err,
            )
        })?,
        y.as_slice().try_into().map_err(|err| {
            InternalError::trace(
                StatusCode::CONFLICT,
                "Signature error, invalid y coordinates",
                err,
            )
        })?,
        false,
    );
    let verifying_key = VerifyingKey::from_sec1_point(&sec_point).map_err(|e| {
        InternalError::trace(
            StatusCode::CONFLICT,
            "Signature error, invalid P-256 key",
            e,
        )
    })?;

    let signature = Signature::from_der(signature_der).map_err(|e| {
        InternalError::trace(
            StatusCode::CONFLICT,
            "Signature error, invalid signature data",
            e,
        )
    })?;

    verifying_key.verify(signed_data, &signature).map_err(|e| {
        InternalError::trace(
            StatusCode::CONFLICT,
            "Signature error, signed data signature mismatch",
            e,
        )
    })?;
    Ok(())
}
