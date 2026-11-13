use crate::passkeys::helpers::{parse_auth_data, verify_client_data};
use crate::result::{InternalError, InternalResult};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::caller;
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

#[derive(Debug, Serialize, Deserialize, TS)]
pub struct AssertionResponse {
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, TS)]
pub struct PasskeyAuthorizationResult {
    pub id: String,
    pub user_id: Uuid,
    pub response: AssertionResponse,
    #[serde(skip, default)]
    validate_called: AtomicBool,
}

impl PasskeyAuthorizationResult {
    pub fn new(id: String, user_id: Uuid, response: AssertionResponse) -> Self {
        Self {
            id,
            user_id,
            response,
            validate_called: Default::default(),
        }
    }

    pub fn validate(&self, public_key: &str, challenge_hash: &str) -> InternalResult<()> {
        verify_client_data(
            &self.response.client_data_json,
            challenge_hash,
            "webauthn.get",
        )?;

        let (flags, credential_data) = parse_auth_data(&self.response.authenticator_data)?;
        if credential_data.is_some() {
            return Err(InternalError::new(
                caller!(),
                StatusCode::CONFLICT,
                "Invalid credential - login object should not hold attestation data",
            ));
        }

        flags.enforce_verification()?;

        let client_data_hash = Sha256::digest(&self.response.client_data_json);
        let mut signed_data = Vec::with_capacity(self.response.authenticator_data.len() + 32);
        signed_data.extend_from_slice(&self.response.authenticator_data);
        signed_data.extend_from_slice(&client_data_hash);

        verify_p256_signature(
            &bin_decode(public_key)?,
            &signed_data,
            &self.response.signature,
        )?;

        self.validate_called.store(true, Ordering::Release);
        Ok(())
    }

    pub fn assert_validation(&self, source: &str) -> InternalResult<()> {
        self.validate_called.load(Ordering::Acquire).ok_or_else(|| {
            InternalError::new(
                source,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Passkey authorization was not validated",
            )
        })
    }
}

fn verify_p256_signature(
    pub_key_cbor: &[u8],
    signed_data: &[u8],
    signature_der: &[u8],
) -> InternalResult<()> {
    let cose_key = CoseKey::from_slice(pub_key_cbor).map_err(|err| {
        InternalError::trace(
            caller!(),
            StatusCode::CONFLICT,
            "Signature Error, invalid COSE key",
            err,
        )
    })?;

    let x = match cose_key.params.iter().find(|(k, _)| k == &Label::Int(-2)) {
        Some((_, Value::Bytes(b))) => b,
        _ => {
            return Err(InternalError::new(
                caller!(),
                StatusCode::CONFLICT,
                "Signature Error, missing x coordinate",
            ));
        }
    };
    let y = match cose_key.params.iter().find(|(k, _)| k == &Label::Int(-3)) {
        Some((_, Value::Bytes(b))) => b,
        _ => {
            return Err(InternalError::new(
                caller!(),
                StatusCode::CONFLICT,
                "Signature Error, missing y coordinate",
            ));
        }
    };

    if x.len() != 32 || y.len() != 32 {
        return Err(InternalError::new(
            caller!(),
            StatusCode::CONFLICT,
            "Signature Error, invalid coordinate length",
        ));
    }

    let sec_point = Sec1Point::from_affine_coordinates(
        x.as_slice().try_into().map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::CONFLICT,
                "Signature error, invalid x coordinates",
                err,
            )
        })?,
        y.as_slice().try_into().map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::CONFLICT,
                "Signature error, invalid y coordinates",
                err,
            )
        })?,
        false,
    );
    let verifying_key = VerifyingKey::from_sec1_point(&sec_point).map_err(|e| {
        InternalError::trace(
            caller!(),
            StatusCode::CONFLICT,
            "Signature error, invalid P-256 key",
            e,
        )
    })?;

    let signature = Signature::from_der(signature_der).map_err(|e| {
        InternalError::trace(
            caller!(),
            StatusCode::CONFLICT,
            "Signature error, invalid signature data",
            e,
        )
    })?;

    verifying_key.verify(signed_data, &signature).map_err(|e| {
        InternalError::trace(
            caller!(),
            StatusCode::CONFLICT,
            "Signature error, signed data signature mismatch",
            e,
        )
    })?;
    Ok(())
}
