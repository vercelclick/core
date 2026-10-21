use crate::passkeys::protocol::{parse_auth_data, verify_client_data};
use ciborium::Value;
use coset::{CborSerializable, CoseKey, Label};
use p256::Sec1Point;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use secretpass_core::SecretpassPasskey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tsify::Tsify;

#[derive(Serialize, Deserialize, Debug, Clone, Tsify)]
pub struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Tsify)]
pub struct AuthorizationResponse {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: AssertionResponse,
}

impl AuthorizationResponse {
    pub fn partial_verification(
        &self,
        challenge_hash: String,
        rp_id: String,
        rp_origin: String,
    ) -> anyhow::Result<String> {
        verify_client_data(
            &self.response.client_data_json,
            challenge_hash,
            "webauthn.get",
            &rp_origin,
        )?;

        let (flags, credential_data) = parse_auth_data(&self.response.authenticator_data, rp_id)?;
        if credential_data.is_some() {
            return Err(anyhow::anyhow!(
                "Invalid credential - login object should not hold attestation data"
            ));
        }

        flags.enforce_verification()?;

        // Verify user handle if present
        if let Some(uh_bytes) = &self.response.user_handle {
            let uid_str = String::from_utf8(uh_bytes.clone())
                .map_err(|_| anyhow::anyhow!("Invalid userHandle utf8"))?;
            Ok(uid_str)
        } else {
            Err(anyhow::anyhow!(
                "Invalid credential - missing user_id details"
            ))
        }
    }

    pub fn full_verification(
        &self,
        passkey: SecretpassPasskey,
        challenge_hash: String,
        rp_id: String,
        rp_origin: String,
    ) -> anyhow::Result<()> {
        let user_id = self.partial_verification(challenge_hash, rp_id, rp_origin)?;
        if user_id != passkey.user_id {
            return Err(anyhow::anyhow!("Invalid credential - user_id mismatch!"));
        }

        let client_data_hash = Sha256::digest(&self.response.client_data_json);
        let mut signed_data = Vec::with_capacity(self.response.authenticator_data.len() + 32);
        signed_data.extend_from_slice(&self.response.authenticator_data);
        signed_data.extend_from_slice(&client_data_hash);

        verify_p256_signature(
            &passkey.public_key_bytes()?,
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
) -> anyhow::Result<()> {
    let cose_key = CoseKey::from_slice(pub_key_cbor)
        .map_err(|e| anyhow::format_err!("Invalid COSE key: {e}"))?;

    let x = match cose_key.params.iter().find(|(k, _)| k == &Label::Int(-2)) {
        Some((_, Value::Bytes(b))) => b,
        _ => return Err(anyhow::anyhow!("Missing x coordinate")),
    };
    let y = match cose_key.params.iter().find(|(k, _)| k == &Label::Int(-3)) {
        Some((_, Value::Bytes(b))) => b,
        _ => return Err(anyhow::anyhow!("Missing y coordinate")),
    };

    if x.len() != 32 || y.len() != 32 {
        return Err(anyhow::anyhow!("Invalid coordinate length"));
    }

    let sec_point = Sec1Point::from_affine_coordinates(
        x.as_slice().try_into()?,
        y.as_slice().try_into()?,
        false,
    );
    let verifying_key = VerifyingKey::from_sec1_point(&sec_point)
        .map_err(|e| anyhow::format_err!("Invalid P-256 key: {e}"))?;

    let signature = Signature::from_der(signature_der)
        .map_err(|e| anyhow::format_err!("Error parsing signature: {e}"))?;

    verifying_key
        .verify(signed_data, &signature)
        .map_err(|e| anyhow::format_err!("Invalid signature: {e}"))?;
    Ok(())
}
