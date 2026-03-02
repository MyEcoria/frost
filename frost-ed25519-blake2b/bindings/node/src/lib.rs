use std::collections::BTreeMap;

use frost_ed25519_blake2b as frost;
use rand_core::OsRng;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Clone)]
pub struct DealerShare {
    identifier: Vec<u8>,
    secret_share: Vec<u8>,
    key_package: Vec<u8>,
}

#[wasm_bindgen]
impl DealerShare {
    #[wasm_bindgen(getter)]
    pub fn identifier(&self) -> Vec<u8> {
        self.identifier.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn secret_share(&self) -> Vec<u8> {
        self.secret_share.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn key_package(&self) -> Vec<u8> {
        self.key_package.clone()
    }
}

#[wasm_bindgen]
pub struct DealerKeygenResult {
    public_key_package: Vec<u8>,
    shares: Vec<DealerShare>,
}

#[wasm_bindgen]
impl DealerKeygenResult {
    #[wasm_bindgen(getter)]
    pub fn public_key_package(&self) -> Vec<u8> {
        self.public_key_package.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn shares_len(&self) -> usize {
        self.shares.len()
    }

    pub fn share(&self, index: usize) -> Result<DealerShare, JsValue> {
        self.shares
            .get(index)
            .cloned()
            .ok_or_else(|| js_error("share index out of bounds"))
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct Round1CommitResult {
    identifier: Vec<u8>,
    nonces: Vec<u8>,
    commitments: Vec<u8>,
}

#[wasm_bindgen]
impl Round1CommitResult {
    #[wasm_bindgen(getter)]
    pub fn identifier(&self) -> Vec<u8> {
        self.identifier.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn nonces(&self) -> Vec<u8> {
        self.nonces.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn commitments(&self) -> Vec<u8> {
        self.commitments.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct Round2SignatureShareResult {
    identifier: Vec<u8>,
    signature_share: Vec<u8>,
}

#[wasm_bindgen]
impl Round2SignatureShareResult {
    #[wasm_bindgen(getter)]
    pub fn identifier(&self) -> Vec<u8> {
        self.identifier.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn signature_share(&self) -> Vec<u8> {
        self.signature_share.clone()
    }
}

#[wasm_bindgen]
pub struct CommitmentList {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

#[wasm_bindgen]
impl CommitmentList {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn push(&mut self, identifier: &[u8], commitment: &[u8]) {
        self.entries
            .push((identifier.to_vec(), commitment.to_vec()));
    }

    #[wasm_bindgen(getter)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[wasm_bindgen]
pub struct SignatureShareList {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

#[wasm_bindgen]
impl SignatureShareList {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn push(&mut self, identifier: &[u8], signature_share: &[u8]) {
        self.entries
            .push((identifier.to_vec(), signature_share.to_vec()));
    }

    #[wasm_bindgen(getter)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

fn js_error(message: impl Into<String>) -> JsValue {
    JsValue::from_str(&message.into())
}

fn frost_error_to_js(error: frost::Error) -> JsValue {
    js_error(format!("FROST error: {error}"))
}

fn parse_identifier(identifier: &[u8]) -> Result<frost::Identifier, JsValue> {
    frost::Identifier::deserialize(identifier).map_err(frost_error_to_js)
}

#[wasm_bindgen]
pub fn generate_with_dealer(
    max_signers: u16,
    min_signers: u16,
) -> Result<DealerKeygenResult, JsValue> {
    let (secret_shares, public_key_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        OsRng,
    )
    .map_err(frost_error_to_js)?;

    let mut shares = Vec::with_capacity(secret_shares.len());

    for (identifier, secret_share) in secret_shares {
        let key_package =
            frost::keys::KeyPackage::try_from(secret_share.clone()).map_err(frost_error_to_js)?;

        shares.push(DealerShare {
            identifier: identifier.serialize(),
            secret_share: secret_share.serialize().map_err(frost_error_to_js)?,
            key_package: key_package.serialize().map_err(frost_error_to_js)?,
        });
    }

    Ok(DealerKeygenResult {
        public_key_package: public_key_package.serialize().map_err(frost_error_to_js)?,
        shares,
    })
}

#[wasm_bindgen]
pub fn key_package_from_secret_share(secret_share_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let secret_share =
        frost::keys::SecretShare::deserialize(secret_share_bytes).map_err(frost_error_to_js)?;
    let key_package = frost::keys::KeyPackage::try_from(secret_share).map_err(frost_error_to_js)?;

    key_package.serialize().map_err(frost_error_to_js)
}

#[wasm_bindgen]
pub fn round1_commit(key_package_bytes: &[u8]) -> Result<Round1CommitResult, JsValue> {
    let key_package =
        frost::keys::KeyPackage::deserialize(key_package_bytes).map_err(frost_error_to_js)?;

    let mut rng = OsRng;
    let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);

    Ok(Round1CommitResult {
        identifier: key_package.identifier().serialize(),
        nonces: nonces.serialize().map_err(frost_error_to_js)?,
        commitments: commitments.serialize().map_err(frost_error_to_js)?,
    })
}

#[wasm_bindgen]
pub fn create_signing_package(
    round1_commitments: &CommitmentList,
    message: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let mut commitments_by_signer = BTreeMap::new();

    for (identifier, commitment) in &round1_commitments.entries {
        let identifier = parse_identifier(identifier)?;
        let commitment = frost::round1::SigningCommitments::deserialize(commitment)
            .map_err(frost_error_to_js)?;

        if commitments_by_signer
            .insert(identifier, commitment)
            .is_some()
        {
            return Err(js_error("duplicate identifier in round1 commitments"));
        }
    }

    let signing_package = frost::SigningPackage::new(commitments_by_signer, message);
    signing_package.serialize().map_err(frost_error_to_js)
}

#[wasm_bindgen]
pub fn round2_sign(
    signing_package_bytes: &[u8],
    nonces_bytes: &[u8],
    key_package_bytes: &[u8],
) -> Result<Round2SignatureShareResult, JsValue> {
    let signing_package =
        frost::SigningPackage::deserialize(signing_package_bytes).map_err(frost_error_to_js)?;
    let nonces =
        frost::round1::SigningNonces::deserialize(nonces_bytes).map_err(frost_error_to_js)?;
    let key_package =
        frost::keys::KeyPackage::deserialize(key_package_bytes).map_err(frost_error_to_js)?;

    let signature_share =
        frost::round2::sign(&signing_package, &nonces, &key_package).map_err(frost_error_to_js)?;

    Ok(Round2SignatureShareResult {
        identifier: key_package.identifier().serialize(),
        signature_share: signature_share.serialize(),
    })
}

#[wasm_bindgen]
pub fn aggregate_signature(
    signing_package_bytes: &[u8],
    signature_shares: &SignatureShareList,
    public_key_package_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let signing_package =
        frost::SigningPackage::deserialize(signing_package_bytes).map_err(frost_error_to_js)?;
    let public_key_package = frost::keys::PublicKeyPackage::deserialize(public_key_package_bytes)
        .map_err(frost_error_to_js)?;

    let mut shares_by_signer = BTreeMap::new();

    for (identifier, signature_share) in &signature_shares.entries {
        let identifier = parse_identifier(identifier)?;
        let signature_share = frost::round2::SignatureShare::deserialize(signature_share)
            .map_err(frost_error_to_js)?;

        if shares_by_signer
            .insert(identifier, signature_share)
            .is_some()
        {
            return Err(js_error("duplicate identifier in signature shares"));
        }
    }

    let signature = frost::aggregate(&signing_package, &shares_by_signer, &public_key_package)
        .map_err(frost_error_to_js)?;

    signature.serialize().map_err(frost_error_to_js)
}

#[wasm_bindgen]
pub fn verify_group_signature(
    public_key_package_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, JsValue> {
    let public_key_package = frost::keys::PublicKeyPackage::deserialize(public_key_package_bytes)
        .map_err(frost_error_to_js)?;
    let signature = frost::Signature::deserialize(signature_bytes).map_err(frost_error_to_js)?;

    match public_key_package
        .verifying_key()
        .verify(message, &signature)
    {
        Ok(()) => Ok(true),
        Err(frost::Error::InvalidSignature) => Ok(false),
        Err(error) => Err(frost_error_to_js(error)),
    }
}
