//! Verification of a remote sealer's output before it can enter mint state.

use elastos_protected_content_contracts::{
    CanonicalContract, ClearLayoutV1, ContractError, CustodyEnvelopeV1, NodePublicKey,
    PoolContractError, SealCompletedV1, SignedMintRequestV1, SignedPoolDescriptorAnyV1,
    SignedSealCompletedV1,
};
use elastos_protected_content_provider_contracts::{
    CencDashMediaIdentityV2, ChunkedPayloadObjectIdentityV1,
};

use crate::RuntimeContentIdentityV1;

// The signed statement includes the file table for a full DASH package.
pub const MAX_REMOTE_SEAL_COMPLETION_BYTES: usize = 512 * 1024;

pub struct VerifiedRemoteSealOutput<'a> {
    statement: &'a SealCompletedV1,
    identity: RuntimeContentIdentityV1,
}

impl VerifiedRemoteSealOutput<'_> {
    pub fn statement(&self) -> &SealCompletedV1 {
        self.statement
    }

    pub fn identity(&self) -> &RuntimeContentIdentityV1 {
        &self.identity
    }
}

/// Bind the signed completion to the fetched envelope and decode its typed
/// object or DASH identity. The caller still checks the published package,
/// availability evidence and finalized item binding before publication.
pub fn verify_remote_seal_output<'a>(
    completion: &'a SignedSealCompletedV1,
    descriptor: &SignedPoolDescriptorAnyV1,
    request: &SignedMintRequestV1,
    expected_sealer: NodePublicKey,
    fetched_envelope: &CustodyEnvelopeV1,
    now: u64,
) -> Result<VerifiedRemoteSealOutput<'a>, PoolContractError> {
    let (statement, layout) =
        completion.verify_for_request_at(descriptor, request, expected_sealer, now)?;
    verify_remote_seal_envelope(statement, layout, fetched_envelope)
}

/// Verify output from a previously admitted completion retained in the mint
/// journal. The upload window may have elapsed. The caller still needs fresh
/// availability and the finalized item binding.
pub fn verify_recorded_remote_seal_output<'a>(
    completion: &'a SignedSealCompletedV1,
    descriptor: &SignedPoolDescriptorAnyV1,
    request: &SignedMintRequestV1,
    expected_sealer: NodePublicKey,
    fetched_envelope: &CustodyEnvelopeV1,
) -> Result<VerifiedRemoteSealOutput<'a>, PoolContractError> {
    let (statement, layout) =
        completion.verify_for_recorded_request(descriptor, request, expected_sealer)?;
    verify_remote_seal_envelope(statement, layout, fetched_envelope)
}

/// Read a completion already admitted by the mint journal. The trusted sealer
/// proved custody and the key commitment before it signed. The minter checks
/// the signed identities and package availability without fetching shares.
pub fn verify_recorded_remote_seal_attestation<'a>(
    completion: &'a SignedSealCompletedV1,
    descriptor: &SignedPoolDescriptorAnyV1,
    request: &SignedMintRequestV1,
    expected_sealer: NodePublicKey,
) -> Result<VerifiedRemoteSealOutput<'a>, PoolContractError> {
    let (statement, layout) =
        completion.verify_for_recorded_request(descriptor, request, expected_sealer)?;
    verify_remote_seal_identity(statement, layout)
}

fn verify_remote_seal_envelope<'a>(
    statement: &'a SealCompletedV1,
    layout: &ClearLayoutV1,
    fetched_envelope: &CustodyEnvelopeV1,
) -> Result<VerifiedRemoteSealOutput<'a>, PoolContractError> {
    if statement.key_envelope != fetched_envelope.key_envelope_identity()?
        || statement.content_key_commitment != fetched_envelope.manifest().content_key_commitment()
    {
        return Err(ContractError::InvalidField("seal_completed.fetched_envelope").into());
    }
    verify_remote_seal_identity(statement, layout)
}

fn verify_remote_seal_identity<'a>(
    statement: &'a SealCompletedV1,
    layout: &ClearLayoutV1,
) -> Result<VerifiedRemoteSealOutput<'a>, PoolContractError> {
    let identity = match layout {
        ClearLayoutV1::Object {
            content_type,
            length,
        } => {
            let object =
                ChunkedPayloadObjectIdentityV1::from_canonical_bytes(&statement.content_identity)?;
            if object.content_type() != content_type || object.plaintext_bytes() != *length {
                return Err(ContractError::InvalidField("seal_completed.object_layout").into());
            }
            RuntimeContentIdentityV1::Object(object)
        }
        ClearLayoutV1::DashV2 { renditions } => {
            let dash = CencDashMediaIdentityV2::from_canonical_bytes(&statement.content_identity)?;
            if dash.default_kid() != statement.content_access_id
                || dash.renditions().len() != renditions.len()
                || dash
                    .renditions()
                    .iter()
                    .zip(renditions)
                    .any(|(encrypted, clear)| {
                        encrypted.kind().code() != clear.kind
                            || encrypted.segment_count() as usize != clear.segment_lengths.len()
                    })
            {
                return Err(ContractError::InvalidField("seal_completed.dash_layout").into());
            }
            RuntimeContentIdentityV1::MediaDash(dash)
        }
    };
    if identity.encrypted_content() != statement.key_envelope.encrypted_content() {
        return Err(ContractError::InvalidField("seal_completed.encrypted_content").into());
    }
    Ok(VerifiedRemoteSealOutput {
        statement,
        identity,
    })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer as _;
    use elastos_protected_content_contracts::test_fixtures::{
        node_public_key, pool_bundle, pool_descriptor_signed_by, pool_did, runtime_issuer,
        signing_key, POOL_AUTHORITY_SEED,
    };
    use elastos_protected_content_contracts::{
        ContentAccessIdV1, CustodyEnvelopeManifestV1, Digest32, MintRequestV1,
        PqHybridSealedShareV1, SealCompletedV1, PQ_HYBRID_SEALED_SHARE_ENVELOPE_BYTES,
        PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES, X_WING_DRAFT06_CIPHERTEXT_BYTES,
    };
    use x_wing::kem::{Decapsulator as _, KeyExport as _};
    use x_wing::TryKeyInit as _;

    use super::*;
    use crate::test_object::object_identity;

    fn custody_public(seed: u8) -> [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
        x_wing::DecapsulationKey::from([seed; x_wing::DECAPSULATION_KEY_SIZE])
            .encapsulation_key()
            .to_bytes()
            .into()
    }

    #[test]
    fn remote_object_completion_checks_the_fetched_envelope_and_declared_identity() {
        let now = 2_000_000_000;
        let identity = object_identity(0x41);
        let bundle = pool_bundle(custody_public, now);
        let descriptor: SignedPoolDescriptorAnyV1 =
            pool_descriptor_signed_by(&bundle, 1, now, POOL_AUTHORITY_SEED).into();
        let epoch = bundle.signed_epoch().statement();
        let commitment = Digest32::new([0x51; 32]);
        let manifest = CustodyEnvelopeManifestV1::new(
            identity.encrypted_content().clone(),
            bundle.signed_pool().pool_identity().unwrap(),
            bundle.epoch_identity().unwrap(),
            bundle
                .signed_committee_authorization()
                .authorization_identity()
                .unwrap(),
            epoch.threshold(),
            commitment,
            epoch.nodes().to_vec(),
        )
        .unwrap();
        // This verification fixture exercises identities, without opening a share.
        let shares = (1..=3)
            .map(|seed| {
                let key = x_wing::EncapsulationKey::new_from_slice(&custody_public(seed)).unwrap();
                let (ciphertext, _) = key.encapsulate_deterministic(
                    &[seed; x_wing::ENCAPSULATION_RANDOMNESS_SIZE].into(),
                );
                let bytes: [u8; X_WING_DRAFT06_CIPHERTEXT_BYTES] = ciphertext.into();
                let mut share = bytes.to_vec();
                share.resize(PQ_HYBRID_SEALED_SHARE_ENVELOPE_BYTES, seed);
                PqHybridSealedShareV1::new(share).unwrap()
            })
            .collect();
        let envelope = CustodyEnvelopeV1::new(manifest, shares).unwrap();
        let asset = ContentAccessIdV1::new([0x61; 16]).unwrap();
        let minter = MintRequestV1 {
            pool: pool_did(),
            epoch: bundle.epoch_identity().unwrap(),
            minter_issuer: runtime_issuer(POOL_AUTHORITY_SEED),
            content_access_id: asset,
            clear_layout: ClearLayoutV1::Object {
                content_type: identity.content_type().into(),
                length: identity.plaintext_bytes(),
            },
            request_nonce: [0x71; 16],
            issued_at: now,
            expires_at: now + 60,
        };
        let signature = signing_key(POOL_AUTHORITY_SEED)
            .sign(&minter.canonical_bytes().unwrap())
            .to_bytes();
        let request = SignedMintRequestV1::new(minter, signature).unwrap();
        let node = node_public_key(1);
        let statement = SealCompletedV1 {
            pool: pool_did(),
            epoch: bundle.epoch_identity().unwrap(),
            descriptor_digest: descriptor.canonical_hash().unwrap(),
            sealer_node_public_key: node,
            sealer_device_did: descriptor.member_peer_did(node).unwrap().into(),
            content_publisher_did: "did:key:zPublisher".into(),
            mint_request_hash: request.canonical_hash().unwrap(),
            content_access_id: asset,
            key_envelope: envelope.key_envelope_identity().unwrap(),
            content_identity: identity.canonical_bytes().unwrap(),
            content_key_commitment: commitment,
            package_cid: "bafypackagefixture".into(),
            file_cids: vec![("asset.epc".into(), "bafyfilefixture".into())],
            availability_receipt: vec![1, 2, 3],
            completed_at: now + 1,
        };
        let verify = |statement: SealCompletedV1| {
            let signature = signing_key(1)
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes();
            let signed = SignedSealCompletedV1::new(statement, signature).unwrap();
            verify_remote_seal_output(&signed, &descriptor, &request, node, &envelope, now + 2)
                .map(|verified| verified.identity)
        };
        assert_eq!(
            verify(statement.clone()),
            Ok(RuntimeContentIdentityV1::Object(identity))
        );
        assert_eq!(
            verify(SealCompletedV1 {
                content_identity: object_identity(0x42).canonical_bytes().unwrap(),
                ..statement.clone()
            }),
            Err(ContractError::InvalidField("seal_completed.encrypted_content").into())
        );
        assert_eq!(
            verify(SealCompletedV1 {
                content_key_commitment: Digest32::new([0x52; 32]),
                ..statement.clone()
            }),
            Err(ContractError::InvalidField("seal_completed.fetched_envelope").into())
        );
        let signature = signing_key(1)
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes();
        let completion = SignedSealCompletedV1::new(statement, signature).unwrap();
        assert!(verify_remote_seal_output(
            &completion,
            &descriptor,
            &request,
            node,
            &envelope,
            now + 60
        )
        .is_err());
        let recovered =
            verify_recorded_remote_seal_output(&completion, &descriptor, &request, node, &envelope)
                .unwrap();
        assert_eq!(
            recovered.identity().encrypted_content(),
            envelope.manifest().encrypted_content()
        );
    }
}
