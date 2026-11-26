//! Plan B T3.3: the pool owner's signed pool descriptor.
//!
//! The owner signs one descriptor for its pool with the pool authority key:
//! the current composition and retained epoch bundles, every member with its
//! roles and route, and the pool's serve and mint policies. Members receive it
//! over the pool-active transport, store it (it is public and holds no
//! secret), and answer `describe` from it.
//!
//! The owner reads its composition through the release-time rule
//! (`validate_custody_epoch_for_release_at`), not through the term-gated
//! loader, so a pool past its members' term still re-signs its descriptor and
//! its items keep playing (F1). The sequence orders descriptors across
//! compositions. A change in the installed composition must preserve the
//! exact bundles and member routes already in the descriptor.
//!
//! Item 10 (user 2026-11-12 22:50; DEC-F1): the owner signs only the
//! ticketless v2 descriptor, and each member route is the member's peer DID.
//! A buyer reaches a member through Carrier discovery; a pool member uses the
//! node card it kept. Readers (a member's copy, `describe`, the pool address
//! text) take any version and keep its original bytes.
//!
//! #388 A2 (A388-F1): the owner signs only the v3 descriptor, `WciOperated`
//! with every member's attestation slot empty. A stored v1 or v2 owner record
//! is re-signed as v3 at its sequence + 1; the old signed bytes are never
//! re-encoded, and a member keeps its copy as signed until a newer one comes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use anyhow::Context as _;
use base64::Engine as _;
use elastos_protected_content_contracts::{
    validate_custody_epoch_for_release_at, CanonicalContract, CustodyEpochIssuerKeyV1, Digest32,
    MintPolicyV1, NodePublicKey, PoolAddressAnyV1, PoolAddressV2, PoolDescriptorStatementV3,
    PoolDidV1, PoolEpochBundleV1, PoolMemberRolesV1, PoolMemberRouteV2, PoolMemberV2, PoolMemberV3,
    PoolRolloverProposalV1, PoolTrustModeV1, RuntimeOperationIssuerKeyV1, ServePolicyV1,
    SignedCustodyCommitteeAuthorizationV1, SignedCustodyEpochV1, SignedCustodyPoolV1,
    SignedPoolDescriptorAnyV1, SignedPoolDescriptorV3, SignedPoolRolloverConsentV1,
    SignedPoolRolloverProposalV1, VerifiedPoolDescriptorV1, MAX_POOL_DESCRIPTOR_LIFETIME_SECS,
    MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::collaboration_config::read_owner_only_file;
use crate::collaboration_custody_messages::CustodyRefusal as WireRefusal;
use crate::custody_consent::{CustodyWriteGuard, ServedPoolFacts};
use crate::protected_content_config::{
    ensure_owner_only_dir, policy_authority_signature, MAX_CUSTODY_COMPOSITION_FILE_BYTES,
};
use crate::protected_content_runtime::{
    decode_canonical_contract_base64, decode_custody_epoch_issuer_base64, protected_content_root,
    runtime_custody_composition_config_path, write_owner_only_bytes,
    RuntimeCustodyCompositionConfigFile, RuntimeCustodyRouteTransportConfig,
    MAX_CUSTODY_COMPOSITION_BLOB_BYTES,
};

const OWNER_DESCRIPTOR_FILE: &str = "custody-pool-descriptor.json";
const OWNER_DESCRIPTOR_SCHEMA_V1: &str = "elastos.protected-content.custody-pool-descriptor/v1";
const STAGED_ROLLOVER_FILE: &str = "custody-rollover-staged.json";
const STAGED_ROLLOVER_SCHEMA_V1: &str = "elastos.protected-content.custody-rollover-staged/v1";
/// The owner file holds one descriptor at its cap, as base64, plus its schema.
const MAX_OWNER_DESCRIPTOR_FILE_BYTES: usize =
    MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1.div_ceil(3) * 4 + 1024;
const MAX_STAGED_ROLLOVER_BYTES: usize =
    MAX_OWNER_DESCRIPTOR_FILE_BYTES + MAX_CUSTODY_COMPOSITION_FILE_BYTES.div_ceil(3) * 4 + 8192;
const MAX_ROLLOVER_CONSENT_BYTES: usize = 512;
/// A member keeps the exact signed bytes, bounded by the descriptor cap (L14).
const SERVED_DESCRIPTOR_FILE: &str = "custody-served-pool-descriptor.bin";
/// The owner re-signs a descriptor this long before it expires.
const RESIGN_BEFORE_EXPIRY_SECS: u64 = 7 * 86_400;
/// The text form of a pool address (E4): this prefix, then base64url without
/// padding of its canonical bytes.
pub(crate) const POOL_ADDRESS_TEXT_PREFIX: &str = "elastos-pool:";

const NOT_MEMBER: WireRefusal = WireRefusal::new("not_member");
const STALE_NOTICE: WireRefusal = WireRefusal::new("stale_notice");
const INVALID_DESCRIPTOR: WireRefusal = WireRefusal::new("invalid_payload");

/// Descriptor files change one writer at a time.
static DESCRIPTOR_LOCK: Mutex<()> = Mutex::new(());

fn lock() -> anyhow::Result<MutexGuard<'static, ()>> {
    DESCRIPTOR_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("the custody pool descriptor lock is poisoned"))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerDescriptorFileV1 {
    schema: String,
    /// Standard base64 of the signed descriptor's canonical bytes.
    descriptor_base64: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RolloverPreparedV1 {
    proposal_base64: String,
    descriptor_base64: String,
    expires_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StagedRolloverV1 {
    schema: String,
    operation_id: [u8; 16],
    input_digest: [u8; 32],
    prepared: RolloverPreparedV1,
    composition_base64: String,
    #[serde(default)]
    consents: BTreeMap<String, String>,
}

impl StagedRolloverV1 {
    fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        if !present(path)? {
            return Ok(None);
        }
        let bytes =
            read_owner_only_file(path, MAX_STAGED_ROLLOVER_BYTES, "staged custody rollover")?;
        let record: Self = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(
            record.schema == STAGED_ROLLOVER_SCHEMA_V1,
            "invalid staged custody rollover schema"
        );
        Ok(Some(record))
    }

    fn write(&self, path: &Path) -> anyhow::Result<()> {
        let record = serde_json::to_vec(self)?;
        anyhow::ensure!(
            record.len() <= MAX_STAGED_ROLLOVER_BYTES,
            "staged custody rollover exceeds its limit"
        );
        write_owner_only_bytes(path, &record)
    }

    fn verify(
        &self,
        previous: &SignedPoolDescriptorV3,
        now: u64,
    ) -> anyhow::Result<(
        SignedPoolRolloverProposalV1,
        SignedPoolDescriptorV3,
        Digest32,
    )> {
        let proposal: SignedPoolRolloverProposalV1 = decode_canonical_contract_base64(
            &self.prepared.proposal_base64,
            4096,
            "staged rollover proposal",
        )?;
        let candidate: SignedPoolDescriptorV3 = decode_canonical_contract_base64(
            &self.prepared.descriptor_base64,
            MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1,
            "staged rollover descriptor",
        )?;
        let composition =
            base64::engine::general_purpose::STANDARD.decode(&self.composition_base64)?;
        let digest = Digest32::new(Sha256::digest(composition).into());
        let staged = proposal.verify(previous, &candidate, digest, now)?;
        anyhow::ensure!(
            staged.operation_id == self.operation_id
                && staged.expires_at == self.prepared.expires_at,
            "invalid staged custody rollover binding"
        );
        Ok((proposal, candidate, digest))
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct RolloverConsentRecordedV1 {
    node_public_key: String,
    approved: bool,
}

pub(crate) fn record_rollover_consent(
    _write: &CustodyWriteGuard,
    data_dir: &Path,
    operation_id: [u8; 16],
    decision_base64: &str,
    now: u64,
) -> anyhow::Result<RolloverConsentRecordedV1> {
    use crate::custody_pool_setup::CustodyRefusal;

    let refusal = || CustodyRefusal::new("invalid_rollover_consent");
    let consent: SignedPoolRolloverConsentV1 = decode_canonical_contract_base64(
        decision_base64,
        MAX_ROLLOVER_CONSENT_BYTES,
        "rollover consent",
    )
    .map_err(|_| refusal())?;
    let _guard = lock()?;
    let Some(SignedPoolDescriptorAnyV1::V3(previous)) = load_owner_descriptor(data_dir)? else {
        return Err(CustodyRefusal::new("no_pool").into());
    };
    let path = protected_content_root(data_dir).join(STAGED_ROLLOVER_FILE);
    let mut record = StagedRolloverV1::load(&path)?.ok_or_else(refusal)?;
    if record.operation_id != operation_id {
        return Err(refusal().into());
    }
    let (proposal, candidate, digest) = record.verify(&previous, now)?;
    let statement = proposal
        .verify_member_consent(&previous, &candidate, digest, &consent, now)
        .map_err(|_| refusal())?;
    let node_public_key = hex::encode(statement.node.as_bytes());
    if let Some(kept_base64) = record.consents.get(&node_public_key) {
        let kept: SignedPoolRolloverConsentV1 = decode_canonical_contract_base64(
            kept_base64,
            MAX_ROLLOVER_CONSENT_BYTES,
            "stored rollover consent",
        )?;
        if kept == consent {
            return Ok(RolloverConsentRecordedV1 {
                node_public_key,
                approved: statement.approved,
            });
        }
        // A signed decline is final for this proposal. A delayed approval
        // cannot replace it, even after the decline's submission window ends.
        let kept_statement = proposal.verify_member_consent(
            &previous,
            &candidate,
            digest,
            &kept,
            kept.statement().issued_at,
        )?;
        if kept_statement.node != statement.node || !kept_statement.approved || statement.approved {
            return Err(refusal().into());
        }
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(consent.canonical_bytes()?);
    record.consents.insert(node_public_key.clone(), encoded);
    record.write(&path)?;
    Ok(RolloverConsentRecordedV1 {
        node_public_key,
        approved: statement.approved,
    })
}

/// Persist a proposal for consent. The existing descriptor and composition
/// remain the active ones, and a replay returns the exact staged bytes.
pub(crate) fn stage_owner_rollover(
    _write: &CustodyWriteGuard,
    data_dir: &Path,
    operation_id: [u8; 16],
    input_digest: [u8; 32],
    now: u64,
    build_composition: impl FnOnce() -> anyhow::Result<Vec<u8>>,
) -> anyhow::Result<RolloverPreparedV1> {
    let _guard = lock()?;
    let Some(SignedPoolDescriptorAnyV1::V3(previous)) = load_owner_descriptor(data_dir)? else {
        return Err(crate::custody_pool_setup::CustodyRefusal::new("no_pool").into());
    };
    let active = installed_composition(data_dir, now)?
        .ok_or_else(|| crate::custody_pool_setup::CustodyRefusal::new("no_pool"))?;
    anyhow::ensure!(
        previous.statement().epochs().contains(&active.bundle),
        "the active custody composition is missing from the current descriptor"
    );
    let path = protected_content_root(data_dir).join(STAGED_ROLLOVER_FILE);
    if let Some(kept) = StagedRolloverV1::load(&path)? {
        if kept.operation_id == operation_id {
            anyhow::ensure!(
                kept.input_digest == input_digest,
                "custody rollover operation has different inputs"
            );
            kept.verify(&previous, now)?;
            return Ok(kept.prepared);
        }
        anyhow::ensure!(
            kept.prepared.expires_at <= now,
            "a custody rollover candidate is already staged"
        );
    }

    let bytes = build_composition()?;
    anyhow::ensure!(
        bytes.len() <= MAX_CUSTODY_COMPOSITION_FILE_BYTES,
        "staged custody composition exceeds its limit"
    );
    let composition = parse_owner_composition(&bytes, now)?;
    let stored = SignedPoolDescriptorAnyV1::from(previous.clone());
    let candidate = build_descriptor(
        data_dir,
        &composition,
        Some(&stored),
        *stored.serve_policy(),
        stored.mint_policy().clone(),
        now,
    )?;
    let expires_at = now
        .saturating_add(86_400)
        .min(previous.statement().expires_at())
        .min(candidate.statement().expires_at());
    let statement = PoolRolloverProposalV1 {
        pool: *previous.statement().pool(),
        predecessor_sequence: previous.statement().sequence(),
        predecessor_digest: previous.canonical_hash()?,
        candidate_descriptor_digest: candidate.canonical_hash()?,
        candidate_composition_digest: Digest32::new(Sha256::digest(&bytes).into()),
        provisioning_epoch: composition.bundle.epoch_identity()?,
        operation_id,
        issued_at: now,
        expires_at,
    };
    let signature = policy_authority_signature(
        &crate::custody_pool_setup::policy_authority_key_path(data_dir),
        &statement.canonical_bytes()?,
    )?;
    let digest = statement.candidate_composition_digest;
    let proposal = SignedPoolRolloverProposalV1::new(
        statement,
        signature
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid custody rollover signature size"))?,
    )?;
    proposal.verify(&previous, &candidate, digest, now)?;
    let base64 = base64::engine::general_purpose::STANDARD;
    let prepared = RolloverPreparedV1 {
        proposal_base64: base64.encode(proposal.canonical_bytes()?),
        descriptor_base64: base64.encode(candidate.canonical_bytes()?),
        expires_at,
    };
    StagedRolloverV1 {
        schema: STAGED_ROLLOVER_SCHEMA_V1.into(),
        operation_id,
        input_digest,
        prepared: prepared.clone(),
        composition_base64: base64.encode(bytes),
        consents: BTreeMap::new(),
    }
    .write(&path)?;
    Ok(prepared)
}

fn owner_descriptor_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join(OWNER_DESCRIPTOR_FILE)
}

fn served_descriptor_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join(SERVED_DESCRIPTOR_FILE)
}

/// The installed composition, read through the release-time rule (F1).
struct InstalledComposition {
    authority: CustodyEpochIssuerKeyV1,
    bundle: PoolEpochBundleV1,
    config: RuntimeCustodyCompositionConfigFile,
}

fn installed_composition(
    data_dir: &Path,
    now: u64,
) -> anyhow::Result<Option<InstalledComposition>> {
    let path = runtime_custody_composition_config_path(data_dir);
    if !present(&path)? {
        return Ok(None);
    }
    let bytes = read_owner_only_file(
        &path,
        MAX_CUSTODY_COMPOSITION_FILE_BYTES,
        "custody composition",
    )?;
    parse_owner_composition(&bytes, now).map(Some)
}

fn parse_owner_composition(bytes: &[u8], now: u64) -> anyhow::Result<InstalledComposition> {
    let config: RuntimeCustodyCompositionConfigFile = serde_json::from_slice(bytes)?;
    let authority = decode_custody_epoch_issuer_base64(
        &config.expected_policy_authority_base64,
        "expected_policy_authority",
    )?;
    let authorization_identity = decode_canonical_contract_base64(
        &config.expected_committee_authorization_identity_base64,
        MAX_CUSTODY_COMPOSITION_BLOB_BYTES,
        "expected_committee_authorization_identity",
    )?;
    let pool: SignedCustodyPoolV1 = decode_canonical_contract_base64(
        &config.signed_pool_base64,
        MAX_CUSTODY_COMPOSITION_BLOB_BYTES,
        "signed_pool",
    )?;
    let epoch: SignedCustodyEpochV1 = decode_canonical_contract_base64(
        &config.signed_epoch_base64,
        MAX_CUSTODY_COMPOSITION_BLOB_BYTES,
        "signed_epoch",
    )?;
    let authorization: SignedCustodyCommitteeAuthorizationV1 = decode_canonical_contract_base64(
        &config.signed_committee_authorization_base64,
        MAX_CUSTODY_COMPOSITION_BLOB_BYTES,
        "signed_committee_authorization",
    )?;
    validate_custody_epoch_for_release_at(
        authority,
        authorization_identity,
        &pool,
        &epoch,
        &authorization,
        now,
    )
    .map_err(|error| anyhow::anyhow!("the installed custody pool does not validate: {error:?}"))?;
    let bundle = PoolEpochBundleV1::new(pool, epoch, authorization).map_err(|error| {
        anyhow::anyhow!("the installed custody pool is not a bundle: {error:?}")
    })?;
    Ok(InstalledComposition {
        authority,
        bundle,
        config,
    })
}

/// Every committee member: hold, serve and seal by default; its route is the
/// Carrier peer DID the composition routes to, or this Home's DID for its own
/// node. Routes carry no ticket (item 10).
fn members_for(
    data_dir: &Path,
    composition: &InstalledComposition,
) -> anyhow::Result<Vec<PoolMemberV2>> {
    let own_home = elastos_identity::load_existing_did(data_dir)
        .map(|(_, did)| did)
        .ok();
    composition
        .bundle
        .signed_epoch()
        .statement()
        .nodes()
        .iter()
        .map(|node| {
            let key = node.node_public_key();
            let key_base64 = base64::engine::general_purpose::STANDARD.encode(key.as_bytes());
            let route = composition
                .config
                .routes
                .iter()
                .find(|route| route.node_public_key_base64 == key_base64)
                .context("the installed custody pool has a node without a route")?;
            let peer_did = match &route.transport {
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid { peer_did } => peer_did.clone(),
                RuntimeCustodyRouteTransportConfig::Local => own_home
                    .clone()
                    .context("this Home has no DID for its own pool node")?,
            };
            let route = PoolMemberRouteV2::new(peer_did)
                .map_err(|error| anyhow::anyhow!("a pool member route is invalid: {error:?}"))?;
            PoolMemberV2::new(
                key,
                PoolMemberRolesV1 {
                    hold: true,
                    serve: true,
                    seal: true,
                },
                route,
            )
            .map_err(|error| anyhow::anyhow!("a pool member is invalid: {error:?}"))
        })
        .collect()
}

/// This Home's Runtime issuer, derived from its device key (E12).
fn own_runtime_issuer(data_dir: &Path) -> anyhow::Result<RuntimeOperationIssuerKeyV1> {
    let (device_key, _) =
        crate::collaboration_profile_authority::load_existing_device_signing_key(data_dir)?
            .context("this Home has no device key")?;
    RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes())
        .map_err(|error| anyhow::anyhow!("this Home's device key is invalid: {error:?}"))
}

/// The owner's stored descriptor, in either version (item 10).
fn load_owner_descriptor(data_dir: &Path) -> anyhow::Result<Option<SignedPoolDescriptorAnyV1>> {
    let path = owner_descriptor_path(data_dir);
    if !present(&path)? {
        return Ok(None);
    }
    let bytes = read_owner_only_file(
        &path,
        MAX_OWNER_DESCRIPTOR_FILE_BYTES,
        "custody pool descriptor",
    )?;
    let file: OwnerDescriptorFileV1 = serde_json::from_slice(&bytes)?;
    if file.schema != OWNER_DESCRIPTOR_SCHEMA_V1 {
        anyhow::bail!("the custody pool descriptor has an unknown schema");
    }
    let raw = base64::engine::general_purpose::STANDARD.decode(&file.descriptor_base64)?;
    Ok(Some(
        SignedPoolDescriptorAnyV1::from_canonical_bytes(&raw).map_err(|error| {
            anyhow::anyhow!("the custody pool descriptor is invalid: {error:?}")
        })?,
    ))
}

fn store_owner_descriptor(
    data_dir: &Path,
    descriptor: &SignedPoolDescriptorV3,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(&OwnerDescriptorFileV1 {
        schema: OWNER_DESCRIPTOR_SCHEMA_V1.to_string(),
        descriptor_base64: base64::engine::general_purpose::STANDARD
            .encode(descriptor.canonical_bytes()?),
    })?;
    ensure_owner_only_dir(&protected_content_root(data_dir), "protected-content root")?;
    write_owner_only_bytes(&owner_descriptor_path(data_dir), &bytes)
}

/// The owner's descriptor for the installed pool, built at sequence 1 the
/// first time (L14), reused while nothing changed and it is not about to
/// expire, and re-signed at the stored sequence + 1 otherwise. `None` when
/// no pool is installed.
pub(crate) fn owner_descriptor(
    data_dir: &Path,
    now: u64,
) -> anyhow::Result<Option<SignedPoolDescriptorV3>> {
    let _guard = lock()?;
    let Some(composition) = installed_composition(data_dir, now)? else {
        return Ok(None);
    };
    let stored = load_owner_descriptor(data_dir)?;
    let (serve, mint) = match &stored {
        Some(stored) => (*stored.serve_policy(), stored.mint_policy().clone()),
        None => (
            ServePolicyV1::DEFAULT,
            MintPolicyV1::owner_default(own_runtime_issuer(data_dir)?),
        ),
    };
    sign_descriptor(data_dir, &composition, stored, serve, mint, now).map(Some)
}

/// Sets the pool's policies and re-signs the descriptor at the next
/// sequence. Runs under the custody write lock.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "T3.3 API; its owner task (T3.4 or T4.3) wires the caller"
    )
)]
pub(crate) fn set_owner_policies(
    _write: &CustodyWriteGuard,
    data_dir: &Path,
    serve: ServePolicyV1,
    mint: MintPolicyV1,
    now: u64,
) -> anyhow::Result<SignedPoolDescriptorV3> {
    let _guard = lock()?;
    let composition = installed_composition(data_dir, now)?
        .ok_or_else(|| crate::custody_pool_setup::CustodyRefusal::new("no_pool"))?;
    // Plan B T4.8: the release refuses a server count above the epoch's
    // total (L2), so such a policy is refused before anything is signed.
    let total = composition
        .bundle
        .signed_epoch()
        .statement()
        .threshold()
        .total();
    if serve.max_servers_per_session > total {
        tracing::debug!(
            max_servers_per_session = serve.max_servers_per_session,
            total,
            "custody pool policy refused: more servers than the epoch's nodes"
        );
        return Err(crate::custody_pool_setup::CustodyRefusal::new("too_many_servers").into());
    }
    let stored = load_owner_descriptor(data_dir)?;
    sign_descriptor(data_dir, &composition, stored, serve, mint, now)
}

fn sign_descriptor(
    data_dir: &Path,
    composition: &InstalledComposition,
    stored: Option<SignedPoolDescriptorAnyV1>,
    serve: ServePolicyV1,
    mint: MintPolicyV1,
    now: u64,
) -> anyhow::Result<SignedPoolDescriptorV3> {
    let descriptor = build_descriptor(data_dir, composition, stored.as_ref(), serve, mint, now)?;
    let sequence = descriptor.statement().sequence();
    if stored.as_ref().map(SignedPoolDescriptorAnyV1::sequence) != Some(sequence) {
        store_owner_descriptor(data_dir, &descriptor)?;
        tracing::debug!(sequence, "custody pool descriptor signed");
    }
    Ok(descriptor)
}

/// Sign and verify a candidate before publishing it as the owner's head.
fn build_descriptor(
    data_dir: &Path,
    composition: &InstalledComposition,
    stored: Option<&SignedPoolDescriptorAnyV1>,
    serve: ServePolicyV1,
    mint: MintPolicyV1,
    now: u64,
) -> anyhow::Result<SignedPoolDescriptorV3> {
    // #388 A2: every slot empty under `WciOperated`.
    let current_members = members_for(data_dir, composition)?
        .into_iter()
        .map(|member| PoolMemberV3::new(member, Vec::new()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| anyhow::anyhow!("the pool member is invalid: {error:?}"))?;
    let pool = PoolDidV1::from_issuer(composition.authority);
    let (mut epochs, mut members) = match stored {
        Some(stored) => owner_descriptor_history(stored, &pool, &composition.bundle)?,
        None => (Vec::new(), BTreeMap::new()),
    };
    if !epochs.contains(&composition.bundle) {
        let active_epoch = composition.bundle.epoch_identity()?;
        for kept in &epochs {
            anyhow::ensure!(
                kept.epoch_identity()? != active_epoch,
                "the installed custody composition would replace a kept epoch bundle"
            );
        }
        epochs.push(composition.bundle.clone());
    }
    for member in current_members {
        let kept = members
            .entry(member.node_public_key())
            .or_insert_with(|| member.clone());
        anyhow::ensure!(
            *kept == member,
            "the installed custody composition would change a kept member route or role"
        );
    }
    let members = members.into_values().collect::<Vec<_>>();
    if let Some(SignedPoolDescriptorAnyV1::V3(previous)) = stored {
        let statement = previous.statement();
        let unchanged = statement.epochs() == epochs.as_slice()
            && statement.members() == members.as_slice()
            && statement.serve_policy() == &serve
            && statement.mint_policy() == &mint
            && statement.trust_mode() == PoolTrustModeV1::WciOperated;
        if unchanged && now.saturating_add(RESIGN_BEFORE_EXPIRY_SECS) < statement.expires_at() {
            return Ok(previous.clone());
        }
    }
    // Never lowered, also when the installed composition changed (17:55).
    let sequence = match stored {
        Some(stored) => stored
            .sequence()
            .checked_add(1)
            .context("custody pool descriptor sequence is exhausted")?,
        None => 1,
    };
    let statement = PoolDescriptorStatementV3::new(
        pool,
        sequence,
        epochs,
        members,
        serve,
        mint,
        now,
        now.saturating_add(MAX_POOL_DESCRIPTOR_LIFETIME_SECS),
        PoolTrustModeV1::WciOperated,
    )
    .map_err(|error| anyhow::anyhow!("the pool descriptor is invalid: {error:?}"))?;
    let signature = policy_authority_signature(
        &crate::custody_pool_setup::policy_authority_key_path(data_dir),
        &statement.canonical_bytes()?,
    )?;
    let descriptor = SignedPoolDescriptorV3::new(statement, signature)
        .map_err(|error| anyhow::anyhow!("the signed pool descriptor is invalid: {error:?}"))?;
    descriptor.verify(now).map_err(|error| {
        anyhow::anyhow!("the next custody pool descriptor does not verify: {error:?}")
    })?;
    Ok(descriptor)
}

/// Authenticate the stored owner history at its issuance time. Its window
/// limits live use, but expiry must never discard an existing asset's epoch.
fn owner_descriptor_history(
    stored: &SignedPoolDescriptorAnyV1,
    pool: &PoolDidV1,
    active: &PoolEpochBundleV1,
) -> anyhow::Result<(
    Vec<PoolEpochBundleV1>,
    BTreeMap<NodePublicKey, PoolMemberV3>,
)> {
    anyhow::ensure!(
        stored.pool() == pool,
        "the stored custody descriptor names a different pool"
    );
    let issued_at = match stored {
        SignedPoolDescriptorAnyV1::V1(descriptor) => descriptor.statement().issued_at(),
        SignedPoolDescriptorAnyV1::V2(descriptor) => descriptor.statement().issued_at(),
        SignedPoolDescriptorAnyV1::V3(descriptor) => descriptor.statement().issued_at(),
    };
    stored.verify(issued_at).map_err(|error| {
        anyhow::anyhow!("the stored custody pool descriptor does not verify: {error:?}")
    })?;
    let SignedPoolDescriptorAnyV1::V3(previous) = stored else {
        // Keep the existing single-bundle v3 upgrade, whose routes and trust
        // come from the verified local composition.
        anyhow::ensure!(
            stored.epochs() == std::slice::from_ref(active),
            "upgrade the kept custody descriptor before changing its composition"
        );
        return Ok((Vec::new(), BTreeMap::new()));
    };
    Ok((
        previous.statement().epochs().to_vec(),
        previous
            .statement()
            .members()
            .iter()
            .map(|member| (member.node_public_key(), member.clone()))
            .collect(),
    ))
}

/// A v3 successor must keep all previous bundles and routes. Until the
/// retirement protocol exists, a descriptor update cannot withdraw serving authority.
pub(crate) fn preserves_serving_history(
    kept: &SignedPoolDescriptorAnyV1,
    newer: &SignedPoolDescriptorAnyV1,
) -> bool {
    let SignedPoolDescriptorAnyV1::V3(kept) = kept else {
        return true;
    };
    let SignedPoolDescriptorAnyV1::V3(newer) = newer else {
        return false;
    };
    newer.preserves_serving_history(kept)
}

/// A served owner's descriptor (L13). The caller has checked what
/// `receive_pool_active` checks of the sender; here the descriptor verifies
/// by the release rule, holds a bundle whose signed pool is the pool this node
/// serves (its issuer, start, end, threshold and this node at its share), and
/// is newer than the descriptor kept for that pool. Otherwise `not_member` or
/// `stale_notice`. Either version is kept as its original signed bytes
/// (item 10).
pub(crate) fn store_member_descriptor(
    data_dir: &Path,
    served: &ServedPoolFacts,
    descriptor: &SignedPoolDescriptorAnyV1,
    now: u64,
) -> Result<(), WireRefusal> {
    let unavailable = |error: anyhow::Error| {
        tracing::debug!(error = %format!("{error:#}"), "the served pool descriptor is unavailable");
        WireRefusal::UNAVAILABLE
    };
    let verified = descriptor.verify(now).map_err(|_| INVALID_DESCRIPTOR)?;
    let bundle = matching_bundle(descriptor.epochs(), verified.pool(), served).ok_or(NOT_MEMBER)?;
    let pool_start = signed_pool_start(bundle).ok_or(NOT_MEMBER)?;
    let bytes = descriptor
        .canonical_bytes()
        .map_err(|_| INVALID_DESCRIPTOR)?;
    if bytes.len() > MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1 {
        return Err(INVALID_DESCRIPTOR);
    }
    // Plan B T2.2 (re-anchor F6): kept in that pool's served-pools entry,
    // one descriptor per pool, as signed.
    let pool_key = served.issuer_fingerprint_full.clone();
    let outcome = crate::custody_consent::update_served_pools(data_dir, |pools| {
        let Some(entry) = pools.entries.get_mut(&pool_key) else {
            return Ok(Err(NOT_MEMBER));
        };
        if let Some(kept) = entry
            .descriptor
            .as_deref()
            .and_then(decode_entry_descriptor)
        {
            let same_composition = matching_bundle(kept.epochs(), kept.pool(), served)
                .and_then(signed_pool_start)
                == Some(pool_start);
            if (same_composition || matches!(kept, SignedPoolDescriptorAnyV1::V3(_)))
                && kept.sequence() >= descriptor.sequence()
            {
                return Ok(Err(STALE_NOTICE));
            }
            if !preserves_serving_history(&kept, descriptor) {
                return Ok(Err(INVALID_DESCRIPTOR));
            }
        }
        entry.descriptor = Some(base64::engine::general_purpose::STANDARD.encode(&bytes));
        entry.pool_did = descriptor.pool().to_did_key().ok();
        Ok(Ok(()))
    })
    .map_err(unavailable)?;
    outcome?;
    tracing::debug!(
        sequence = descriptor.sequence(),
        "the served pool's descriptor is kept"
    );
    Ok(())
}

/// The bundle whose signed pool is the served one.
fn matching_bundle<'a>(
    bundles: &'a [PoolEpochBundleV1],
    pool: &PoolDidV1,
    served: &ServedPoolFacts,
) -> Option<&'a PoolEpochBundleV1> {
    bundles.iter().find(|bundle| {
        let signed_pool = bundle.signed_pool().statement();
        let epoch = bundle.signed_epoch().statement();
        let end = signed_pool
            .members()
            .iter()
            .map(|member| member.valid_until())
            .min();
        crate::custody_node_card::Fingerprint::of(signed_pool.issuer().as_bytes()).full
            == served.issuer_fingerprint_full
            && pool.issuer() == signed_pool.issuer()
            && signed_pool_start(bundle) == Some(served.pool_start)
            && end == Some(served.term_end)
            && epoch.threshold().required() == served.required
            && epoch.threshold().total() == served.total
            && epoch.nodes().iter().any(|node| {
                *node.node_public_key().as_bytes() == served.own_node_key
                    && node.share_coordinate().get() == served.share
            })
    })
}

/// The signed pool's start: the latest member `valid_from`.
fn signed_pool_start(bundle: &PoolEpochBundleV1) -> Option<u64> {
    bundle
        .signed_pool()
        .statement()
        .members()
        .iter()
        .map(|member| member.valid_from())
        .max()
}

/// The v1 descriptor file (one served pool), read once into the served-pools
/// map by Plan B T2.2. The file stays on disk, unused.
pub(crate) fn v1_served_descriptor_bytes(data_dir: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    let path = served_descriptor_path(data_dir);
    if !present(&path)? {
        return Ok(None);
    }
    Ok(Some(read_owner_only_file(
        &path,
        MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1,
        "served custody pool descriptor",
    )?))
}

/// MEMBER-COPIES: whether `descriptor` names the custody pool `pool`, the
/// one a key envelope names, in one of its epochs.
pub(crate) fn descriptor_names_custody_pool(
    descriptor: &SignedPoolDescriptorAnyV1,
    pool: elastos_protected_content_contracts::CustodyPoolIdentityV1,
) -> bool {
    descriptor
        .epochs()
        .iter()
        .any(|bundle| bundle.signed_pool().pool_identity().ok() == Some(pool))
}

/// MEMBER-COPIES: whether the descriptor a served-pools entry keeps names
/// the custody pool `pool`. An entry without one names none.
pub(crate) fn served_entry_names_custody_pool(
    entry: &crate::custody_consent::ServedPoolEntryV2,
    pool: elastos_protected_content_contracts::CustodyPoolIdentityV1,
) -> bool {
    entry
        .descriptor
        .as_deref()
        .and_then(decode_entry_descriptor)
        .is_some_and(|descriptor| descriptor_names_custody_pool(&descriptor, pool))
}

/// MEMBER-COPIES (lead ruling 2026-11-16): the members a listing of the
/// custody pool `pool` is copied to: every member's Carrier DID in the
/// current descriptor of this Home's own pool, of a pool it serves, or of a
/// pool it uses, that names `pool`, this Home excluded. Empty when no
/// descriptor names it. STAB-42 (D3): the pool's owner is a member of its
/// own descriptor, so it is asked like every other key-share holder. STAB-10
/// (D3): a content fetch asks these before any other pool's members.
pub(crate) fn pool_copy_holders(
    data_dir: &Path,
    pool: elastos_protected_content_contracts::CustodyPoolIdentityV1,
    now: u64,
) -> Vec<String> {
    let own = elastos_identity::load_existing_did(data_dir)
        .map(|(_, did)| did)
        .unwrap_or_default();
    load_owner_descriptor(data_dir)
        .ok()
        .flatten()
        .into_iter()
        .chain(served_descriptors(data_dir, now).unwrap_or_default())
        .chain(crate::custody_pool_resolver::known_pool_descriptors(
            data_dir,
        ))
        .filter(|descriptor| descriptor_names_custody_pool(descriptor, pool))
        .find_map(|descriptor| descriptor.verify(now).ok())
        .map(|verified| {
            crate::custody_pool_resolver::bounded_unique_peer_dids(
                verified
                    .members()
                    .iter()
                    .map(|member| member.route().peer_did().to_string())
                    .filter(|did| *did != own),
            )
        })
        .unwrap_or_default()
}

/// STAB-08 (J4-F3(a)): the pool members a content fetch asks as holders:
/// the members of this Home's own pool and of the pools it serves, then those
/// of the pools it uses ([`crate::custody_pool_resolver::known_pool_member_peer_dids`]).
/// Only descriptors that verify at `now` count; this Home excluded, unique,
/// at most [`crate::custody_pool_resolver::MAX_KNOWN_POOL_CONTENT_HOLDERS`].
/// With the creator offline, a member then still finds its fellow members'
/// copies. The bytes are still checked against their CIDs, as for any holder.
pub(crate) fn pool_member_content_holder_peer_dids(data_dir: &Path, now: u64) -> Vec<String> {
    let own = elastos_identity::load_existing_did(data_dir)
        .map(|(_, did)| did)
        .unwrap_or_default();
    let served = served_descriptors(data_dir, now).unwrap_or_else(|error| {
        tracing::debug!(error = %format!("{error:#}"), "served pools are unreadable for holders");
        Vec::new()
    });
    let own_and_served = load_owner_descriptor(data_dir)
        .ok()
        .flatten()
        .into_iter()
        .chain(served)
        .filter_map(|descriptor| descriptor.verify(now).ok())
        .flat_map(|verified| {
            verified
                .members()
                .iter()
                .map(|member| member.route().peer_did().to_string())
                .collect::<Vec<_>>()
        });
    crate::custody_pool_resolver::bounded_unique_peer_dids(
        own_and_served
            .chain(crate::custody_pool_resolver::known_pool_member_peer_dids(
                data_dir, now,
            ))
            .filter(|did| *did != own),
    )
}

/// STAB-42 (D3): whether this Home's own pool descriptor names the custody
/// pool `pool` (the one a listing's key envelope names) and is the pool
/// `pool_did` (the one a minter's share statement names).
pub(crate) fn own_descriptor_names_pool(
    data_dir: &Path,
    pool: elastos_protected_content_contracts::CustodyPoolIdentityV1,
    pool_did: &PoolDidV1,
) -> bool {
    load_owner_descriptor(data_dir)
        .ok()
        .flatten()
        .is_some_and(|descriptor| {
            descriptor_names_custody_pool(&descriptor, pool) && descriptor.pool() == pool_did
        })
}

/// STAB-12 (J4-F4, A2-F6; D7): the Homes of the copy pool `pool_key` (a
/// served-pools key, or this Home's own pool's), by Carrier DID: its owner
/// and the members of its current descriptor. They read the pool's copies
/// with no rate limit, since pool playback is served by them part by part.
pub(crate) fn copy_pool_peer_dids(data_dir: &Path, pool_key: &str, now: u64) -> Vec<String> {
    let members = |descriptor: SignedPoolDescriptorAnyV1| {
        descriptor
            .verify(now)
            .map(|verified| {
                verified
                    .members()
                    .iter()
                    .map(|member| member.route().peer_did().to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    if let Some(entry) = crate::custody_consent::served_pools(data_dir)
        .ok()
        .and_then(|pools| pools.entries.get(pool_key).cloned())
    {
        let Some(descriptor) = entry
            .descriptor
            .as_deref()
            .and_then(decode_entry_descriptor)
        else {
            return Vec::new();
        };
        let Ok(verified) = descriptor.verify(now) else {
            return Vec::new();
        };
        let mut peers = vec![entry.owner_home.clone()];
        peers.extend(
            verified
                .members()
                .iter()
                .map(|member| member.route().peer_did().to_string()),
        );
        return peers;
    }
    if crate::custody_consent::own_copy_pool(data_dir).is_some_and(|(key, _)| key == pool_key) {
        return load_owner_descriptor(data_dir)
            .ok()
            .flatten()
            .map(members)
            .unwrap_or_default();
    }
    Vec::new()
}

/// MC-F6: the pool a served-pools entry's kept descriptor names. An entry
/// without one names none.
pub(crate) fn served_entry_pool_did(
    entry: &crate::custody_consent::ServedPoolEntryV2,
) -> Option<elastos_protected_content_contracts::PoolDidV1> {
    entry
        .descriptor
        .as_deref()
        .and_then(decode_entry_descriptor)
        .map(|descriptor| *descriptor.pool())
}

/// A served-pools entry's descriptor, in its own version; an unreadable one
/// reads as none.
fn decode_entry_descriptor(encoded: &str) -> Option<SignedPoolDescriptorAnyV1> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    SignedPoolDescriptorAnyV1::from_canonical_bytes(&bytes)
        .inspect_err(|error| {
            tracing::warn!(?error, "a served pool's kept descriptor is invalid");
        })
        .ok()
}

/// The descriptor this node keeps for `pool` (its served-pools entry).
fn load_served_descriptor(
    data_dir: &Path,
    pool: &PoolDidV1,
) -> anyhow::Result<Option<SignedPoolDescriptorAnyV1>> {
    let pool_key = crate::custody_node_card::Fingerprint::of(pool.issuer().as_bytes()).full;
    let pools = crate::custody_consent::served_pools(data_dir)?;
    Ok(pools
        .entries
        .get(&pool_key)
        .and_then(|entry| entry.descriptor.as_deref())
        .and_then(decode_entry_descriptor)
        .filter(|descriptor| descriptor.pool() == pool))
}

/// The descriptor this node keeps for `pool`, verified at `now` by the
/// release rule.
pub(crate) fn served_descriptor(
    data_dir: &Path,
    pool: &PoolDidV1,
    now: u64,
) -> anyhow::Result<Option<VerifiedPoolDescriptorV1>> {
    Ok(load_served_descriptor(data_dir, pool)?.and_then(|descriptor| descriptor.verify(now).ok()))
}

/// Plan B S4 (T3.3 amendment R4; item 10) and T2.2 (re-anchor F6): the
/// descriptors this node keeps as a member, one per served pool, that verify
/// at `now` by the release rule, in their own version and as signed, so the
/// resolver can keep the exact bytes.
pub(crate) fn served_descriptors(
    data_dir: &Path,
    now: u64,
) -> anyhow::Result<Vec<SignedPoolDescriptorAnyV1>> {
    Ok(crate::custody_consent::served_pools(data_dir)?
        .entries
        .values()
        .filter_map(|entry| entry.descriptor.as_deref())
        .filter_map(decode_entry_descriptor)
        .filter(|descriptor| descriptor.verify(now).is_ok())
        .collect())
}

/// `describe`: the owner's own descriptor for its pool, else the copy this
/// node keeps as a member; nothing for any other pool. Either version, as
/// signed (item 10).
pub(crate) fn describe(
    data_dir: &Path,
    pool: &PoolDidV1,
    now: u64,
) -> anyhow::Result<Option<SignedPoolDescriptorAnyV1>> {
    if let Some(owned) = owner_descriptor(data_dir, now)? {
        if owned.statement().pool() == pool {
            return Ok(Some(owned.into()));
        }
    }
    let Some(kept) = load_served_descriptor(data_dir, pool)? else {
        return Ok(None);
    };
    Ok(kept.verify(now).is_ok().then_some(kept))
}

/// Plan B S7-lite T7.3 (S7L-F2): the custody root this Home trusts to hold
/// `pool`, from its own records, and the descriptor it keeps for that pool.
/// This Home's own pool (its pool signing key) is held by its own root; a
/// served pool by the root its served-pools entry names. Any other pool has
/// no trusted root here, whatever a descriptor says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedPoolRoot {
    pub(crate) root_path: String,
    pub(crate) kept: Option<SignedPoolDescriptorAnyV1>,
}

pub(crate) fn trusted_pool_root(
    data_dir: &Path,
    pool: &PoolDidV1,
) -> anyhow::Result<Option<TrustedPoolRoot>> {
    let fingerprint = crate::custody_node_card::Fingerprint::of(pool.issuer().as_bytes()).full;
    let own = crate::custody_pool_setup::signing_key_fingerprint(data_dir)?;
    if own.is_some_and(|own| own.full == fingerprint) {
        let Some(root_path) = crate::custody_pool_setup::own_root_path(data_dir)? else {
            return Ok(None);
        };
        let kept = load_owner_descriptor(data_dir)?.filter(|kept| kept.pool() == pool);
        return Ok(Some(TrustedPoolRoot { root_path, kept }));
    }
    Ok(crate::custody_consent::served_pools(data_dir)?
        .entries
        .get(&fingerprint)
        .map(|entry| TrustedPoolRoot {
            root_path: entry.root_path.clone(),
            kept: entry
                .descriptor
                .as_deref()
                .and_then(decode_entry_descriptor)
                .filter(|kept| kept.pool() == pool),
        }))
}

/// Plan B S7-lite T7.3 (S7L-F2): whether a provisioning request for `node`
/// under `descriptor` is for THIS Home's trusted binding of that pool:
/// - this Home trusts a root for the descriptor's pool (`trusted`);
/// - that root's node key is the request's node (`root_node`);
/// - the descriptor is not older than the one this Home keeps for the pool.
///
/// The descriptor's signature, the minter's share statement and the term are the
/// custody provider's checks; a self-signed descriptor names its signer's
/// own pool, which has no trusted root here.
pub(crate) fn check_pool_provision(
    trusted: Option<&TrustedPoolRoot>,
    root_node: Option<NodePublicKey>,
    descriptor: &SignedPoolDescriptorAnyV1,
    node: NodePublicKey,
) -> Result<(), &'static str> {
    let trusted = trusted.ok_or("pool_not_served")?;
    if root_node != Some(node) {
        return Err("node_not_in_pool_root");
    }
    if trusted
        .kept
        .as_ref()
        .is_some_and(|kept| descriptor.sequence() < kept.sequence())
    {
        return Err("stale_descriptor");
    }
    Ok(())
}

/// [`check_pool_provision`] against this Home's records. Admitted, it
/// returns the directory of the root that holds the pool.
pub(crate) fn admit_pool_provision(
    data_dir: &Path,
    descriptor: &SignedPoolDescriptorAnyV1,
    node: NodePublicKey,
) -> Result<PathBuf, &'static str> {
    let trusted = trusted_pool_root(data_dir, descriptor.pool()).map_err(|error| {
        tracing::debug!(error = %format!("{error:#}"), "the trusted pool root is unavailable");
        "unavailable"
    })?;
    let root_dir = trusted.as_ref().map(|trusted| {
        crate::protected_content_runtime::custody_root_dir(data_dir, &trusted.root_path)
    });
    let root_node = root_dir
        .as_deref()
        .and_then(|root_dir| custody_provider::load_node_public_key(root_dir).ok());
    check_pool_provision(trusted.as_ref(), root_node, descriptor, node)?;
    root_dir.ok_or("pool_not_served")
}

/// `elastos-pool:` + base64url (no padding) of the canonical bytes (E4).
/// Writers encode the ticketless v2 address (item 10).
pub(crate) fn encode_pool_address(address: &PoolAddressV2) -> anyhow::Result<String> {
    Ok(format!(
        "{POOL_ADDRESS_TEXT_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(address.canonical_bytes()?)
    ))
}

/// Parses either address version (item 10). Custody's Add a pool reads it
/// (T4.3).
pub(crate) fn parse_pool_address(text: &str) -> anyhow::Result<PoolAddressAnyV1> {
    let encoded = text
        .trim()
        .strip_prefix(POOL_ADDRESS_TEXT_PREFIX)
        .context("a pool address starts with elastos-pool:")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .context("a pool address is base64url")?;
    PoolAddressAnyV1::from_canonical_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("a pool address is invalid: {error:?}"))
}

/// The owner's pool address for the summary: its pool and this Home as the
/// first route. Nothing is signed or written.
pub(crate) fn owner_pool_address(data_dir: &Path) -> Option<String> {
    let key = crate::protected_content_config::policy_authority_public_key(
        &crate::custody_pool_setup::policy_authority_key_path(data_dir),
    )
    .ok()?;
    let authority = CustodyEpochIssuerKeyV1::new(key).ok()?;
    let (_, home) = elastos_identity::load_existing_did(data_dir).ok()?;
    let address = PoolAddressV2::new(
        PoolDidV1::from_issuer(authority),
        PoolMemberRouteV2::new(home).ok()?,
    )
    .ok()?;
    encode_pool_address(&address).ok()
}

fn present(path: &Path) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(all(test, unix))]
mod tests;
