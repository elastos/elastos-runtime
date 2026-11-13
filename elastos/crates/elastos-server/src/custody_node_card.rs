//! Node cards: the one-line text a custody node operator hands to a pool
//! owner. A card carries the node's exact descriptor bytes, its Carrier
//! connect ticket, the provider roles it hosts and its kubo peer id.

use std::path::Path;

use anyhow::Context as _;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::carrier::decode_ticket_endpoints;
use crate::collaboration_config::read_owner_only_file;
use crate::operator_control::{normalize_ipfs_peer, OperatorPeerIpfs};
use crate::protected_content_config::{
    validated_custody_node_descriptor, validated_custody_node_label,
    CustodyNodeDescriptorTransportV1, CustodyNodeDescriptorV1, ValidatedCustodyNodeDescriptor,
    CUSTODY_NODE_DESCRIPTOR_SCHEMA_V1, MAX_CUSTODY_NODE_DESCRIPTOR_BYTES,
};
use crate::protected_content_runtime::{
    decode_canonical_peer_did, RuntimeCustodyRouteTransportConfig,
};

pub(crate) const NODE_CARD_PREFIX: &str = "elastos-node-card:v1:";
const NODE_CARD_PREFIX_STEM: &str = "elastos-node-card:v";
pub(crate) const NODE_CARD_SCHEMA_V1: &str = "elastos.protected-content.custody-node-card/v1";
const NODE_CARD_SCHEMA_STEM: &str = "elastos.protected-content.custody-node-card/v";
/// Real cards are a few KiB. The cap bounds the work done on pasted text
/// before any decoding, line breaks from chat or email included.
const MAX_NODE_CARD_TEXT_BYTES: usize = 16 * 1024;
/// In sorted order: a card lists a sorted, distinct subset of these.
pub(crate) const NODE_CARD_PROVIDES: [&str; 3] = ["chain", "custody", "ipfs"];
const IPFS_PROVIDES: &str = "ipfs";
/// Every custody node serves these, in sorted order; it adds ipfs when it
/// knows its kubo peer id.
const NODE_ANSWER_BASE_PROVIDES: [&str; 2] = ["chain", "custody"];
pub(crate) const NODE_CARD_ANSWER_SCHEMA_V1: &str =
    "elastos.protected-content.custody-node-card-read/v1";
const NODE_CARD_ANSWER_SCHEMA_STEM: &str = "elastos.protected-content.custody-node-card-read/v";
/// Written by the provider host (`provider_host.rs`, `READY_RECEIPT_RELATIVE_PATH`).
const PROVIDER_HOST_READY_RECEIPT: &str = "run/provider-host.ready.json";
const MAX_PROVIDER_HOST_READY_RECEIPT_BYTES: usize = 64 * 1024;
/// A full Home's own kubo repo, the file `deploy/custody-host/up.sh`
/// `host_kubo_peer_id` reads.
const IPFS_REPO_CONFIG: &str = "ipfs-repo/config";
/// A kubo config is a few KiB; peering lists grow it.
const MAX_IPFS_REPO_CONFIG_BYTES: usize = 256 * 1024;

/// The one field read from kubo's config; the private key beside it is not.
#[derive(Deserialize)]
struct KuboRepoConfig {
    #[serde(rename = "Identity")]
    identity: KuboIdentity,
}

#[derive(Deserialize)]
struct KuboIdentity {
    #[serde(rename = "PeerID")]
    peer_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeCardV1 {
    schema: String,
    /// Standard base64 of the exact descriptor bytes the node exported.
    node: String,
    ticket: String,
    provides: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ipfs_peer_id: Option<String>,
}

/// A custody node's answer to its pool owner over Carrier: the card without
/// its ticket, which the owner already holds because it dialed it.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeCardAnswer {
    schema: String,
    /// Standard base64 of the exact descriptor bytes the node stored.
    node: String,
    provides: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ipfs_peer_id: Option<String>,
}

/// A card that passed every check, with the descriptor it carries.
pub(crate) struct NodeCard {
    pub(crate) node_bytes: Vec<u8>,
    pub(crate) descriptor: ValidatedCustodyNodeDescriptor,
    pub(crate) ticket: String,
    pub(crate) provides: Vec<String>,
    pub(crate) ipfs_peer_id: Option<String>,
    pub(crate) fingerprint: String,
    pub(crate) fingerprint_full: String,
}

/// Why a card cannot be used. Each code has one line of user copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeCardRefusal {
    NotACard,
    NewerVersion,
    Changed,
    Unsupported,
    TicketMismatch,
    StorageWithoutId,
    BadLabels,
    LocalCard,
}

impl NodeCardRefusal {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::NotACard => "not_a_card",
            Self::NewerVersion => "newer_version",
            Self::Changed => "changed",
            Self::Unsupported => "unsupported",
            Self::TicketMismatch => "ticket_mismatch",
            Self::StorageWithoutId => "storage_without_id",
            Self::BadLabels => "bad_labels",
            Self::LocalCard => "local_card",
        }
    }
}

/// Build a card and prove it parses, so a node never hands out a card its
/// pool owner would refuse.
pub(crate) fn encode_node_card(
    node_bytes: &[u8],
    ticket: &str,
    provides: &[String],
    ipfs_peer_id: Option<&str>,
) -> Result<String, NodeCardRefusal> {
    let mut provides = provides.to_vec();
    provides.sort();
    provides.dedup();
    let card = NodeCardV1 {
        schema: NODE_CARD_SCHEMA_V1.to_string(),
        node: base64::engine::general_purpose::STANDARD.encode(node_bytes),
        ticket: ticket.to_string(),
        provides,
        ipfs_peer_id: ipfs_peer_id.map(str::to_string),
    };
    let json = serde_json::to_vec(&card).map_err(|_| NodeCardRefusal::NotACard)?;
    let text = format!(
        "{NODE_CARD_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
    );
    parse_node_card(&text)?;
    Ok(text)
}

pub(crate) fn parse_node_card(text: &str) -> Result<NodeCard, NodeCardRefusal> {
    if text.len() > MAX_NODE_CARD_TEXT_BYTES {
        return Err(NodeCardRefusal::NotACard);
    }
    // Chat and email wrap long lines; base64url never contains whitespace.
    let compact: String = text
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(card_body(&compact)?)
        .map_err(|_| NodeCardRefusal::NotACard)?;
    let card = card_v1(&json)?;
    let node_bytes = base64::engine::general_purpose::STANDARD
        .decode(&card.node)
        .map_err(|_| NodeCardRefusal::NotACard)?;
    let descriptor = validated_card_descriptor(&node_bytes)?;
    let provides = validated_provides(card.provides)?;
    let ipfs_peer_id = validated_ipfs_peer_id(&provides, card.ipfs_peer_id)?;
    if !ticket_reaches_descriptor_peer(&card.ticket, &descriptor) {
        return Err(NodeCardRefusal::TicketMismatch);
    }
    let print = Fingerprint::of(&node_bytes);
    Ok(NodeCard {
        fingerprint: print.short,
        fingerprint_full: print.full,
        node_bytes,
        descriptor,
        ticket: card.ticket,
        provides,
        ipfs_peer_id,
    })
}

/// What this node offers its pool owner, as stored and found on this Home.
pub(crate) struct LocalNodeCard {
    pub(crate) node_bytes: Vec<u8>,
    pub(crate) provides: Vec<String>,
    pub(crate) ipfs_peer_id: Option<String>,
}

/// The `inactive` root's card facts, or `None` when it was never
/// provisioned as a custody node. Plan B T2.2: callers name the root now
/// (`served_node_card`) and nothing calls this; it stays until its removal
/// is approved.
#[allow(dead_code)]
pub(crate) fn local_node_card(data_dir: &Path) -> anyhow::Result<Option<LocalNodeCard>> {
    served_node_card(data_dir, custody_provider::CUSTODY_INACTIVE_ROOT_PATH)
}

/// Plan B T2.2: the card facts of the node at custody root `root_path`, or
/// `None` when that root was never provisioned as a served node.
pub(crate) fn served_node_card(
    data_dir: &Path,
    root_path: &str,
) -> anyhow::Result<Option<LocalNodeCard>> {
    let path =
        crate::protected_content_config::custody_node_descriptor_path_for(data_dir, root_path);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("failed to inspect custody node details"),
        Ok(_) => {}
    }
    let node_bytes = read_owner_only_file(
        &path,
        MAX_CUSTODY_NODE_DESCRIPTOR_BYTES,
        "custody node details",
    )?;
    let ipfs_peer_id = node_ipfs_peer_id(data_dir);
    Ok(Some(LocalNodeCard {
        node_bytes,
        provides: provides_with(ipfs_peer_id.is_some()),
        ipfs_peer_id,
    }))
}

/// The roles this Home's node card carries, as its offer states them before
/// it is a node: storage only when it knows its kubo peer id.
pub(crate) fn node_provides(data_dir: &Path) -> Vec<String> {
    provides_with(node_ipfs_peer_id(data_dir).is_some())
}

fn provides_with(storage: bool) -> Vec<String> {
    let mut provides: Vec<String> = NODE_ANSWER_BASE_PROVIDES.map(str::to_string).to_vec();
    if storage {
        provides.push(IPFS_PROVIDES.to_string());
    }
    provides
}

/// This node's answer to its pool owner, or `None` when it was never
/// provisioned as a custody node.
pub(crate) fn local_node_card_answer(
    data_dir: &Path,
    root_path: &str,
) -> anyhow::Result<Option<NodeCardAnswer>> {
    let Some(card) = served_node_card(data_dir, root_path)? else {
        return Ok(None);
    };
    tracing::debug!(
        fingerprint = %fingerprint(&card.node_bytes),
        provides = ?card.provides,
        "custody node card answered"
    );
    Ok(Some(NodeCardAnswer {
        schema: NODE_CARD_ANSWER_SCHEMA_V1.to_string(),
        node: base64::engine::general_purpose::STANDARD.encode(&card.node_bytes),
        provides: card.provides,
        ipfs_peer_id: card.ipfs_peer_id,
    }))
}

/// The provider host's receipt decides when there is one. A full Home runs no
/// provider host: its storage is the kubo node in its own repo.
fn node_ipfs_peer_id(data_dir: &Path) -> Option<String> {
    let receipt = data_dir.join(PROVIDER_HOST_READY_RECEIPT);
    if std::fs::symlink_metadata(&receipt).is_ok() {
        return ready_receipt_ipfs_peer_id(&receipt);
    }
    ipfs_repo_peer_id(data_dir)
}

/// The kubo peer id the provider host published, when its ipfs plane started.
fn ready_receipt_ipfs_peer_id(path: &Path) -> Option<String> {
    let bytes = read_owner_only_file(
        path,
        MAX_PROVIDER_HOST_READY_RECEIPT_BYTES,
        "provider host readiness receipt",
    )
    .inspect_err(|error| tracing::debug!(%error, "provider host readiness receipt is unreadable"))
    .ok()?;
    let receipt: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    receipt
        .get("ipfs")?
        .get("peer_id")?
        .as_str()
        .filter(|peer_id| !peer_id.is_empty())
        .map(str::to_string)
}

/// What this Home's kubo repo says about the storage its card offers.
#[derive(Debug, PartialEq, Eq)]
enum RepoStorage {
    Offered(String),
    /// No repo: this Home never ran kubo.
    Missing,
    /// The repo is there but refused, which costs this Home its storage.
    Refused(String),
}

/// The kubo peer id a card can carry. A refused repo is told to the
/// operator; a missing one is not news.
fn ipfs_repo_peer_id(data_dir: &Path) -> Option<String> {
    match ipfs_repo_storage(data_dir) {
        RepoStorage::Offered(peer_id) => Some(peer_id),
        RepoStorage::Missing => {
            tracing::debug!("this Home has no kubo repo config");
            None
        }
        RepoStorage::Refused(reason) => {
            tracing::warn!(%reason, "this Home offers no storage");
            None
        }
    }
}

/// The kubo identity in this Home's repo. kubo derives it from the key pair
/// in the same file, so it holds whether or not the daemon is running.
fn ipfs_repo_storage(data_dir: &Path) -> RepoStorage {
    let path = data_dir.join(IPFS_REPO_CONFIG);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return RepoStorage::Missing,
        Err(error) => {
            return RepoStorage::Refused(format!("its kubo repo config is unreadable: {error}"))
        }
        Ok(_) => {}
    }
    let bytes = match read_owner_only_file(&path, MAX_IPFS_REPO_CONFIG_BYTES, "kubo repo config") {
        Ok(bytes) => bytes,
        Err(error) => {
            return RepoStorage::Refused(format!("its kubo repo config is refused: {error:#}"))
        }
    };
    let peer_id = match serde_json::from_slice::<KuboRepoConfig>(&bytes) {
        Ok(config) => config.identity.peer_id,
        Err(error) => {
            return RepoStorage::Refused(format!("its kubo repo config has no peer id: {error}"))
        }
    };
    if !is_exact_ipfs_peer_id(&peer_id) {
        return RepoStorage::Refused("its kubo repo peer id is not valid".to_string());
    }
    RepoStorage::Offered(peer_id)
}

/// The card a node's answer stands for, built with the ticket the owner
/// dialed. The card then goes through the same reading as a pasted one.
pub(crate) fn node_card_from_answer(
    answer: &serde_json::Value,
    ticket: &str,
) -> Result<String, NodeCardRefusal> {
    // The schema decides first, as for a card.
    let answer: NodeCardAnswer = match answer.get("schema").and_then(serde_json::Value::as_str) {
        Some(NODE_CARD_ANSWER_SCHEMA_V1) => {
            serde_json::from_value(answer.clone()).map_err(|_| NodeCardRefusal::NotACard)?
        }
        Some(schema)
            if schema
                .strip_prefix(NODE_CARD_ANSWER_SCHEMA_STEM)
                .is_some_and(is_newer_version) =>
        {
            return Err(NodeCardRefusal::NewerVersion)
        }
        _ => return Err(NodeCardRefusal::NotACard),
    };
    let node_bytes = base64::engine::general_purpose::STANDARD
        .decode(&answer.node)
        .map_err(|_| NodeCardRefusal::NotACard)?;
    encode_node_card(
        &node_bytes,
        ticket,
        &answer.provides,
        answer.ipfs_peer_id.as_deref(),
    )
}

/// One SHA-256 shown two ways: `short` to compare by eye, `full` to copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fingerprint {
    pub(crate) short: String,
    pub(crate) full: String,
}

impl Fingerprint {
    pub(crate) fn of(bytes: &[u8]) -> Self {
        Self::of_digest(&Sha256::digest(bytes).into())
    }

    pub(crate) fn of_digest(digest: &[u8; 32]) -> Self {
        Self {
            short: digest_fingerprint(digest),
            full: format!("sha256:{}", hex::encode(digest)),
        }
    }
}

/// SHA-256 as uppercase hex, shown as the first two and last two 4-character
/// groups: enough for two people to compare a card by eye.
pub(crate) fn fingerprint(bytes: &[u8]) -> String {
    digest_fingerprint(&Sha256::digest(bytes).into())
}

/// The same display for a digest the caller already holds, such as a pool's
/// `config_sha256`.
pub(crate) fn digest_fingerprint(digest: &[u8; 32]) -> String {
    let hex = hex::encode_upper(digest);
    let last = hex.len();
    format!(
        "{} {} \u{2026} {} {}",
        &hex[..4],
        &hex[4..8],
        &hex[last - 8..last - 4],
        &hex[last - 4..]
    )
}

fn card_body(text: &str) -> Result<&str, NodeCardRefusal> {
    if let Some(body) = text.strip_prefix(NODE_CARD_PREFIX) {
        return Ok(body);
    }
    match text
        .strip_prefix(NODE_CARD_PREFIX_STEM)
        .and_then(|rest| rest.split_once(':'))
    {
        Some((version, _)) if is_newer_version(version) => Err(NodeCardRefusal::NewerVersion),
        _ => Err(NodeCardRefusal::NotACard),
    }
}

fn card_v1(json: &[u8]) -> Result<NodeCardV1, NodeCardRefusal> {
    let value: serde_json::Value =
        serde_json::from_slice(json).map_err(|_| NodeCardRefusal::NotACard)?;
    // The schema decides first: a newer card may carry fields v1 refuses.
    match value.get("schema").and_then(serde_json::Value::as_str) {
        Some(NODE_CARD_SCHEMA_V1) => {
            serde_json::from_value(value).map_err(|_| NodeCardRefusal::NotACard)
        }
        Some(schema)
            if schema
                .strip_prefix(NODE_CARD_SCHEMA_STEM)
                .is_some_and(is_newer_version) =>
        {
            Err(NodeCardRefusal::NewerVersion)
        }
        _ => Err(NodeCardRefusal::NotACard),
    }
}

/// A decimal version above 1; one too large to parse is newer still.
fn is_newer_version(version: &str) -> bool {
    !version.is_empty()
        && version.bytes().all(|byte| byte.is_ascii_digit())
        && version.parse::<u64>().map_or(true, |number| number > 1)
}

/// Runs each descriptor check on its own so the refusal names the cause, then
/// the descriptor validator as the single authority.
fn validated_card_descriptor(
    bytes: &[u8],
) -> Result<ValidatedCustodyNodeDescriptor, NodeCardRefusal> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| NodeCardRefusal::Changed)?;
    match value.get("schema").and_then(serde_json::Value::as_str) {
        Some(CUSTODY_NODE_DESCRIPTOR_SCHEMA_V1) => {}
        Some(_) => return Err(NodeCardRefusal::Unsupported),
        None => return Err(NodeCardRefusal::Changed),
    }
    let descriptor: CustodyNodeDescriptorV1 =
        serde_json::from_value(value).map_err(|_| NodeCardRefusal::Changed)?;
    let canonical = serde_json::to_value(&descriptor).and_then(|value| serde_json::to_vec(&value));
    if canonical.ok().as_deref() != Some(bytes) {
        return Err(NodeCardRefusal::Changed);
    }
    validated_custody_node_label(&descriptor.operator, "operator")
        .and_then(|_| validated_custody_node_label(&descriptor.failure_domain, "failure domain"))
        .map_err(|_| NodeCardRefusal::BadLabels)?;
    match &descriptor.transport {
        CustodyNodeDescriptorTransportV1::Local => return Err(NodeCardRefusal::LocalCard),
        CustodyNodeDescriptorTransportV1::CarrierPeerDid { peer_did } => {
            decode_canonical_peer_did(peer_did).map_err(|_| NodeCardRefusal::Changed)?;
        }
    }
    validated_custody_node_descriptor(bytes, "node card").map_err(|error| {
        tracing::debug!(%error, "node card descriptor refused");
        NodeCardRefusal::Changed
    })
}

/// A card lists a non-empty, sorted, distinct subset of the known roles.
/// Which roles a pool needs is the pool's check, which names the node.
fn validated_provides(provides: Vec<String>) -> Result<Vec<String>, NodeCardRefusal> {
    let sorted_distinct = provides.windows(2).all(|pair| pair[0] < pair[1]);
    let known = provides
        .iter()
        .all(|target| NODE_CARD_PROVIDES.contains(&target.as_str()));
    if provides.is_empty() || !sorted_distinct || !known {
        return Err(NodeCardRefusal::NotACard);
    }
    Ok(provides)
}

fn validated_ipfs_peer_id(
    provides: &[String],
    ipfs_peer_id: Option<String>,
) -> Result<Option<String>, NodeCardRefusal> {
    let keeps_copies = provides.iter().any(|target| target == IPFS_PROVIDES);
    match (keeps_copies, ipfs_peer_id) {
        (false, None) => Ok(None),
        (true, Some(id)) if is_exact_ipfs_peer_id(&id) => Ok(Some(id)),
        _ => Err(NodeCardRefusal::StorageWithoutId),
    }
}

/// The peer registry's rule, without its trimming: a card carries the exact
/// id that registration records.
fn is_exact_ipfs_peer_id(id: &str) -> bool {
    normalize_ipfs_peer(&OperatorPeerIpfs {
        id: id.to_string(),
        addrs: Vec::new(),
    })
    .is_ok_and(|peer| peer.id == id)
}

/// The ticket must reach the device that the descriptor names as its Carrier
/// route, or the pool would dial a different Home.
fn ticket_reaches_descriptor_peer(
    ticket: &str,
    descriptor: &ValidatedCustodyNodeDescriptor,
) -> bool {
    let RuntimeCustodyRouteTransportConfig::CarrierPeerDid { peer_did } = &descriptor.transport
    else {
        return false;
    };
    let Ok(device_key) = crate::crypto::decode_did_key(peer_did) else {
        return false;
    };
    decode_ticket_endpoints(ticket)
        .iter()
        .any(|endpoint| endpoint.id.as_bytes() == device_key.as_bytes())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use elastos_protected_content_contracts::NodeCustodyPublicKeyV1;
    use x_wing::kem::Decapsulator as _;
    use x_wing::KeyExport as _;

    pub(crate) const TEST_IPFS_PEER_ID: &str =
        "12D3KooWGzBkSQVQ8yGgCcPRrMRwKcq5WmFjvYzR9qGpJn3cPWNx";

    fn random_bytes<const N: usize>() -> [u8; N] {
        let mut bytes = [0u8; N];
        getrandom::getrandom(&mut bytes).unwrap();
        bytes
    }

    fn fresh_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&random_bytes::<32>())
    }

    fn fixture_descriptor(transport: CustodyNodeDescriptorTransportV1) -> CustodyNodeDescriptorV1 {
        let custody_public_key = NodeCustodyPublicKeyV1::new(
            x_wing::DecapsulationKey::from(random_bytes::<{ x_wing::DECAPSULATION_KEY_SIZE }>())
                .encapsulation_key()
                .to_bytes()
                .into(),
        )
        .unwrap();
        CustodyNodeDescriptorV1 {
            schema: CUSTODY_NODE_DESCRIPTOR_SCHEMA_V1.to_string(),
            node_public_key_hex: format!(
                "0x{}",
                hex::encode(fresh_signing_key().verifying_key().to_bytes())
            ),
            node_custody_public_key_hex: format!(
                "0x{}",
                hex::encode(custody_public_key.as_bytes())
            ),
            operator: "Alice".to_string(),
            failure_domain: "Lisbon".to_string(),
            transport,
        }
    }

    fn canonical_bytes(value: &impl serde::Serialize) -> Vec<u8> {
        serde_json::to_vec(&serde_json::to_value(value).unwrap()).unwrap()
    }

    /// The ticket shape `deploy/custody-host/up.sh` `build_ticket` writes.
    pub(crate) fn ticket_for(key: &ed25519_dalek::VerifyingKey) -> String {
        ticket_at(key, "127.0.0.1:14431")
    }

    /// The same ticket shape, reaching `key` at `addr`.
    pub(crate) fn ticket_at(key: &ed25519_dalek::VerifyingKey, addr: &str) -> String {
        let ticket = serde_json::json!({
            "topic": null,
            "endpoints": [{
                "id": hex::encode(key.as_bytes()),
                "addrs": [{ "Ip": addr }],
            }],
        });
        data_encoding::BASE32_NOPAD
            .encode(&serde_json::to_vec(&ticket).unwrap())
            .to_ascii_lowercase()
    }

    struct Fixture {
        node_bytes: Vec<u8>,
        ticket: String,
        peer_did: String,
    }

    fn fixture() -> Fixture {
        let device_key = fresh_signing_key().verifying_key();
        let peer_did = crate::crypto::encode_did_key(&device_key).unwrap();
        let descriptor = fixture_descriptor(CustodyNodeDescriptorTransportV1::CarrierPeerDid {
            peer_did: peer_did.clone(),
        });
        Fixture {
            node_bytes: canonical_bytes(&descriptor),
            ticket: ticket_for(&device_key),
            peer_did,
        }
    }

    fn storage_provides() -> Vec<String> {
        ["custody", "chain", "ipfs"].map(String::from).to_vec()
    }

    fn fixture_card() -> (String, Fixture) {
        let fixture = fixture();
        let card = encode_node_card(
            &fixture.node_bytes,
            &fixture.ticket,
            &storage_provides(),
            Some(TEST_IPFS_PEER_ID),
        )
        .unwrap();
        (card, fixture)
    }

    /// A card for a fresh node that `device` reaches, with its own labels
    /// and roles; it carries a kubo peer id exactly when it provides ipfs.
    pub(crate) fn card_for_device(
        device: &ed25519_dalek::VerifyingKey,
        run_by: &str,
        location: &str,
        provides: &[&str],
    ) -> String {
        let mut descriptor = fixture_descriptor(CustodyNodeDescriptorTransportV1::CarrierPeerDid {
            peer_did: crate::crypto::encode_did_key(device).unwrap(),
        });
        descriptor.operator = run_by.to_string();
        descriptor.failure_domain = location.to_string();
        let provides: Vec<String> = provides.iter().map(|role| role.to_string()).collect();
        let ipfs_peer_id = provides
            .iter()
            .any(|role| role == IPFS_PROVIDES)
            .then_some(TEST_IPFS_PEER_ID);
        encode_node_card(
            &canonical_bytes(&descriptor),
            &ticket_for(device),
            &provides,
            ipfs_peer_id,
        )
        .unwrap()
    }

    /// A card for a fresh node on its own fresh device.
    pub(crate) fn labelled_card(run_by: &str, location: &str, provides: &[&str]) -> String {
        card_for_device(
            &fresh_signing_key().verifying_key(),
            run_by,
            location,
            provides,
        )
    }

    /// Descriptor bytes for a fresh node that `device` reaches over Carrier.
    pub(crate) fn carrier_descriptor_bytes(
        device: &ed25519_dalek::VerifyingKey,
        run_by: &str,
        location: &str,
    ) -> Vec<u8> {
        let mut descriptor = fixture_descriptor(CustodyNodeDescriptorTransportV1::CarrierPeerDid {
            peer_did: crate::crypto::encode_did_key(device).unwrap(),
        });
        descriptor.operator = run_by.to_string();
        descriptor.failure_domain = location.to_string();
        canonical_bytes(&descriptor)
    }

    /// Descriptor bytes for a fresh node on the local route.
    pub(crate) fn local_descriptor_bytes(run_by: &str, location: &str) -> Vec<u8> {
        let mut descriptor = fixture_descriptor(CustodyNodeDescriptorTransportV1::Local);
        descriptor.operator = run_by.to_string();
        descriptor.failure_domain = location.to_string();
        canonical_bytes(&descriptor)
    }

    /// Card text built without the encoder's checks, for refusal cases.
    fn raw_card_from_json(json: &serde_json::Value) -> String {
        format!(
            "{NODE_CARD_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(json).unwrap())
        )
    }

    fn raw_card(
        node_bytes: &[u8],
        ticket: &str,
        provides: &[&str],
        ipfs_peer_id: Option<&str>,
    ) -> String {
        let mut json = serde_json::json!({
            "schema": NODE_CARD_SCHEMA_V1,
            "node": base64::engine::general_purpose::STANDARD.encode(node_bytes),
            "ticket": ticket,
            "provides": provides,
        });
        if let Some(id) = ipfs_peer_id {
            json["ipfs_peer_id"] = serde_json::Value::from(id);
        }
        raw_card_from_json(&json)
    }

    fn refusal(text: &str) -> NodeCardRefusal {
        match parse_node_card(text) {
            Ok(_) => panic!("card must be refused"),
            Err(refusal) => refusal,
        }
    }

    #[test]
    fn card_round_trips() {
        let (card, fixture) = fixture_card();
        assert!(card.starts_with(NODE_CARD_PREFIX));

        let parsed = parse_node_card(&card).unwrap();
        assert_eq!(parsed.node_bytes, fixture.node_bytes);
        assert_eq!(parsed.ticket, fixture.ticket);
        assert_eq!(parsed.provides, ["chain", "custody", "ipfs"]);
        assert_eq!(parsed.ipfs_peer_id.as_deref(), Some(TEST_IPFS_PEER_ID));
        assert_eq!(parsed.fingerprint, fingerprint(&fixture.node_bytes));
        assert_eq!(parsed.descriptor.operator, "Alice");
        assert_eq!(parsed.descriptor.failure_domain, "Lisbon");
        match &parsed.descriptor.transport {
            crate::protected_content_runtime::RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                peer_did,
            } => assert_eq!(peer_did, &fixture.peer_did),
            crate::protected_content_runtime::RuntimeCustodyRouteTransportConfig::Local => {
                panic!("fixture card routes over Carrier")
            }
        }

        let custody_only = encode_node_card(
            &fixture.node_bytes,
            &fixture.ticket,
            &["chain".to_string(), "custody".to_string()],
            None,
        )
        .unwrap();
        let parsed = parse_node_card(&custody_only).unwrap();
        assert_eq!(parsed.provides, ["chain", "custody"]);
        assert_eq!(parsed.ipfs_peer_id, None);

        // Roles are the pool's check, which names the node; the card accepts
        // any non-empty, sorted, distinct subset.
        for (provides, id) in [
            (&["chain"][..], None),
            (&["ipfs"][..], Some(TEST_IPFS_PEER_ID)),
            (&["chain", "ipfs"][..], Some(TEST_IPFS_PEER_ID)),
        ] {
            let card = raw_card(&fixture.node_bytes, &fixture.ticket, provides, id);
            let parsed = parse_node_card(&card).unwrap_or_else(|refusal| {
                panic!("{provides:?} must be accepted, got {}", refusal.code())
            });
            assert_eq!(parsed.provides, provides);
            assert_eq!(parsed.ipfs_peer_id.as_deref(), id);
        }
    }

    #[test]
    fn card_parse_ignores_wrapping_whitespace() {
        let (card, fixture) = fixture_card();
        let wrapped = card
            .as_bytes()
            .chunks(76)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n");
        let pasted = format!("  \n\t{wrapped}\n  ");

        let parsed = parse_node_card(&pasted).unwrap();
        assert_eq!(parsed.node_bytes, fixture.node_bytes);
    }

    #[test]
    fn card_refuses_not_a_card() {
        let (card, _) = fixture_card();
        let body = card.strip_prefix(NODE_CARD_PREFIX).unwrap();

        for text in [
            String::new(),
            body.to_string(),
            format!("elastos-node-card:{body}"),
            format!("{NODE_CARD_PREFIX}not*base64url"),
            format!(
                "{NODE_CARD_PREFIX}{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{not json")
            ),
            raw_card_from_json(&serde_json::json!({ "schema": "something-else/v1" })),
        ] {
            assert_eq!(refusal(&text), NodeCardRefusal::NotACard, "{text}");
        }
        assert_eq!(NodeCardRefusal::NotACard.code(), "not_a_card");
    }

    #[test]
    fn card_refuses_oversized_text_as_not_a_card() {
        let (card, _) = fixture_card();
        let oversized = format!("{card}{}", " ".repeat(MAX_NODE_CARD_TEXT_BYTES));
        assert_eq!(refusal(&oversized), NodeCardRefusal::NotACard);
    }

    #[test]
    fn card_refuses_newer_version() {
        let (card, _) = fixture_card();
        let body = card.strip_prefix(NODE_CARD_PREFIX).unwrap();
        assert_eq!(
            refusal(&format!("elastos-node-card:v2:{body}")),
            NodeCardRefusal::NewerVersion
        );

        let newer_schema = raw_card_from_json(&serde_json::json!({
            "schema": "elastos.protected-content.custody-node-card/v2",
            "node": "",
            "a_field_v1_does_not_know": true,
        }));
        assert_eq!(refusal(&newer_schema), NodeCardRefusal::NewerVersion);
        assert_eq!(NodeCardRefusal::NewerVersion.code(), "newer_version");
    }

    #[test]
    fn card_refuses_changed() {
        let fixture = fixture();
        let value: serde_json::Value = serde_json::from_slice(&fixture.node_bytes).unwrap();
        let pretty = serde_json::to_vec_pretty(&value).unwrap();
        let card = raw_card(&pretty, &fixture.ticket, &["chain", "custody"], None);
        assert_eq!(refusal(&card), NodeCardRefusal::Changed);

        let mut bad_key = value.clone();
        bad_key["node_public_key_hex"] = serde_json::Value::from("0x00");
        let card = raw_card(
            &canonical_bytes(&bad_key),
            &fixture.ticket,
            &["chain", "custody"],
            None,
        );
        assert_eq!(refusal(&card), NodeCardRefusal::Changed);

        let mut bad_did = value;
        bad_did["transport"]["peer_did"] = serde_json::Value::from("did:key:z6Mnot-a-key");
        let card = raw_card(
            &canonical_bytes(&bad_did),
            &fixture.ticket,
            &["chain", "custody"],
            None,
        );
        assert_eq!(refusal(&card), NodeCardRefusal::Changed);
        assert_eq!(NodeCardRefusal::Changed.code(), "changed");
    }

    #[test]
    fn card_refuses_unsupported() {
        let fixture = fixture();
        let mut value: serde_json::Value = serde_json::from_slice(&fixture.node_bytes).unwrap();
        value["schema"] =
            serde_json::Value::from("elastos.protected-content.custody-node-descriptor/v2");
        let card = raw_card(
            &canonical_bytes(&value),
            &fixture.ticket,
            &["chain", "custody"],
            None,
        );
        assert_eq!(refusal(&card), NodeCardRefusal::Unsupported);
        assert_eq!(NodeCardRefusal::Unsupported.code(), "unsupported");
    }

    #[test]
    fn card_refuses_ticket_mismatch() {
        let fixture = fixture();
        let other_ticket = ticket_for(&fresh_signing_key().verifying_key());
        for ticket in [other_ticket.as_str(), "", "not a ticket"] {
            let card = raw_card(&fixture.node_bytes, ticket, &["chain", "custody"], None);
            assert_eq!(refusal(&card), NodeCardRefusal::TicketMismatch, "{ticket}");
        }
        assert!(matches!(
            encode_node_card(
                &fixture.node_bytes,
                &other_ticket,
                &["custody".to_string()],
                None
            ),
            Err(NodeCardRefusal::TicketMismatch)
        ));
        assert_eq!(NodeCardRefusal::TicketMismatch.code(), "ticket_mismatch");
    }

    #[test]
    fn card_refuses_storage_without_id() {
        let fixture = fixture();
        for (provides, id) in [
            (&["chain", "custody", "ipfs"][..], None),
            (&["chain", "custody", "ipfs"][..], Some("")),
            (
                &["chain", "custody", "ipfs"][..],
                Some("/ip4/10.0.0.1/tcp/4001"),
            ),
            (&["chain", "custody", "ipfs"][..], Some(" 12D3KooW ")),
            (&["chain", "custody"][..], Some(TEST_IPFS_PEER_ID)),
        ] {
            let card = raw_card(&fixture.node_bytes, &fixture.ticket, provides, id);
            assert_eq!(
                refusal(&card),
                NodeCardRefusal::StorageWithoutId,
                "{provides:?} {id:?}"
            );
        }
        assert_eq!(
            NodeCardRefusal::StorageWithoutId.code(),
            "storage_without_id"
        );
    }

    #[test]
    fn card_refuses_bad_labels() {
        let fixture = fixture();
        let value: serde_json::Value = serde_json::from_slice(&fixture.node_bytes).unwrap();
        for (field, label) in [
            ("operator", String::new()),
            ("operator", " Alice".to_string()),
            ("failure_domain", "x".repeat(65)),
        ] {
            let mut bad = value.clone();
            bad[field] = serde_json::Value::from(label.clone());
            let card = raw_card(
                &canonical_bytes(&bad),
                &fixture.ticket,
                &["chain", "custody"],
                None,
            );
            assert_eq!(
                refusal(&card),
                NodeCardRefusal::BadLabels,
                "{field}={label:?}"
            );
        }
        assert_eq!(NodeCardRefusal::BadLabels.code(), "bad_labels");
    }

    #[test]
    fn card_refuses_local_card() {
        let fixture = fixture();
        let local = canonical_bytes(&fixture_descriptor(CustodyNodeDescriptorTransportV1::Local));
        let card = raw_card(&local, &fixture.ticket, &["chain", "custody"], None);
        assert_eq!(refusal(&card), NodeCardRefusal::LocalCard);
        assert_eq!(NodeCardRefusal::LocalCard.code(), "local_card");
    }

    #[test]
    fn card_refuses_unknown_or_unsorted_provides_as_not_a_card() {
        let fixture = fixture();
        for provides in [
            &[][..],
            &["custody", "chain"][..],
            &["chain", "chain", "custody"][..],
            &["chain", "custody", "storage"][..],
        ] {
            let card = raw_card(&fixture.node_bytes, &fixture.ticket, provides, None);
            assert_eq!(refusal(&card), NodeCardRefusal::NotACard, "{provides:?}");
        }
    }

    /// A Home holding its node descriptor, as provisioning leaves it.
    fn node_home() -> (tempfile::TempDir, std::path::PathBuf, Fixture) {
        use crate::protected_content_config::tests::owner_only_dir;

        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        owner_only_dir(&data_dir);
        owner_only_dir(&crate::protected_content_runtime::protected_content_root(
            &data_dir,
        ));
        let fixture = fixture();
        crate::collaboration_config::create_owner_only_file(
            &crate::protected_content_config::custody_node_descriptor_path(&data_dir),
            &fixture.node_bytes,
            "test custody node details",
        )
        .unwrap();
        (dir, data_dir, fixture)
    }

    /// Owner-only, as kubo writes the file that holds its private key.
    fn write_owner_only(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt;

        let parent = path.parent().unwrap();
        if !parent.exists() {
            crate::protected_content_config::tests::owner_only_dir(parent);
        }
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn write_ipfs_repo_config(data_dir: &Path, config: &serde_json::Value) {
        write_owner_only(
            &data_dir.join("ipfs-repo/config"),
            &serde_json::to_vec(config).unwrap(),
        );
    }

    fn kubo_config(peer_id: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "Identity": { "PeerID": peer_id, "PrivKey": "CAESQPrivateKeyMaterial" },
            "Addresses": { "Swarm": ["/ip4/0.0.0.0/tcp/4001"] },
        })
    }

    fn answered(data_dir: &Path) -> (Vec<String>, Option<String>) {
        let answer = local_node_card_answer(data_dir, "inactive")
            .unwrap()
            .unwrap();
        (answer.provides, answer.ipfs_peer_id)
    }

    #[test]
    fn full_home_card_answer_offers_storage_from_its_ipfs_repo() {
        const RECEIPT_PEER_ID: &str = "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N";

        let (_dir, data_dir, fixture) = node_home();
        write_ipfs_repo_config(&data_dir, &kubo_config(TEST_IPFS_PEER_ID.into()));
        let answer = local_node_card_answer(&data_dir, "inactive")
            .unwrap()
            .unwrap();
        assert_eq!(answer.provides, ["chain", "custody", "ipfs"]);
        assert_eq!(answer.ipfs_peer_id.as_deref(), Some(TEST_IPFS_PEER_ID));
        // The owner reads the answer as a storage card for this node.
        let card = node_card_from_answer(&serde_json::to_value(&answer).unwrap(), &fixture.ticket)
            .unwrap();
        let card = parse_node_card(&card).unwrap();
        assert_eq!(card.node_bytes, fixture.node_bytes);
        assert_eq!(card.ipfs_peer_id.as_deref(), Some(TEST_IPFS_PEER_ID));

        // A provider host's receipt keeps priority over the repo.
        let receipt = data_dir.join(PROVIDER_HOST_READY_RECEIPT);
        write_owner_only(
            &receipt,
            &serde_json::to_vec(&serde_json::json!({
                "ipfs": { "peer_id": RECEIPT_PEER_ID, "swarm_addrs": [] },
            }))
            .unwrap(),
        );
        assert_eq!(
            answered(&data_dir),
            (storage_provides_sorted(), Some(RECEIPT_PEER_ID.to_string()))
        );
        // A provider host without an ipfs plane serves no copies, whatever
        // repo sits beside it.
        write_owner_only(&receipt, br#"{"providers":["custody-provider"]}"#);
        assert_eq!(answered(&data_dir), (custody_only(), None));
    }

    #[test]
    fn card_answer_without_a_valid_repo_peer_id_offers_custody_only() {
        let (_dir, data_dir, _) = node_home();
        // No repo at all.
        assert_eq!(answered(&data_dir), (custody_only(), None));

        let path = data_dir.join("ipfs-repo/config");
        let refused: [Vec<u8>; 7] = [
            b"not json".to_vec(),
            b"{}".to_vec(),
            br#"{"Identity":{}}"#.to_vec(),
            serde_json::to_vec(&kubo_config("".into())).unwrap(),
            serde_json::to_vec(&kubo_config(7.into())).unwrap(),
            serde_json::to_vec(&kubo_config("/ip4/10.0.0.2/tcp/4001".into())).unwrap(),
            serde_json::to_vec(&kubo_config(format!(" {TEST_IPFS_PEER_ID} ").into())).unwrap(),
        ];
        for config in refused {
            write_owner_only(&path, &config);
            assert_eq!(
                answered(&data_dir),
                (custody_only(), None),
                "{}",
                String::from_utf8_lossy(&config)
            );
        }
    }

    /// A repo that is there but refused is what the operator is warned of; a
    /// Home without a repo is not news.
    #[test]
    fn repo_storage_tells_a_missing_repo_from_a_refused_one() {
        use std::os::unix::fs::PermissionsExt;

        let (_dir, data_dir, _) = node_home();
        assert_eq!(ipfs_repo_storage(&data_dir), RepoStorage::Missing);

        let path = data_dir.join("ipfs-repo/config");
        write_ipfs_repo_config(&data_dir, &kubo_config(TEST_IPFS_PEER_ID.into()));
        assert_eq!(
            ipfs_repo_storage(&data_dir),
            RepoStorage::Offered(TEST_IPFS_PEER_ID.to_string())
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let refused: [Vec<u8>; 3] = [
            serde_json::to_vec(&kubo_config(TEST_IPFS_PEER_ID.into())).unwrap(),
            b"not json".to_vec(),
            serde_json::to_vec(&kubo_config("a/b".into())).unwrap(),
        ];
        for (index, config) in refused.into_iter().enumerate() {
            // The first stays world-readable, the rest are owner-only again.
            if index > 0 {
                write_owner_only(&path, &config);
            }
            match ipfs_repo_storage(&data_dir) {
                RepoStorage::Refused(reason) => {
                    assert!(!reason.contains("PrivateKeyMaterial"), "{reason}")
                }
                other => panic!("{}: {other:?}", String::from_utf8_lossy(&config)),
            }
        }
    }

    fn storage_provides_sorted() -> Vec<String> {
        ["chain", "custody", "ipfs"].map(String::from).to_vec()
    }

    fn custody_only() -> Vec<String> {
        ["chain", "custody"].map(String::from).to_vec()
    }

    #[test]
    fn fingerprint_shows_first_and_last_two_groups() {
        let shown = fingerprint(b"node descriptor bytes");
        let groups: Vec<&str> = shown.split(' ').collect();
        assert_eq!(groups.len(), 5, "{shown}");
        assert_eq!(groups[2], "\u{2026}", "{shown}");
        for group in [groups[0], groups[1], groups[3], groups[4]] {
            assert_eq!(group.len(), 4, "{shown}");
            assert!(
                group
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'F')),
                "{shown}"
            );
        }

        let full = hex::encode_upper(sha2::Sha256::digest(b"node descriptor bytes"));
        assert!(shown.starts_with(&format!("{} {}", &full[0..4], &full[4..8])));
        assert!(shown.ends_with(&format!("{} {}", &full[56..60], &full[60..64])));
        // Both forms come from the one digest; the full one is for copying.
        let print = Fingerprint::of(b"node descriptor bytes");
        assert_eq!(print.short, shown);
        assert_eq!(print.full, format!("sha256:{}", full.to_ascii_lowercase()));
    }
}
