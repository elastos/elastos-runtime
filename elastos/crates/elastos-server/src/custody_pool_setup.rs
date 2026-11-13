//! The Custody app's pool setup: what a pool owner reads, checks, signs and
//! installs, over the same Runtime functions the `protected-content-config`
//! and `node peer add` commands use. Gateway routes adapt it one to one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use elastos_runtime::provider::ProviderRegistry;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::carrier::{carrier_connect_ticket, decode_ticket_endpoints};
use crate::collaboration_config::{create_owner_only_file, read_owner_only_file};
use crate::collaboration_profile_authority::load_profile_authority;
use crate::custody_consent::CustodyWriteGuard;
use crate::custody_node_card::{
    fingerprint, node_card_from_answer, parse_node_card, Fingerprint, LocalNodeCard, NodeCard,
};
use crate::operator_control::{
    last_accepted_request_at, load_operator_control, request_remote_custody_node_card,
    request_remote_custody_node_card_within, upsert_peer, OperatorAnswer, OperatorPeer,
    OperatorPeerIpfs, CUSTODY_NODE_HAS_NO_CARD, OPERATOR_PROVIDES_IPFS,
};
use crate::protected_content_config::{
    create_policy_authority_key, custody_node_descriptor_path, distinct_custody_node_descriptors,
    ensure_owner_only_dir, install_custody_composition, policy_authority_public_key,
    provision_custody_node_at, runtime_issuer_hex, store_custody_node_descriptor_at,
    validated_custody_node_descriptor, validated_custody_node_label,
    verify_installed_custody_composition, ValidatedCustodyNodeDescriptor,
    CUSTODY_THRESHOLD_REQUIRED, CUSTODY_THRESHOLD_TOTAL, MAX_CUSTODY_COMPOSITION_FILE_BYTES,
    MAX_CUSTODY_NODE_DESCRIPTOR_BYTES,
};
use crate::protected_content_runtime::{
    load_runtime_custody_composition, load_runtime_protected_content_chain_provider_config,
    protected_content_root, register_custody_provider, runtime_custody_composition_config_path,
    RuntimeCustodyCompositionConfigFile, RuntimeCustodyRouteTransportConfig, CUSTODY_PROVIDER_ID,
    PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET,
};

const POLICY_AUTHORITY_KEY_FILE: &str = "policy-authority.key";
const LOCAL_NODE_FILE: &str = "custody-local-node.descriptor.json";
const INCLUDE_MARKER_FILE: &str = "custody-local-node.including";
const POOL_MEMBERS_FILE: &str = "custody-pool-members.json";
const POOL_MEMBERS_SCHEMA_V1: &str = "elastos.protected-content.custody-pool-members/v1";
/// Room for every member's card at its parser cap, plus the record around it.
const MAX_POOL_MEMBERS_FILE_BYTES: usize = 128 * 1024;
const CUSTODY_ROLE: &str = "custody";
const CHAIN_ROLE: &str = "chain";
/// Every pool node serves these; this Home's node serves both.
const REQUIRED_ROLES: [&str; 2] = [CUSTODY_ROLE, CHAIN_ROLE];
const SECONDS_PER_DAY: u64 = 86_400;
/// The terms a pool owner can sign for: six months, one year and two years.
pub(crate) const POOL_TERM_DAYS: [u16; 3] = [182, 365, 730];
/// A stopped member must not hold the health check: its dial gives up soon,
/// and the whole probe within a few seconds.
const HEALTH_PROBE_CONNECT_TIMEOUT_SECS: u64 = 3;
const HEALTH_PROBE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// A refusal the Custody app shows by its stable `code`. `detail` carries the
/// Runtime's own reason, for display and logs only.
#[derive(Debug)]
pub(crate) struct CustodyRefusal {
    code: &'static str,
    detail: Option<String>,
}

impl CustodyRefusal {
    pub(crate) fn new(code: &'static str) -> Self {
        Self { code, detail: None }
    }

    pub(crate) fn with_detail(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: Some(detail.into()),
        }
    }

    /// A refusal carrying a Runtime error's full reason chain.
    pub(crate) fn from_error(code: &'static str, error: &anyhow::Error) -> Self {
        Self::with_detail(code, format!("{error:#}"))
    }

    pub(crate) fn code(&self) -> &'static str {
        self.code
    }

    pub(crate) fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

impl std::fmt::Display for CustodyRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.detail {
            Some(detail) => write!(formatter, "{}: {detail}", self.code),
            None => formatter.write_str(self.code),
        }
    }
}

impl std::error::Error for CustodyRefusal {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct ThresholdView {
    pub(crate) required: u8,
    pub(crate) total: u8,
}

#[derive(Debug, Serialize)]
pub(crate) struct CustodySummary {
    pub(crate) threshold: ThresholdView,
    /// The terms Install accepts, so the app offers exactly these.
    pub(crate) term_presets_days: &'static [u16],
    pub(crate) runtime_issuer: Option<String>,
    pub(crate) signing_key: SigningKeyView,
    pub(crate) chain: ChainView,
    pub(crate) local_node: LocalNodeSummary,
    /// A pool file is present, even when the loader refuses it, so the app
    /// never offers to form a second pool.
    pub(crate) pool_installed: bool,
    pub(crate) pool: Option<PoolView>,
    /// Why an installed pool cannot be read, such as a term that has ended.
    pub(crate) pool_problem: Option<PoolProblemView>,
    /// Plan B T2.3: every pool this Home serves a custody node for.
    pub(crate) serving: Vec<ServingView>,
    /// The served pools from before the served-pools map with no matching
    /// consent, by pool fingerprint; left on disk untouched (user decision
    /// 2026-11-12 10:35).
    pub(crate) serving_needs_attention: Vec<String>,
    /// This Home's own pool, when it has an own root (S2-R3-F1): Hosting
    /// asks to confirm its publisher while none is kept.
    pub(crate) own_pool: Option<OwnPoolView>,
    /// The display name the signed-in admin shares with connected people,
    /// from their signed Profile.
    pub(crate) local_profile_name: Option<String>,
    /// The requests this Home sent contacts to be its custody nodes, newest
    /// first.
    pub(crate) node_requests: Vec<crate::custody_owner_requests::NodeRequestOutView>,
    /// Who of the installed pool's members was told they are in it.
    pub(crate) pool_notices: Option<crate::custody_pool_notices::PoolNoticesView>,
    /// Plan B T3.3 (E4): the installed pool's address as text, to share with
    /// buyers' Homes.
    pub(crate) pool_address: Option<String>,
}

/// Plan B T2.3 (S2-R3-F1): this Home's own pool, as Hosting shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct OwnPoolView {
    /// The 64 hex digits, as the Confirm publisher route's `:pool` names it.
    pub(crate) pool_fingerprint: String,
    pub(crate) publisher_confirmed: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct PoolProblemView {
    pub(crate) code: &'static str,
    pub(crate) detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SigningKeyView {
    pub(crate) present: bool,
    pub(crate) fingerprint: Option<String>,
    /// The whole digest `fingerprint` shows, `sha256:` and 64 lowercase hex.
    pub(crate) fingerprint_full: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ChainView {
    pub(crate) ready: bool,
    pub(crate) network: Option<String>,
    pub(crate) proof_sources: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct LocalNodeSummary {
    pub(crate) provisioned: bool,
    pub(crate) run_by: Option<String>,
    pub(crate) location: Option<String>,
    pub(crate) fingerprint: Option<String>,
    /// The whole digest `fingerprint` shows, `sha256:` and 64 lowercase hex.
    pub(crate) fingerprint_full: Option<String>,
    /// Its custody provider is serving in the running Runtime; a provisioned
    /// node that is not starts on the next restart.
    pub(crate) running: bool,
    /// The Carrier connect ticket a pool owner fetches this Home's node card
    /// with; only on a Home provisioned as a Carrier-routed custody node.
    pub(crate) address: Option<String>,
}

/// The custody node this Home runs for a pool owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ServingView {
    /// The Home whose pool this node serves, the only one it answers.
    pub(crate) owner_did: Option<String>,
    /// The owner's People name. Always null for now: no contact lookup reads
    /// outside a signed-in principal.
    pub(crate) owner_name: Option<String>,
    pub(crate) run_by: String,
    pub(crate) location: String,
    pub(crate) provides: Vec<String>,
    pub(crate) fingerprint: String,
    /// The whole digest `fingerprint` shows, `sha256:` and 64 lowercase hex.
    pub(crate) fingerprint_full: String,
    pub(crate) provider_running: bool,
    /// The node serves its owner only after this Home restarts.
    pub(crate) needs_restart: bool,
    /// Unix seconds of the owner's newest accepted request to this node.
    pub(crate) last_owner_contact: Option<u64>,
    /// The signed pool this node is in, once its owner told it.
    pub(crate) pool: Option<crate::custody_consent::ServedPoolView>,
    /// Plan B T2.3: the served pool's fingerprint hex, which Stop serving
    /// names (`:pool`).
    pub(crate) pool_fingerprint: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct LocalNodeView {
    #[serde(flatten)]
    pub(crate) node: LocalNodeSummary,
    pub(crate) needs_restart: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub(crate) enum CardView {
    Read {
        run_by: String,
        location: String,
        home_id: String,
        provides: Vec<String>,
        fingerprint: String,
        /// The whole digest `fingerprint` shows.
        fingerprint_full: String,
        local: bool,
    },
    Refused {
        refused: &'static str,
    },
}

/// A card fetched from its node over Carrier, or the refusal code the Custody
/// app shows for it.
#[derive(Debug)]
pub(crate) enum FetchedCard {
    Card {
        card: String,
        view: CardView,
    },
    Refused {
        refused: &'static str,
        detail: Option<String>,
    },
}

/// One share slot: a pasted card, or this Home's own node.
#[derive(Debug, Clone)]
pub(crate) enum CardInput {
    Remote { text: String },
    ThisHome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CheckOutcome {
    Pass,
    Fail,
    Advice,
}

/// One check. `names` are Run by names, except where a check says otherwise:
/// `card` and `duplicate` name 1-based slot numbers, and `run_by` names the
/// nodes' Locations, since their Run by is the shared value in `detail`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CheckResult {
    pub(crate) id: &'static str,
    pub(crate) result: CheckOutcome,
    pub(crate) names: Vec<String>,
    pub(crate) detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct InstallResult {
    pub(crate) fingerprint: String,
    /// The whole digest `fingerprint` shows, `sha256:` and 64 lowercase hex.
    pub(crate) fingerprint_full: String,
    pub(crate) verified: bool,
    pub(crate) registered: Vec<RegistrationView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RegistrationView {
    pub(crate) share: u8,
    pub(crate) ok: bool,
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyView {
    pub(crate) verified: bool,
    pub(crate) fingerprint: String,
    /// The whole digest `fingerprint` shows, `sha256:` and 64 lowercase hex.
    pub(crate) fingerprint_full: String,
    pub(crate) checked_at: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct PoolView {
    pub(crate) members: Vec<PoolMemberView>,
    pub(crate) term: TermView,
    pub(crate) threshold: ThresholdView,
    pub(crate) fingerprint: String,
    /// The whole digest `fingerprint` shows, `sha256:` and 64 lowercase hex.
    pub(crate) fingerprint_full: String,
    /// The members' cards were kept at install, so Register again can work.
    /// A pool installed from the terminal has none.
    pub(crate) cards_kept: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PoolMemberView {
    pub(crate) share: u8,
    pub(crate) run_by: Option<String>,
    pub(crate) location: Option<String>,
    pub(crate) home_id: Option<String>,
    pub(crate) provides: Vec<String>,
    pub(crate) this_home: bool,
    pub(crate) registered: bool,
}

/// Unix seconds; `days` is the term the pool was signed for.
#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct TermView {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) days: u64,
}

/// The pool's health from how many members are online, against its threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PoolHealth {
    Healthy,
    AtRisk,
    Down,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MemberState {
    Online,
    DifferentNode,
    NotAnswering,
    Refused,
}

#[derive(Debug, Serialize)]
pub(crate) struct PoolHealthView {
    pub(crate) status: PoolHealth,
    pub(crate) online: u8,
    pub(crate) required: u8,
    pub(crate) total: u8,
    pub(crate) checked_at: u64,
    pub(crate) members: Vec<MemberHealthView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct MemberHealthView {
    pub(crate) share: u8,
    pub(crate) state: MemberState,
    /// The node's signed refusal, or why the probe got no usable answer.
    pub(crate) detail: Option<String>,
}

/// What the owner's cards said about each member, kept beside the pool so the
/// Active view and Register again work without the cards. Bound to one pool
/// file by its `config_sha256`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolMembersRecordV1 {
    schema: String,
    config_sha256: String,
    members: Vec<PoolMemberRecordV1>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolMemberRecordV1 {
    share: u8,
    node_public_key_hex: String,
    run_by: String,
    location: String,
    /// The member's Carrier peer DID; absent for this Home's local route.
    home_id: Option<String>,
    provides: Vec<String>,
    ipfs_peer_id: Option<String>,
    fingerprint: String,
    /// The card text without whitespace; absent for this Home.
    card: Option<String>,
}

/// A slot that passed card reading, ready for the pool rules.
struct SlotMember {
    slot: usize,
    node_bytes: Vec<u8>,
    descriptor: ValidatedCustodyNodeDescriptor,
    provides: Vec<String>,
    ipfs_peer_id: Option<String>,
    fingerprint: String,
    card: Option<String>,
}

impl SlotMember {
    fn run_by(&self) -> String {
        self.descriptor.operator.clone()
    }

    fn is_local(&self) -> bool {
        matches!(
            self.descriptor.transport,
            RuntimeCustodyRouteTransportConfig::Local
        )
    }

    fn peer_did(&self) -> Option<String> {
        peer_did(&self.descriptor.transport)
    }
}

/// This Home's node, as Include this Home stored it.
struct LocalNode {
    bytes: Vec<u8>,
    descriptor: ValidatedCustodyNodeDescriptor,
}

/// The node this Home runs for a pool owner, as provisioning stored it.
struct ServedNode {
    root_path: String,
    fingerprint_full: String,
    card: LocalNodeCard,
    descriptor: ValidatedCustodyNodeDescriptor,
}

/// The identities a pasted card must not repeat.
struct OwnHome {
    did: Option<String>,
    local_node_bytes: Option<Vec<u8>>,
}

/// The installed pool, as the Runtime loader accepted it.
struct InstalledPool {
    config_sha256: String,
    fingerprint: Fingerprint,
    threshold: ThresholdView,
    term: TermView,
    nodes: Vec<InstalledNode>,
}

struct InstalledNode {
    share: u8,
    node_public_key_hex: String,
    peer_did: Option<String>,
}

pub(crate) fn policy_authority_key_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join(POLICY_AUTHORITY_KEY_FILE)
}

pub(crate) fn local_node_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join(LOCAL_NODE_FILE)
}

fn pool_members_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join(POOL_MEMBERS_FILE)
}

/// `registry` is the running Runtime's, to tell whether this Home's node is
/// serving; without one it reads as not running.
/// `carrier` is the running Carrier node, which knows this Home's address;
/// `principal_id` is the signed-in admin, whose Profile names this Home.
pub(crate) async fn summary(
    data_dir: &Path,
    registry: Option<&Arc<ProviderRegistry>>,
    carrier: Option<&iroh::Endpoint>,
    principal_id: Option<&str>,
) -> CustodySummary {
    let pool_installed = pool_installed(data_dir).unwrap_or_else(|error| {
        // Something is there that cannot be inspected; never offer Prepare over it.
        tracing::warn!(error = %format!("{error:#}"), "custody pool file is unavailable");
        true
    });
    let (pool, pool_problem) = match read_pool(data_dir) {
        Ok(pool) => (pool, None),
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "installed custody pool is unreadable");
            let problem = match error.downcast_ref::<CustodyRefusal>() {
                Some(refusal) => PoolProblemView {
                    code: refusal.code(),
                    detail: refusal.detail().map(str::to_string),
                },
                None => PoolProblemView {
                    code: "verify_failed",
                    detail: Some(format!("{error:#}")),
                },
            };
            (None, Some(problem))
        }
    };
    // A node without its keys reads as none, so Include sets it up again. A
    // root that cannot be read now still shows the node: a glitch must not
    // invite a rebuild.
    let local_node = read_local_node_or_warn(data_dir)
        .filter(|node| !matches!(local_node_keyed(data_dir, node), Keyed::No));
    let provider_ready = custody_provider_ready(registry).await;
    // Plan B T2.3: every served pool.
    let nodes = served_nodes_or_warn(data_dir);
    // This Home's node address, from the first served node's route.
    let address = nodes.first().and_then(|node| node_address(node, carrier));
    let mut serving = Vec::new();
    for node in nodes {
        let loaded =
            crate::protected_content_runtime::custody_root_loaded(data_dir, &node.root_path).await;
        serving.push(serving_view(data_dir, node, provider_ready, loaded));
    }
    let served_pools = crate::custody_consent::served_pools(data_dir).ok();
    let serving_needs_attention = served_pools
        .as_ref()
        .map(|pools| pools.v1_needs_attention.clone())
        .unwrap_or_default();
    let own_pool = own_pool_view(data_dir, served_pools.as_ref());
    let mut local_node = local_node_summary(local_node.as_ref(), provider_ready);
    local_node.address = address;
    let pool_notices = pool.as_ref().and_then(|pool| {
        crate::custody_pool_notices::pool_notices_view(data_dir, &pool.fingerprint_full)
            .unwrap_or_else(|error| {
                tracing::warn!(
                    error = %format!("{error:#}"),
                    "custody pool notices are unreadable"
                );
                None
            })
    });
    let pool_address = pool
        .is_some()
        .then(|| crate::custody_pool_descriptor::owner_pool_address(data_dir))
        .flatten();
    CustodySummary {
        threshold: runtime_threshold(),
        term_presets_days: &POOL_TERM_DAYS,
        runtime_issuer: runtime_issuer_hex(data_dir)
            .inspect_err(|error| tracing::debug!(%error, "custody summary has no Runtime issuer"))
            .ok(),
        signing_key: signing_key_view(data_dir),
        chain: chain_view(data_dir),
        local_node,
        pool_installed,
        pool,
        pool_problem,
        serving,
        serving_needs_attention,
        own_pool,
        local_profile_name: principal_id
            .and_then(|principal_id| local_profile_name(data_dir, principal_id)),
        pool_notices,
        pool_address,
        node_requests: crate::custody_owner_requests::node_requests_view(
            data_dir,
            crate::auth::now_ts(),
        )
        .unwrap_or_else(|error| {
            tracing::warn!(error = %format!("{error:#}"), "custody node requests are unreadable");
            Vec::new()
        }),
    }
}

/// A pool file is present, even one the loader refuses.
pub(crate) fn pool_installed(data_dir: &Path) -> anyhow::Result<bool> {
    path_present(&runtime_custody_composition_config_path(data_dir))
}

/// The pool signing key's fingerprint, once the key exists.
pub(crate) fn signing_key_fingerprint(data_dir: &Path) -> anyhow::Result<Option<Fingerprint>> {
    let path = policy_authority_key_path(data_dir);
    if !path_present(&path)? {
        return Ok(None);
    }
    Ok(Some(Fingerprint::of(&policy_authority_public_key(&path)?)))
}

pub(crate) fn create_signing_key(data_dir: &Path) -> anyhow::Result<Fingerprint> {
    let path = policy_authority_key_path(data_dir);
    if path_present(&path)? {
        return Err(CustodyRefusal::new("key_exists").into());
    }
    ensure_owner_only_dir(&protected_content_root(data_dir), "protected-content root")?;
    create_policy_authority_key(&path)?;
    Ok(Fingerprint::of(&policy_authority_public_key(&path)?))
}

pub(crate) fn read_card(data_dir: &Path, text: &str) -> CardView {
    let local = read_local_node_or_warn(data_dir);
    match read_remote_card(&own_home(data_dir, local.as_ref()), text) {
        Ok(card) => card_view(card),
        Err(code) => CardView::Refused { refused: code },
    }
}

/// Fetch a node's card from the node itself. `address` is the node's Carrier
/// connect ticket; the node answers only the Home it was set up to trust.
pub(crate) async fn fetch_card(data_dir: &Path, address: &str) -> FetchedCard {
    let refused = |refused, detail| FetchedCard::Refused { refused, detail };
    let address = address.trim();
    let Some(dialed_did) = ticket_peer_did(address) else {
        return refused("bad_address", None);
    };
    let peer = OperatorPeer {
        did: dialed_did.clone(),
        connect_ticket: address.to_string(),
        ..OperatorPeer::default()
    };
    let answer = match request_remote_custody_node_card(data_dir, &peer).await {
        Ok(OperatorAnswer::Accepted(answer)) => answer,
        Ok(OperatorAnswer::Refused(reason)) if reason == CUSTODY_NODE_HAS_NO_CARD => {
            return refused("no_card", None)
        }
        Ok(OperatorAnswer::Refused(reason)) => return refused("not_owner", Some(reason)),
        Err(error) => {
            tracing::debug!(error = %format!("{error:#}"), "custody node card fetch failed");
            return refused("unreachable", Some(format!("{error:#}")));
        }
    };
    let local = read_local_node_or_warn(data_dir);
    match card_from_node_answer(
        &own_home(data_dir, local.as_ref()),
        address,
        &dialed_did,
        &answer,
    ) {
        Ok((card, read)) => FetchedCard::Card {
            card,
            view: card_view(read),
        },
        Err(code) => refused(code, None),
    }
}

/// Card refusals per slot, then every pool rule in order, each naming the
/// nodes that break it.
pub(crate) fn check(data_dir: &Path, cards: &[CardInput]) -> Vec<CheckResult> {
    let (members, mut results) = resolve_slots(data_dir, cards);
    results.extend(rule_results(&members));
    results
}

/// Include this Home as a pool node: provision it once, then start its
/// custody provider in the running Runtime when one is given.
pub(crate) async fn include_local_node(
    write: &CustodyWriteGuard,
    data_dir: &Path,
    registry: Option<&Arc<ProviderRegistry>>,
    run_by: &str,
    location: &str,
) -> anyhow::Result<LocalNodeView> {
    // #388 A1: only a WCI-operated host includes itself as a node.
    if !crate::host_trust::host_trusted(data_dir) {
        return Err(CustodyRefusal::new(crate::host_trust::HOST_TRUST_REQUIRED).into());
    }
    // A removal's tombstone holds no custody state; this only frees its space.
    if let Err(error) = finish_local_node_removal(write, data_dir) {
        tracing::warn!(error = %format!("{error:#}"), "a removed custody root is still on disk");
    }
    // An installed pool names this Home's node as it is.
    if pool_installed(data_dir)? {
        return Err(CustodyRefusal::new("pool_installed").into());
    }
    let node = match read_local_node(data_dir)
        .map_err(|error| CustodyRefusal::from_error("local_node_unreadable", &error))?
    {
        Some(node) => match local_node_keyed(data_dir, &node) {
            // Its keys stay when it leaves a slot; including it again reuses them.
            Keyed::Yes => node,
            Keyed::Unknown(error) => {
                return Err(CustodyRefusal::from_error("local_node_unreadable", &error).into())
            }
            // A node file whose keys are gone or differ is set up again.
            Keyed::No => {
                std::fs::remove_file(local_node_path(data_dir))
                    .context("failed to remove this Home's custody node without keys")?;
                provision_marked_local_node(data_dir, run_by, location).await?
            }
        },
        // Plan B T2.2: a Home may serve other pools and own one. A new own
        // root counts toward the cap of eight roots.
        None if custody_root_capacity_reached(data_dir, &[])? => {
            return Err(CustodyRefusal::new("too_many_pools").into())
        }
        None => provision_marked_local_node(data_dir, run_by, location).await?,
    };
    let needs_restart = match registry {
        Some(registry) => match register_local_custody_provider(registry, data_dir).await {
            Ok(()) => false,
            Err(error) => {
                tracing::warn!(
                    error = %format!("{error:#}"),
                    "this Home's custody provider did not start; it starts on the next restart"
                );
                true
            }
        },
        None => true,
    };
    Ok(LocalNodeView {
        node: local_node_summary(Some(&node), !needs_restart),
        needs_restart,
    })
}

/// Undo Include this Home before install. Runtime stops this Home's custody
/// provider, renames the custody root to a tombstone, deletes the node file,
/// then deletes the tombstone. The rename is all or nothing, so a removal
/// that stops anywhere leaves either the node to remove again or a tombstone
/// that holds no custody state and that the next Remove, Include or offer
/// switch deletes. A root that an Include left without its node file goes
/// too. A node an installed pool or another owner uses stays.
pub(crate) async fn remove_local_node(
    write: &CustodyWriteGuard,
    data_dir: &Path,
    registry: Option<&Arc<ProviderRegistry>>,
) -> anyhow::Result<LocalNodeSummary> {
    let failed = |error: anyhow::Error| CustodyRefusal::from_error("remove_failed", &error);
    // S2-F1: a removal stopped before the provider let its root go finishes
    // only once the provider holds the roots on disk alone.
    if !removal_tombstones(data_dir).map_err(failed)?.is_empty() {
        custody_provider_holds_only_disk_roots(registry, data_dir)
            .await
            .map_err(failed)?;
    }
    if finish_local_node_removal(write, data_dir).map_err(failed)? {
        return Ok(local_node_summary(None, false));
    }
    local_node_removable(data_dir)?;
    // None: the node file is left without its root; only the file goes, and
    // no root (a served pool's above all) is touched.
    let own_root = own_root_path(data_dir).map_err(failed)?;
    // Plan B T2.2: served pools keep running. Only a Home whose one root is
    // its own stops the provider; otherwise the provider is sent the roots
    // left once this one is set aside.
    let others = crate::protected_content_runtime::custody_provider_root_paths(data_dir)
        .map_err(failed)?
        .into_iter()
        .any(|root| Some(&root) != own_root.as_ref());
    if let (Some(registry), false) = (registry, others) {
        registry
            .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
            .map_err(|error| CustodyRefusal::with_detail("remove_failed", error.to_string()))?;
    }
    let set_aside = (|| {
        if let Some(own_root) = &own_root {
            let root = crate::protected_content_runtime::custody_root_dir(data_dir, own_root);
            if path_present(&root)? {
                std::fs::rename(&root, removal_tombstone(data_dir, own_root))
                    .context("failed to set the custody root aside")?;
            }
        }
        Ok(())
    })();
    set_aside.map_err(failed)?;
    // S2-F1: this Home's node goes only once the provider holds its root no
    // more; until then the tombstone and the node file stay for a retry.
    custody_provider_holds_only_disk_roots(registry, data_dir)
        .await
        .map_err(failed)?;
    let removed = (|| {
        let node = local_node_path(data_dir);
        if path_present(&node)? {
            std::fs::remove_file(node).context("failed to remove this Home's custody node")?;
        }
        finish_local_node_removal(write, data_dir).map(|_| ())
    })();
    removed.map_err(failed)?;
    tracing::debug!("this Home's custody node removed before install");
    Ok(local_node_summary(None, false))
}

/// Whether Remove has anything to delete, answered before the passkey
/// approval is spent: this Home's node file, with its root in any state, or
/// a root that trusts this Home alone without a node file (an Include that
/// stopped between the two). A root that trusts another Runtime stays, and so
/// does one that names nobody with no node file to say it is this Home's.
pub(crate) fn local_node_removable(data_dir: &Path) -> anyhow::Result<()> {
    use crate::custody_consent::RootTrust;
    if pool_installed(data_dir)? {
        return Err(CustodyRefusal::new("pool_installed").into());
    }
    let node_file = path_present(&local_node_path(data_dir))?;
    let own_did = elastos_identity::load_existing_did(data_dir)
        .map(|(_, did)| did)
        .ok();
    let refused =
        |code: &'static str| -> anyhow::Result<()> { Err(CustodyRefusal::new(code).into()) };
    // Plan B T2.2: only this Home's own root is Remove's; a served pool's
    // root is never its business.
    let own_trust = match own_root_path(data_dir)? {
        Some(own_root) => crate::custody_consent::custody_root_trust_at(data_dir, &own_root)?,
        None => RootTrust::NoRoot,
    };
    match own_trust {
        RootTrust::Trusts(owner) if Some(&owner) != own_did.as_ref() => refused("already_serving"),
        RootTrust::Trusts(_) => Ok(()),
        RootTrust::NamesNobody | RootTrust::NoRoot if node_file => Ok(()),
        RootTrust::NamesNobody => refused("already_serving"),
        RootTrust::NoRoot => refused("no_local_node"),
    }
}

/// What boot finishes before it starts the custody provider, best effort: a
/// removal of this Home's node that a stop interrupted, and an Include that
/// a stop interrupted. An Include's marker says the root without a node file
/// is its own, whose keys were never published; without the marker the root
/// stays. Once a pool is installed that root stays, and a root that trusts
/// another Runtime is never touched.
pub async fn finish_interrupted_local_node_changes(data_dir: &Path) {
    let write = crate::custody_consent::lock_custody_writes().await;
    let finished = (|| {
        finish_local_node_removal(&write, data_dir)?;
        let marker = include_marker_path(data_dir);
        if !path_present(&marker)? {
            return anyhow::Ok(());
        }
        // Only Include writes the marker, so a root the terminal made stays.
        // The marker names the root Include made; an older marker is empty
        // and names `inactive`.
        let marked_root = marked_include_root(&marker)?;
        if !pool_installed(data_dir)?
            && !path_present(&local_node_path(data_dir))?
            && !path_present(
                &crate::protected_content_config::custody_node_descriptor_path_for(
                    data_dir,
                    &marked_root,
                ),
            )?
            && root_trusts_this_home_at(data_dir, &marked_root)?
        {
            let root = crate::protected_content_runtime::custody_root_dir(data_dir, &marked_root);
            std::fs::rename(&root, removal_tombstone(data_dir, &marked_root))
                .context("failed to set the custody root aside")?;
            finish_local_node_removal(&write, data_dir)?;
            tracing::debug!("a custody root an interrupted Include left is removed");
        }
        std::fs::remove_file(&marker).context("failed to remove the Include marker")?;
        Ok(())
    })();
    if let Err(error) = finished {
        tracing::debug!(error = %format!("{error:#}"), "an interrupted custody node change stays");
    }
}

/// Whether the custody root at `root_path` trusts this Home's own Runtime,
/// as Include leaves it.
fn root_trusts_this_home_at(data_dir: &Path, root_path: &str) -> anyhow::Result<bool> {
    let own_did = elastos_identity::load_existing_did(data_dir)
        .map(|(_, did)| did)
        .ok();
    Ok(matches!(
        crate::custody_consent::custody_root_trust_at(data_dir, root_path)?,
        crate::custody_consent::RootTrust::Trusts(owner) if Some(&owner) == own_did.as_ref()
    ))
}

/// The root Include's marker names: its text, or `inactive` for an empty
/// marker an older build wrote.
fn marked_include_root(marker: &Path) -> anyhow::Result<String> {
    let text = read_owner_only_file(marker, 128, "this Home's custody node setup")?;
    let text = String::from_utf8(text).context("the Include marker is not text")?;
    let root = text.trim();
    if root.is_empty() {
        return Ok(custody_provider::CUSTODY_INACTIVE_ROOT_PATH.to_string());
    }
    if !custody_provider::is_custody_root_path(root) {
        anyhow::bail!("the Include marker names no custody root");
    }
    Ok(root.to_string())
}

/// Plan B T2.2: the root of this Home's own pool node, read only: the root
/// that trusts this Home, else the one Include's marker names, else an
/// `inactive` root that names nobody beside this Home's node file (a removal
/// stopped part way; its node file says it is this Home's), else none. A root
/// that trusts another owner is never this Home's own.
pub(crate) fn own_root_path(data_dir: &Path) -> anyhow::Result<Option<String>> {
    for root in crate::protected_content_runtime::custody_provider_root_paths(data_dir)? {
        if root_trusts_this_home_at(data_dir, &root)? {
            return Ok(Some(root));
        }
    }
    let marker = include_marker_path(data_dir);
    if path_present(&marker)? {
        return marked_include_root(&marker).map(Some);
    }
    let inactive = custody_provider::CUSTODY_INACTIVE_ROOT_PATH;
    if path_present(&local_node_path(data_dir))?
        && matches!(
            crate::custody_consent::custody_root_trust_at(data_dir, inactive)?,
            crate::custody_consent::RootTrust::NamesNobody
        )
    {
        return Ok(Some(inactive.to_string()));
    }
    Ok(None)
}

/// The root Include sets this Home's node up in: its own root when there is
/// one, else a new root named by this Home's pool signing key, which is made
/// now when missing (Plan B T2.2, S2-Q5).
fn own_root_path_for_include(data_dir: &Path) -> anyhow::Result<String> {
    if let Some(root) = own_root_path(data_dir)? {
        return Ok(root);
    }
    let fingerprint = match signing_key_fingerprint(data_dir)? {
        Some(fingerprint) => fingerprint,
        None => create_signing_key(data_dir)?,
    };
    reserve_custody_root_for_new_pool(data_dir, &fingerprint.full)
}

/// Plan B T2.2 (user decision 2026-11-12 10:35): the root a new pool takes,
/// and reserves it. `inactive` goes only to the first pool this Home ever
/// holds and is never handed out again; every later pool takes
/// `pools/<hex>`, `<hex>` being its pool fingerprint. The `pools` folder,
/// made here with the first root of any kind, is the record that `inactive`
/// was given out, so an approval that has not provisioned yet still holds
/// it.
pub(crate) fn reserve_custody_root_for_new_pool(
    data_dir: &Path,
    pool_fingerprint_full: &str,
) -> anyhow::Result<String> {
    let base = crate::protected_content_runtime::custody_provider_base(data_dir);
    let inactive = base.join(custody_provider::CUSTODY_INACTIVE_ROOT_PATH);
    let pools = base.join(custody_provider::CUSTODY_POOL_ROOTS_DIR);
    if !path_present(&inactive)?
        && !path_present(&pools)?
        && !path_present(&inactive.with_file_name("inactive.removing"))?
    {
        ensure_owner_only_dir(&protected_content_root(data_dir), "protected-content root")?;
        ensure_owner_only_dir(&base, "custody provider root")?;
        ensure_owner_only_dir(&pools, "custody pool roots")?;
        return Ok(custody_provider::CUSTODY_INACTIVE_ROOT_PATH.to_string());
    }
    let hex = pool_fingerprint_full
        .strip_prefix("sha256:")
        .filter(|hex| hex.len() == 64)
        .context("a pool fingerprint is sha256 and 64 hex digits")?;
    let path = format!("{}/{hex}", custody_provider::CUSTODY_POOL_ROOTS_DIR);
    if !custody_provider::is_custody_root_path(&path) {
        anyhow::bail!("a pool fingerprint is sha256 and 64 lowercase hex digits");
    }
    Ok(path)
}

/// Plan B T2.2 (user decision 2026-11-12 10:35): the roots this Home holds or
/// has given out: every root on disk, and every root an approving request
/// holds (`approving_roots`). Include and approving roots count.
pub(crate) fn custody_roots_in_use(
    data_dir: &Path,
    approving_roots: &[String],
) -> anyhow::Result<usize> {
    let mut roots: std::collections::BTreeSet<String> =
        crate::protected_content_runtime::custody_provider_root_paths(data_dir)?
            .into_iter()
            .collect();
    roots.extend(approving_roots.iter().cloned());
    Ok(roots.len())
}

/// This Home holds as many roots as a node may (D5: 8).
pub(crate) fn custody_root_capacity_reached(
    data_dir: &Path,
    approving_roots: &[String],
) -> anyhow::Result<bool> {
    Ok(custody_roots_in_use(data_dir, approving_roots)?
        >= crate::custody_release_limits::CUSTODY_NODE_SETTINGS.max_pools)
}

/// Include writes this before it sets up this Home's node and deletes it
/// once the node file is written, so boot can tell its root from one the
/// terminal made.
fn include_marker_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join(INCLUDE_MARKER_FILE)
}

/// Sets this Home's node up, under Include's marker when this setup makes
/// the root. A root that was there before (the terminal's, or one an earlier
/// setup left unmarked) is never marked, so boot never deletes it. A marker
/// already there says the root is Include's and stays until a setup
/// succeeds. A setup that failed before any root exists clears the marker;
/// one that stopped after leaves it, so boot removes that root.
async fn provision_marked_local_node(
    data_dir: &Path,
    run_by: &str,
    location: &str,
) -> anyhow::Result<LocalNode> {
    let marker = include_marker_path(data_dir);
    let root_path = own_root_path_for_include(data_dir)?;
    let root = crate::protected_content_runtime::custody_root_dir(data_dir, &root_path);
    let marked = path_present(&marker)?;
    let includes_root = marked || !path_present(&root)?;
    if includes_root && !marked {
        ensure_owner_only_dir(&protected_content_root(data_dir), "protected-content root")?;
        create_owner_only_file(
            &marker,
            root_path.as_bytes(),
            "this Home's custody node setup",
        )?;
    }
    let provisioned = provision_local_node(data_dir, &root_path, run_by, location).await;
    if includes_root && (provisioned.is_ok() || !path_present(&root)?) {
        std::fs::remove_file(&marker).context("failed to remove the Include marker")?;
    }
    provisioned
}

/// Where Remove sets the custody root `root_path` aside before deleting it:
/// `<root>.removing` beside it, which is never a root name.
fn removal_tombstone(data_dir: &Path, root_path: &str) -> PathBuf {
    let root = crate::protected_content_runtime::custody_root_dir(data_dir, root_path);
    let name = format!(
        "{}.removing",
        root.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("inactive")
    );
    root.with_file_name(name)
}

/// Every removal tombstone on disk, with the root it was.
fn removal_tombstones(data_dir: &Path) -> anyhow::Result<Vec<(String, PathBuf)>> {
    let mut found = Vec::new();
    let inactive = removal_tombstone(data_dir, custody_provider::CUSTODY_INACTIVE_ROOT_PATH);
    if path_present(&inactive)? {
        found.push((
            custody_provider::CUSTODY_INACTIVE_ROOT_PATH.to_string(),
            inactive,
        ));
    }
    let pools = crate::protected_content_runtime::custody_provider_base(data_dir)
        .join(custody_provider::CUSTODY_POOL_ROOTS_DIR);
    let entries = match std::fs::read_dir(&pools) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(found),
        Err(error) => return Err(error).context("custody pool roots cannot be listed"),
    };
    for entry in entries {
        let entry = entry.context("custody pool roots cannot be listed")?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(hex) = name.strip_suffix(".removing") else {
            continue;
        };
        let root = format!("{}/{hex}", custody_provider::CUSTODY_POOL_ROOTS_DIR);
        if custody_provider::is_custody_root_path(&root) {
            found.push((root, entry.path()));
        }
    }
    Ok(found)
}

/// Finishes what a stopped removal left. The rename to the tombstone is the
/// removal's commit point: with a tombstone and no root, the node file names
/// keys that are gone, so it goes first, then the tombstone. With a root
/// beside the tombstone, an Include came after, and its node stays. Returns
/// whether this finished removing this Home's node.
pub(crate) fn finish_local_node_removal(
    _write: &CustodyWriteGuard,
    data_dir: &Path,
) -> anyhow::Result<bool> {
    let mut finished_any = false;
    for (root_path, tombstone) in removal_tombstones(data_dir)? {
        let root = crate::protected_content_runtime::custody_root_dir(data_dir, &root_path);
        let node = local_node_path(data_dir);
        // The node file goes only when no root of this Home's own trusts it
        // any more and no Include came after.
        let finished = !path_present(&root)?
            && !pool_installed(data_dir)?
            && path_present(&node)?
            && !local_node_has_a_root(data_dir)?;
        if finished {
            std::fs::remove_file(node).context("failed to remove this Home's custody node")?;
            finished_any = true;
        }
        std::fs::remove_dir_all(&tombstone).context("failed to delete the removed custody root")?;
        tracing::debug!("a removed custody root is deleted");
    }
    Ok(finished_any)
}

/// Some root on disk trusts this Home: its own node still has its root.
fn local_node_has_a_root(data_dir: &Path) -> anyhow::Result<bool> {
    for root in crate::protected_content_runtime::custody_provider_root_paths(data_dir)? {
        if root_trusts_this_home_at(data_dir, &root)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// This Home set up as the custody node of one pool owner.
pub(crate) struct ServedNodeProvisioned {
    pub(crate) descriptor_bytes: Vec<u8>,
    /// Its root is not loaded in the running custody provider yet: true
    /// until the next restart. (Plan B T2.2, S2-Q4: the Chain plane is not
    /// pointed at the owner live; boot keeps reading `inactive`, and owners of
    /// `pools/<hex>` roots release through V2.)
    pub(crate) needs_restart: bool,
}

/// Set this Home up as the custody node a pool owner reaches over Carrier at
/// `own_did`, in the custody root `root_path`, trusting only `owner_issuer`,
/// and bring that root into the running provider.
///
/// Every step is idempotent for the same owner and labels, so approving again
/// after a crash yields the same descriptor bytes. A root that trusts another
/// issuer refuses, so one root never serves two owners.
pub(crate) async fn provision_served_node(
    data_dir: &Path,
    registry: Option<&Arc<ProviderRegistry>>,
    root_path: &str,
    owner_issuer: &str,
    run_by: &str,
    location: &str,
    own_did: &str,
) -> anyhow::Result<ServedNodeProvisioned> {
    validated_custody_node_label(run_by, "operator")
        .and_then(|_| validated_custody_node_label(location, "failure domain"))
        .map_err(|_| CustodyRefusal::new("bad_labels"))?;
    let provisioned = async {
        let provisioned = provision_custody_node_at(
            data_dir,
            root_path,
            owner_issuer,
            run_by,
            location,
            Some(own_did),
        )
        .await?;
        store_custody_node_descriptor_at(data_dir, root_path, &provisioned.descriptor_bytes)?;
        anyhow::Ok(provisioned)
    }
    .await
    .map_err(|error| CustodyRefusal::from_error("provision_failed", &error))?;
    tracing::debug!(
        fingerprint = %fingerprint(&provisioned.descriptor_bytes),
        "this Home's custody node is set up for its pool owner"
    );
    let live = match registry {
        Some(registry) => match register_local_custody_provider(registry, data_dir).await {
            Ok(()) => {
                crate::protected_content_runtime::custody_root_loaded(data_dir, root_path).await
            }
            Err(error) => {
                tracing::warn!(
                    error = %format!("{error:#}"),
                    "this Home's custody provider did not start; it starts on the next restart"
                );
                false
            }
        },
        None => false,
    };
    Ok(ServedNodeProvisioned {
        descriptor_bytes: provisioned.descriptor_bytes,
        needs_restart: !live,
    })
}

/// This Home holds a custody state: a provisioned custody root, the node it
/// serves a pool owner with, its own node from Include this Home, or a pool
/// it owns. A removal's tombstone is not custody state. Plan B T2.2: a Home
/// may hold several pools, so this is a fact, never a refusal; the cap of
/// eight roots (`custody_root_capacity_reached`) is what declines.
pub(crate) fn holds_custody_state(data_dir: &Path) -> anyhow::Result<bool> {
    if !crate::protected_content_runtime::custody_provider_root_paths(data_dir)?.is_empty() {
        return Ok(true);
    }
    for path in [
        crate::protected_content_runtime::inactive_custody_state_root(data_dir),
        custody_node_descriptor_path(data_dir),
        local_node_path(data_dir),
        runtime_custody_composition_config_path(data_dir),
    ] {
        if path_present(&path)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Sign and install the pool, then register its remote nodes as peers.
///
/// The pool file is create-only and the Runtime loader proves it before this
/// returns; a pool the loader refuses is removed and nobody is registered.
pub(crate) async fn install(
    data_dir: &Path,
    cards: &[CardInput],
    term_days: u16,
) -> anyhow::Result<InstallResult> {
    ensure_installable(data_dir)?;
    let key_path = policy_authority_key_path(data_dir);
    let (members, mut results) = resolve_slots(data_dir, cards);
    results.extend(rule_results(&members));
    let failed: Vec<&str> = results
        .iter()
        .filter(|result| result.result == CheckOutcome::Fail)
        .map(|result| result.id)
        .collect();
    if !failed.is_empty() {
        return Err(CustodyRefusal::with_detail("checks_failed", failed.join(",")).into());
    }

    let mut records = BTreeMap::new();
    let mut descriptors = Vec::with_capacity(members.len());
    for member in members {
        let key_hex = node_public_key_hex(&member.descriptor);
        records.insert(
            key_hex.clone(),
            PoolMemberRecordV1 {
                share: 0,
                node_public_key_hex: key_hex,
                run_by: member.run_by(),
                location: member.descriptor.failure_domain.clone(),
                home_id: member.peer_did(),
                provides: member.provides,
                ipfs_peer_id: member.ipfs_peer_id,
                fingerprint: member.fingerprint,
                card: member.card,
            },
        );
        descriptors.push(member.descriptor);
    }
    // The committee rules stay the authority. The checks above only name who
    // breaks them, so a refusal here means the two disagree.
    let descriptors = distinct_custody_node_descriptors(descriptors).map_err(|error| {
        tracing::warn!(error = %error, "custody checks passed a set the committee rules refuse");
        CustodyRefusal::new("checks_failed")
    })?;
    remove_stale_members_record(data_dir)
        .map_err(|error| CustodyRefusal::from_error("install_failed", &error))?;
    install_custody_composition(data_dir, &key_path, descriptors, term_days).map_err(|error| {
        tracing::warn!(error = %format!("{error:#}"), "custody pool was not installed");
        CustodyRefusal::from_error("install_failed", &error)
    })?;

    let pool = installed_pool(data_dir)?.context("installed custody pool is missing")?;
    let mut members = Vec::with_capacity(pool.nodes.len());
    for node in &pool.nodes {
        let mut record = records
            .remove(&node.node_public_key_hex)
            .context("installed custody pool names a node no slot provided")?;
        record.share = node.share;
        members.push(record);
    }
    write_members_record(data_dir, &pool.config_sha256, &members);
    let registered = members
        .iter()
        .filter(|member| member.card.is_some())
        .map(|member| match register_record(data_dir, member) {
            Ok(()) => RegistrationView {
                share: member.share,
                ok: true,
                reason: None,
            },
            Err(error) => {
                tracing::warn!(share = member.share, error = %format!("{error:#}"), "custody pool node was not registered");
                RegistrationView {
                    share: member.share,
                    ok: false,
                    reason: Some(format!("{error:#}")),
                }
            }
        })
        .collect();
    Ok(InstallResult {
        fingerprint: pool.fingerprint.short,
        fingerprint_full: pool.fingerprint.full,
        verified: true,
        registered,
    })
}

/// Install's read-only refusals: a pool is already installed, or there is no
/// signing key. The route asks first so neither spends a passkey approval.
pub(crate) fn ensure_installable(data_dir: &Path) -> anyhow::Result<()> {
    if pool_installed(data_dir)? {
        return Err(CustodyRefusal::new("already_installed").into());
    }
    if !path_present(&policy_authority_key_path(data_dir))? {
        return Err(CustodyRefusal::new("no_signing_key").into());
    }
    Ok(())
}

/// Register again: add the member's node to this Home's peers from the card
/// kept at install.
pub(crate) fn register_member(data_dir: &Path, share: u8) -> anyhow::Result<()> {
    let pool = installed_pool(data_dir)
        .map_err(|error| CustodyRefusal::from_error("verify_failed", &error))?
        .ok_or_else(|| CustodyRefusal::new("no_pool"))?;
    if !pool.nodes.iter().any(|node| node.share == share) {
        return Err(CustodyRefusal::new("unknown_share").into());
    }
    let record = read_members_record(data_dir, &pool.config_sha256)
        .and_then(|record| {
            record
                .members
                .into_iter()
                .find(|member| member.share == share)
        })
        .ok_or_else(|| CustodyRefusal::new("no_card"))?;
    register_record(data_dir, &record)
        .map_err(|error| CustodyRefusal::from_error("register_failed", &error))?;
    Ok(())
}

/// Verify again: the Runtime loader's check of the installed pool file.
pub(crate) fn verify(data_dir: &Path) -> anyhow::Result<VerifyView> {
    if !path_present(&runtime_custody_composition_config_path(data_dir))? {
        return Err(CustodyRefusal::new("no_pool").into());
    }
    let installed = verify_installed_custody_composition(data_dir)
        .map_err(|error| CustodyRefusal::from_error("verify_failed", &error))?;
    let print = pool_fingerprint(&installed.config_sha256)?;
    Ok(VerifyView {
        verified: true,
        fingerprint: print.short,
        fingerprint_full: print.full,
        checked_at: crate::auth::now_ts(),
    })
}

/// The installed pool with its members named, or none when no pool exists.
///
/// A pool installed from the terminal has no members record: its members are
/// named by their peer labels, and their Locations are unknown.
pub(crate) fn read_pool(data_dir: &Path) -> anyhow::Result<Option<PoolView>> {
    let Some(pool) = installed_pool(data_dir)
        .map_err(|error| CustodyRefusal::from_error("verify_failed", &error))?
    else {
        return Ok(None);
    };
    let record = read_members_record(data_dir, &pool.config_sha256);
    let peers = operator_peers_or_warn(data_dir);
    let members = pool
        .nodes
        .iter()
        .map(|node| {
            let recorded = record.as_ref().and_then(|record| {
                record
                    .members
                    .iter()
                    .find(|member| member.node_public_key_hex == node.node_public_key_hex)
            });
            let peer = node
                .peer_did
                .as_ref()
                .and_then(|did| peers.iter().find(|peer| &peer.did == did));
            let this_home = node.peer_did.is_none();
            PoolMemberView {
                share: node.share,
                run_by: recorded.map(|member| member.run_by.clone()).or_else(|| {
                    peer.map(|peer| peer.label.clone())
                        .filter(|label| !label.is_empty())
                }),
                location: recorded.map(|member| member.location.clone()),
                home_id: node.peer_did.clone(),
                provides: match (recorded, peer) {
                    (Some(member), _) => member.provides.clone(),
                    (None, _) if this_home => local_provides(),
                    (None, Some(peer)) => peer.provides.clone(),
                    (None, None) => Vec::new(),
                },
                this_home,
                // This Home's own node needs no peer entry.
                registered: this_home || peer.is_some(),
            }
        })
        .collect();
    Ok(Some(PoolView {
        members,
        term: pool.term,
        threshold: pool.threshold,
        fingerprint: pool.fingerprint.short,
        fingerprint_full: pool.fingerprint.full,
        cards_kept: record.is_some(),
    }))
}

/// Ask every member of the installed pool whether it is serving, and weigh
/// the answers against the pool's threshold. A remote member is online when
/// its Home answers the owner's card read with the node key the pool names;
/// this Home's member is online when its custody provider is serving.
pub(crate) async fn pool_health(
    data_dir: &Path,
    registry: Option<&Arc<ProviderRegistry>>,
) -> anyhow::Result<Option<PoolHealthView>> {
    let Some(pool) = installed_pool(data_dir)
        .map_err(|error| CustodyRefusal::from_error("verify_failed", &error))?
    else {
        return Ok(None);
    };
    let record = read_members_record(data_dir, &pool.config_sha256);
    let peers = operator_peers_or_warn(data_dir);
    let mut members = Vec::with_capacity(pool.nodes.len());
    // One probe per member, all at once, so a stopped node costs one timeout.
    let mut probes = tokio::task::JoinSet::new();
    for node in &pool.nodes {
        let unhealthy = |state, detail: &str| MemberHealthView {
            share: node.share,
            state,
            detail: Some(detail.to_string()),
        };
        let Some(did) = node.peer_did.clone() else {
            let local = read_local_node_or_warn(data_dir);
            members.push(if local_node_running(local.as_ref(), registry).await {
                MemberHealthView {
                    share: node.share,
                    state: MemberState::Online,
                    detail: None,
                }
            } else {
                unhealthy(MemberState::NotAnswering, "not_running")
            });
            continue;
        };
        let Some(connect_ticket) = member_ticket(record.as_ref(), &peers, node) else {
            members.push(unhealthy(MemberState::NotAnswering, "no_address"));
            continue;
        };
        probes.spawn(probe_member(
            data_dir.to_path_buf(),
            node.share,
            OperatorPeer {
                did,
                connect_ticket,
                ..OperatorPeer::default()
            },
            node.node_public_key_hex.clone(),
        ));
    }
    while let Some(probed) = probes.join_next().await {
        members.push(probed.context("custody pool member probe failed")?);
    }
    members.sort_by_key(|member| member.share);
    let online = members
        .iter()
        .filter(|member| member.state == MemberState::Online)
        .count();
    let online = u8::try_from(online).context("custody pool has too many members")?;
    Ok(Some(PoolHealthView {
        status: pool_status(online, pool.threshold),
        online,
        required: pool.threshold.required,
        total: pool.threshold.total,
        checked_at: crate::auth::now_ts(),
        members,
    }))
}

fn pool_status(online: u8, threshold: ThresholdView) -> PoolHealth {
    if online >= threshold.total {
        PoolHealth::Healthy
    } else if online >= threshold.required {
        PoolHealth::AtRisk
    } else {
        PoolHealth::Down
    }
}

/// Where to dial a remote member: the ticket on its peer entry, which Carrier
/// dials and an operator updates, else the one on its kept card.
fn member_ticket(
    record: Option<&PoolMembersRecordV1>,
    peers: &[OperatorPeer],
    node: &InstalledNode,
) -> Option<String> {
    let peer = peers
        .iter()
        .find(|peer| Some(&peer.did) == node.peer_did.as_ref())
        .map(|peer| peer.connect_ticket.trim().to_string())
        .filter(|ticket| !ticket.is_empty());
    peer.or_else(|| {
        record
            .and_then(|record| {
                record
                    .members
                    .iter()
                    .find(|member| member.node_public_key_hex == node.node_public_key_hex)
            })
            .and_then(|member| member.card.as_deref())
            .and_then(|card| parse_node_card(card).ok())
            .map(|card| card.ticket)
    })
}

/// One member's state from its Home's answer to the owner's card read.
async fn probe_member(
    data_dir: PathBuf,
    share: u8,
    peer: OperatorPeer,
    node_public_key_hex: String,
) -> MemberHealthView {
    let answer = request_remote_custody_node_card_within(
        &data_dir,
        &peer,
        HEALTH_PROBE_CONNECT_TIMEOUT_SECS,
        HEALTH_PROBE_WAIT,
    )
    .await;
    let (state, detail) = match answer {
        Ok(OperatorAnswer::Accepted(answer)) => {
            answered_state(&answer, &peer.connect_ticket, &node_public_key_hex)
        }
        Ok(OperatorAnswer::Refused(reason)) => (MemberState::Refused, Some(reason)),
        Err(error) => (MemberState::NotAnswering, Some(format!("{error:#}"))),
    };
    tracing::debug!(share, ?state, ?detail, "custody pool member probed");
    MemberHealthView {
        share,
        state,
        detail,
    }
}

/// Only the answered node key counts: everything else in the answer is the
/// node's own word about itself.
fn answered_state(
    answer: &serde_json::Value,
    ticket: &str,
    expected_key_hex: &str,
) -> (MemberState, Option<String>) {
    match node_card_from_answer(answer, ticket).and_then(|text| parse_node_card(&text)) {
        Ok(card) if node_public_key_hex(&card.descriptor) == expected_key_hex => {
            (MemberState::Online, None)
        }
        Ok(_) => (MemberState::DifferentNode, None),
        Err(refusal) => (MemberState::NotAnswering, Some(refusal.code().to_string())),
    }
}

fn runtime_threshold() -> ThresholdView {
    ThresholdView {
        required: CUSTODY_THRESHOLD_REQUIRED,
        total: CUSTODY_THRESHOLD_TOTAL,
    }
}

fn signing_key_view(data_dir: &Path) -> SigningKeyView {
    let path = policy_authority_key_path(data_dir);
    match path_present(&path) {
        Ok(true) => {
            let (fingerprint, fingerprint_full) = policy_authority_public_key(&path)
                .map(|public_key| Fingerprint::of(&public_key))
                .inspect_err(|error| {
                    tracing::warn!(error = %format!("{error:#}"), "pool signing key is unreadable");
                })
                .ok()
                .map(|print| (print.short, print.full))
                .unzip();
            SigningKeyView {
                present: true,
                fingerprint,
                fingerprint_full,
            }
        }
        Ok(false) => SigningKeyView {
            present: false,
            fingerprint: None,
            fingerprint_full: None,
        },
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "pool signing key is unavailable");
            SigningKeyView {
                present: false,
                fingerprint: None,
                fingerprint_full: None,
            }
        }
    }
}

/// The installed protected-content network and how many independent sources
/// prove a buyer's access on it.
fn chain_view(data_dir: &Path) -> ChainView {
    let config = match load_runtime_protected_content_chain_provider_config(data_dir) {
        Ok(Some(config)) => config,
        Ok(None) => {
            return ChainView {
                ready: false,
                network: None,
                proof_sources: 0,
            }
        }
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "protected-content chain config is unreadable");
            return ChainView {
                ready: false,
                network: None,
                proof_sources: 0,
            };
        }
    };
    let network = config.protected_content_network();
    let proof_sources = network["rights_methods"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|method| method["protected_content_policies"].as_array())
        .flatten()
        .filter(|policy| policy["action"] == "view")
        .filter_map(|policy| policy["evidence_rpc_urls"].as_array())
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    ChainView {
        ready: true,
        network: network["display_name"].as_str().map(str::to_string),
        proof_sources,
    }
}

fn local_node_summary(node: Option<&LocalNode>, running: bool) -> LocalNodeSummary {
    let (fingerprint, fingerprint_full) = node
        .map(|node| Fingerprint::of(&node.bytes))
        .map(|print| (print.short, print.full))
        .unzip();
    LocalNodeSummary {
        provisioned: node.is_some(),
        run_by: node.map(|node| node.descriptor.operator.clone()),
        location: node.map(|node| node.descriptor.failure_domain.clone()),
        fingerprint,
        fingerprint_full,
        running: node.is_some() && running,
        address: None,
    }
}

fn local_provides() -> Vec<String> {
    let mut provides = REQUIRED_ROLES.map(str::to_string).to_vec();
    provides.sort();
    provides
}

fn read_local_node(data_dir: &Path) -> anyhow::Result<Option<LocalNode>> {
    let path = local_node_path(data_dir);
    if !path_present(&path)? {
        return Ok(None);
    }
    let bytes = read_owner_only_file(
        &path,
        MAX_CUSTODY_NODE_DESCRIPTOR_BYTES,
        "this Home's custody node",
    )?;
    let descriptor = validated_custody_node_descriptor(&bytes, "this Home's custody node")?;
    Ok(Some(LocalNode { bytes, descriptor }))
}

async fn provision_local_node(
    data_dir: &Path,
    root_path: &str,
    run_by: &str,
    location: &str,
) -> anyhow::Result<LocalNode> {
    // Checked here so the refusal names labels, not the descriptor fields.
    validated_custody_node_label(run_by, "operator")
        .and_then(|_| validated_custody_node_label(location, "failure domain"))
        .map_err(|_| CustodyRefusal::new("bad_labels"))?;
    let provisioned = async {
        let issuer = runtime_issuer_hex(data_dir)?;
        provision_custody_node_at(data_dir, root_path, &issuer, run_by, location, None).await
    }
    .await
    .map_err(|error| CustodyRefusal::from_error("provision_failed", &error))?;
    ensure_owner_only_dir(&protected_content_root(data_dir), "protected-content root")?;
    create_owner_only_file(
        &local_node_path(data_dir),
        &provisioned.descriptor_bytes,
        "this Home's custody node",
    )?;
    tracing::debug!(
        fingerprint = %fingerprint(&provisioned.descriptor_bytes),
        "this Home's custody node provisioned"
    );
    let descriptor = validated_custody_node_descriptor(
        &provisioned.descriptor_bytes,
        "this Home's custody node",
    )?;
    Ok(LocalNode {
        bytes: provisioned.descriptor_bytes,
        descriptor,
    })
}

/// Start this Home's custody provider in the running Runtime, as boot does.
pub(crate) async fn register_local_custody_provider(
    registry: &Arc<ProviderRegistry>,
    data_dir: &Path,
) -> anyhow::Result<()> {
    if registry
        .has_ready_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
    {
        // Plan B T2.2 (S2-Q1): a new root reaches the running provider this
        // server started. A provider it did not start is left as it is.
        if !crate::protected_content_runtime::custody_bridge_known(data_dir) {
            return Ok(());
        }
        return crate::protected_content_runtime::refresh_custody_roots(data_dir)
            .await
            .map(drop);
    }
    let binary = crate::binaries::resolve_verified_native_provider_binary_with_data_dir(
        data_dir,
        "custody-provider",
    )?
    .context("verified custody provider binary is unavailable")?;
    match register_custody_provider(registry, &binary, data_dir).await {
        Ok(()) => Ok(()),
        // Another request started it first.
        Err(_)
            if registry
                .has_ready_runtime_provider_target(CUSTODY_PROVIDER_ID)
                .await =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// This Home's node is serving in the running Runtime.
async fn local_node_running(
    node: Option<&LocalNode>,
    registry: Option<&Arc<ProviderRegistry>>,
) -> bool {
    node.is_some() && custody_provider_ready(registry).await
}

/// This Home's custody provider is serving in the running Runtime.
pub(crate) async fn custody_provider_ready(registry: Option<&Arc<ProviderRegistry>>) -> bool {
    match registry {
        Some(registry) => {
            registry
                .has_ready_runtime_provider_target(CUSTODY_PROVIDER_ID)
                .await
        }
        None => false,
    }
}

/// The served pools' nodes, in map order (Plan B T2.2).
fn served_nodes_or_warn(data_dir: &Path) -> Vec<ServedNode> {
    let read = || -> anyhow::Result<Vec<ServedNode>> {
        let mut nodes = Vec::new();
        for (fingerprint_full, entry) in crate::custody_consent::served_pools(data_dir)?.entries {
            let Some(card) =
                crate::custody_node_card::served_node_card(data_dir, &entry.root_path)?
            else {
                continue;
            };
            let descriptor = validated_custody_node_descriptor(&card.node_bytes, "custody node")?;
            nodes.push(ServedNode {
                root_path: entry.root_path,
                fingerprint_full,
                card,
                descriptor,
            });
        }
        // A node served from `inactive` before consents were kept has no
        // entry: it still shows, with no pool key, until its owner asks again
        // and the approval backfills the consent.
        let inactive = custody_provider::CUSTODY_INACTIVE_ROOT_PATH;
        if !nodes.iter().any(|node| node.root_path == inactive) {
            if let Some(card) = crate::custody_node_card::served_node_card(data_dir, inactive)? {
                let descriptor =
                    validated_custody_node_descriptor(&card.node_bytes, "custody node")?;
                nodes.push(ServedNode {
                    root_path: inactive.to_string(),
                    fingerprint_full: String::new(),
                    card,
                    descriptor,
                });
            }
        }
        Ok(nodes)
    };
    read().unwrap_or_else(|error| {
        tracing::warn!(error = %format!("{error:#}"), "this Home's custody node details are unreadable");
        Vec::new()
    })
}

/// Plan B T2.3: one served pool as Hosting lists it
/// (`GET /api/apps/custody/pools/served`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ServedPoolItem {
    /// The pool fingerprint's 64 hex digits, as `:pool` names it.
    pub(crate) pool_fingerprint: String,
    /// The owner's People name, else its DID.
    pub(crate) owner_name: String,
    /// What this node does for the pool, from its card.
    pub(crate) roles: Vec<String>,
    pub(crate) status: ServedPoolStatus,
    /// The signed pool's end, once its owner confirmed it.
    pub(crate) term_end: Option<u64>,
    /// The shares this pool's root holds, from the running provider.
    pub(crate) shares_held: Option<u64>,
    /// An admin profile is kept for this pool's sealed publication (S2-A3).
    pub(crate) publisher_confirmed: bool,
    /// Filled by later tasks (S2-Q7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sessions_24h: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) seals_24h: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ServedPoolStatus {
    /// Approved; the owner has not confirmed its pool yet.
    WaitingForPool,
    Serving,
    /// This root is not loaded in the running provider.
    NeedsRestart,
    /// Less than seven days of the consented pool are left (lead 17:55).
    ConsentEnding,
}

/// Below this many seconds of the pool's term, its status is `consent_ending`.
pub(crate) const CONSENT_ENDING_SECS: u64 = 7 * SECONDS_PER_DAY;

/// Every served pool, for Hosting. `name_of` gives an owner DID's People
/// name. A root not loaded comes first: it is the one to act on.
pub(crate) async fn served_pool_items(
    data_dir: &Path,
    registry: Option<&Arc<ProviderRegistry>>,
    name_of: &(dyn Fn(&str) -> Option<String> + Sync),
    now: u64,
) -> anyhow::Result<Vec<ServedPoolItem>> {
    let pools = crate::custody_consent::served_pools(data_dir)?;
    let running = custody_provider_ready(registry).await;
    let roots = crate::protected_content_runtime::custody_provider_root_statuses(data_dir)
        .await
        .unwrap_or_default();
    let mut items = Vec::new();
    for (pool_key, entry) in pools.entries {
        let root = roots
            .iter()
            .find(|root| root.path.as_deref() == Some(entry.root_path.as_str()));
        let loaded = running && root.is_some_and(|root| root.configured);
        let pool = crate::custody_consent::served_pool_view(data_dir, &pool_key);
        let term_end = pool.as_ref().map(|pool| pool.term_end);
        let status = served_pool_status(loaded, term_end, now);
        let roles = crate::custody_node_card::served_node_card(data_dir, &entry.root_path)
            .ok()
            .flatten()
            .map(|card| card.provides)
            .unwrap_or_default();
        items.push(ServedPoolItem {
            pool_fingerprint: pool_key.trim_start_matches("sha256:").to_string(),
            owner_name: name_of(&entry.owner_home).unwrap_or_else(|| entry.owner_home.clone()),
            roles,
            status,
            term_end,
            shares_held: root.and_then(|root| root.shares_held),
            publisher_confirmed: entry.admin_profile_did.is_some(),
            sessions_24h: None,
            seals_24h: None,
        });
    }
    Ok(items)
}

/// A served pool's status: a root not loaded needs a restart; an approved
/// pool its owner has not confirmed waits; under seven days left, the
/// consent is ending.
pub(crate) fn served_pool_status(
    loaded: bool,
    term_end: Option<u64>,
    now: u64,
) -> ServedPoolStatus {
    match term_end {
        _ if !loaded => ServedPoolStatus::NeedsRestart,
        None => ServedPoolStatus::WaitingForPool,
        Some(end) if end.saturating_sub(now) < CONSENT_ENDING_SECS => {
            ServedPoolStatus::ConsentEnding
        }
        Some(_) => ServedPoolStatus::Serving,
    }
}

/// Plan B T2.3 (S2-R3-F1): this Home's own pool, when it has an own root: its
/// pool key's fingerprint and whether the including admin profile is kept.
fn own_pool_view(
    data_dir: &Path,
    pools: Option<&crate::custody_consent::ServedPools>,
) -> Option<OwnPoolView> {
    own_root_path(data_dir).ok().flatten()?;
    let fingerprint = signing_key_fingerprint(data_dir).ok().flatten()?;
    Some(OwnPoolView {
        pool_fingerprint: fingerprint.full.trim_start_matches("sha256:").to_string(),
        publisher_confirmed: pools.is_some_and(|pools| pools.own_root_admin_profile_did.is_some()),
    })
}

/// What Confirm publisher writes to (S2-A3, S2-R3-F1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PublisherTarget {
    /// A served pool's entry, by its `sha256:` key.
    Served(String),
    /// This Home's own root.
    OwnRoot,
}

/// The pool Confirm publisher names, checked before the passkey approval is
/// spent: 64 lowercase hex digits (`bad_pool`), a served pool or this Home's
/// own pool (`unknown_pool`).
pub(crate) fn publisher_target(data_dir: &Path, pool_hex: &str) -> anyhow::Result<PublisherTarget> {
    if let Ok(pool_key) = served_pool_stoppable(data_dir, pool_hex) {
        return Ok(PublisherTarget::Served(pool_key));
    }
    if !custody_provider::is_custody_root_path(&format!(
        "{}/{pool_hex}",
        custody_provider::CUSTODY_POOL_ROOTS_DIR
    )) {
        return Err(CustodyRefusal::new("bad_pool").into());
    }
    match own_pool_view(data_dir, None) {
        Some(own) if own.pool_fingerprint == pool_hex => Ok(PublisherTarget::OwnRoot),
        _ => Err(CustodyRefusal::new("unknown_pool").into()),
    }
}

/// Plan B T2.3 (S2-A3): records the calling admin profile as the publisher
/// of exactly that pool: its entry, or this Home's own root. Nothing else
/// changes.
pub(crate) fn confirm_publisher(
    write: &CustodyWriteGuard,
    data_dir: &Path,
    pool_hex: &str,
    profile_did: &str,
) -> anyhow::Result<()> {
    match publisher_target(data_dir, pool_hex)? {
        PublisherTarget::Served(pool_key) => {
            crate::custody_consent::update_served_pools(data_dir, |pools| {
                let entry = pools
                    .entries
                    .get_mut(&pool_key)
                    .ok_or_else(|| CustodyRefusal::new("unknown_pool"))?;
                entry.admin_profile_did = Some(profile_did.to_string());
                Ok(())
            })
        }
        PublisherTarget::OwnRoot => {
            crate::custody_consent::record_own_root_admin_profile(write, data_dir, profile_did)
        }
    }
}

/// The served pool `pool_hex` names, checked before the passkey approval is
/// spent: 64 lowercase hex digits (`bad_pool`), served here (`unknown_pool`).
pub(crate) fn served_pool_stoppable(data_dir: &Path, pool_hex: &str) -> anyhow::Result<String> {
    let pool_key = format!("sha256:{pool_hex}");
    if !custody_provider::is_custody_root_path(&format!(
        "{}/{pool_hex}",
        custody_provider::CUSTODY_POOL_ROOTS_DIR
    )) {
        return Err(CustodyRefusal::new("bad_pool").into());
    }
    let pools = crate::custody_consent::served_pools(data_dir)
        .map_err(|error| CustodyRefusal::from_error("unavailable", &error))?;
    if !pools.entries.contains_key(&pool_key) {
        return Err(CustodyRefusal::new("unknown_pool").into());
    }
    Ok(pool_key)
}

/// Plan B T2.3: Stop serving one pool. Its root goes aside to a tombstone
/// under `pools/` (kept: the shares are not destroyed), the running provider
/// is sent the roots left, and the pool's entry (consent, served pool and
/// descriptor) and node card go. The other roots keep running. For the
/// `inactive` root the Chain plane falls back to this Home's own issuer at
/// the next boot. A stop that a crash cut short is finished by asking again.
pub(crate) async fn stop_serving_pool(
    write: &CustodyWriteGuard,
    data_dir: &Path,
    registry: Option<&Arc<ProviderRegistry>>,
    pool_hex: &str,
    now: u64,
) -> anyhow::Result<()> {
    let failed = |error: anyhow::Error| CustodyRefusal::from_error("stop_failed", &error);
    let pool_key = served_pool_stoppable(data_dir, pool_hex)?;
    let entry = crate::custody_consent::served_pools(data_dir)
        .map_err(failed)?
        .entries
        .remove(&pool_key)
        .ok_or_else(|| CustodyRefusal::new("unknown_pool"))?;
    // R3-D1 = A: when this is the last root, the provider stops first, as
    // Remove does, and only then is the root set aside.
    let last_root = crate::protected_content_runtime::custody_provider_root_paths(data_dir)
        .map_err(failed)?
        .iter()
        .all(|root| *root == entry.root_path);
    // S2-F1: a provider that does not stop keeps the pool served and the
    // root in place, and the stop is refused; asking again retries it.
    if let (true, Some(registry)) = (last_root, registry) {
        registry
            .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
            .map_err(|error| CustodyRefusal::with_detail("stop_failed", error.to_string()))?;
    }
    let root = crate::protected_content_runtime::custody_root_dir(data_dir, &entry.root_path);
    if path_present(&root).map_err(failed)? {
        let tombstone = stopped_tombstone(data_dir, &entry.root_path, now);
        if let Some(parent) = tombstone.parent() {
            ensure_owner_only_dir(parent, "custody pool roots").map_err(failed)?;
        }
        std::fs::rename(&root, &tombstone)
            .context("failed to set the custody root aside")
            .map_err(failed)?;
        tracing::info!("a served pool's custody root is set aside");
    }
    // S2-F1: the pool stays served (its entry kept, the stop refused) until
    // the provider holds the stopped root no more; asking again retries.
    custody_provider_holds_only_disk_roots(registry, data_dir)
        .await
        .map_err(failed)?;
    // The `inactive` root's card lives beside the roots, not in its folder.
    if entry.root_path == custody_provider::CUSTODY_INACTIVE_ROOT_PATH {
        let card = custody_node_descriptor_path(data_dir);
        if path_present(&card).map_err(failed)? {
            std::fs::remove_file(&card)
                .context("failed to remove the served node's card")
                .map_err(failed)?;
        }
    }
    // OPEN-LOOP F1 / ADV-14: the copy duty ends with the owner's last root.
    // Before the entry goes, so a refused withdrawal is retried by asking
    // again.
    crate::custody_consent::withdraw_served_owner_replicas(write, data_dir, &entry.owner_home)
        .map_err(failed)?;
    crate::custody_consent::forget_served_pool(write, data_dir, &pool_key).map_err(failed)?;
    tracing::debug!("this Home stopped serving a pool");
    Ok(())
}

/// S2-F1: the running custody provider holds only the roots on disk, made so
/// by a fresh `init` when this server started it. Fails while a provider may
/// still hold a root that is gone from disk, so a stop or a removal is never
/// reported before its root is out. With no registry there is no provider.
async fn custody_provider_holds_only_disk_roots(
    registry: Option<&Arc<ProviderRegistry>>,
    data_dir: &Path,
) -> anyhow::Result<()> {
    let Some(registry) = registry else {
        return Ok(());
    };
    let on_disk = crate::protected_content_runtime::custody_provider_root_paths(data_dir)?;
    if on_disk.is_empty() || !crate::protected_content_runtime::custody_bridge_known(data_dir) {
        // Ready or Settling: a provider whose shutdown has not finished may
        // still hold the root.
        if registry
            .has_runtime_provider_target_registration(CUSTODY_PROVIDER_ID)
            .await
        {
            anyhow::bail!("the running custody provider cannot be sent the roots left");
        }
        return Ok(());
    }
    let held = crate::protected_content_runtime::refresh_custody_roots(data_dir).await?;
    if held
        .iter()
        .filter_map(|root| root.path.as_ref())
        .any(|path| !on_disk.contains(path))
    {
        anyhow::bail!("the custody provider still holds a root that is set aside");
    }
    Ok(())
}

/// Where Stop serving sets the root `root_path` aside: under `pools/`, a name
/// that is never a root, stamped with the time so a later stop never meets
/// it.
fn stopped_tombstone(data_dir: &Path, root_path: &str, now: u64) -> PathBuf {
    let name = root_path.rsplit('/').next().unwrap_or(root_path);
    crate::protected_content_runtime::custody_provider_base(data_dir)
        .join(custody_provider::CUSTODY_POOL_ROOTS_DIR)
        .join(format!("{name}.stopped-{now}"))
}

/// This Home's Carrier ticket as its running Carrier node reports it, when
/// that node is the one the descriptor routes to.
fn node_address(node: &ServedNode, carrier: Option<&iroh::Endpoint>) -> Option<String> {
    let routed_to = peer_did(&node.descriptor.transport)?;
    let ticket = carrier_connect_ticket(carrier?);
    if ticket_peer_did(&ticket)? != routed_to {
        tracing::warn!("custody node details route to another Carrier node than this Home's");
        return None;
    }
    Some(ticket)
}

/// A verified Profile's name is already a valid node label: at most 64 bytes,
/// whitespace collapsed.
fn local_profile_name(data_dir: &Path, principal_id: &str) -> Option<String> {
    load_profile_authority(
        data_dir,
        principal_id,
        &crate::auth::principal_localhost_root(principal_id),
    )
    .inspect_err(
        |error| tracing::debug!(error = %format!("{error:#}"), "admin Profile is unreadable"),
    )
    .ok()
    .flatten()
    .map(|profile| profile.document().display_name.clone())
}

fn serving_view(
    data_dir: &Path,
    node: ServedNode,
    provider_running: bool,
    root_loaded: bool,
) -> ServingView {
    let owner_did = match crate::custody_consent::custody_root_trust_at(data_dir, &node.root_path) {
        Ok(crate::custody_consent::RootTrust::Trusts(owner)) => Some(owner),
        _ => None,
    };
    let last_owner_contact = owner_did
        .as_deref()
        .and_then(|owner| last_accepted_request_at(data_dir, owner));
    let print = Fingerprint::of(&node.card.node_bytes);
    ServingView {
        owner_did,
        owner_name: None,
        run_by: node.descriptor.operator,
        location: node.descriptor.failure_domain,
        provides: node.card.provides,
        fingerprint: print.short,
        fingerprint_full: print.full,
        provider_running,
        // Plan B T2.2 (S2-Q4): "this root is not loaded in the running
        // provider".
        needs_restart: !provider_running || !root_loaded,
        last_owner_contact,
        pool: crate::custody_consent::served_pool_view(data_dir, &node.fingerprint_full),
        pool_fingerprint: node
            .fingerprint_full
            .trim_start_matches("sha256:")
            .to_string(),
    }
}

/// The served root `root_path` still waits for a restart: the provider is
/// not serving, or it has not loaded that root.
pub(crate) async fn served_node_needs_restart(
    data_dir: &Path,
    registry: Option<&Arc<ProviderRegistry>>,
    root_path: &str,
) -> bool {
    !custody_provider_ready(registry).await
        || !crate::protected_content_runtime::custody_root_loaded(data_dir, root_path).await
}

fn operator_peers_or_warn(data_dir: &Path) -> Vec<OperatorPeer> {
    load_operator_control(data_dir)
        .map(|config| config.peers)
        .unwrap_or_else(|error| {
            tracing::warn!(error = %format!("{error:#}"), "peer store is unreadable; custody members are read without it");
            Vec::new()
        })
}

fn read_local_node_or_warn(data_dir: &Path) -> Option<LocalNode> {
    read_local_node(data_dir).unwrap_or_else(|error| {
        tracing::warn!(error = %format!("{error:#}"), "this Home's custody node is unreadable");
        None
    })
}

fn own_home(data_dir: &Path, local: Option<&LocalNode>) -> OwnHome {
    OwnHome {
        did: elastos_identity::load_existing_did(data_dir)
            .map(|(_, did)| did)
            .inspect_err(|error| tracing::debug!(%error, "this Home has no DID yet"))
            .ok(),
        local_node_bytes: local.map(|node| node.bytes.clone()),
    }
}

fn card_view(card: NodeCard) -> CardView {
    CardView::Read {
        run_by: card.descriptor.operator.clone(),
        location: card.descriptor.failure_domain.clone(),
        home_id: peer_did(&card.descriptor.transport).unwrap_or_default(),
        provides: card.provides,
        fingerprint: card.fingerprint,
        fingerprint_full: card.fingerprint_full,
        local: false,
    }
}

/// The DID a ticket dials: the key of its one endpoint.
fn ticket_peer_did(address: &str) -> Option<String> {
    let [endpoint] = <[iroh::EndpointAddr; 1]>::try_from(decode_ticket_endpoints(address)).ok()?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(endpoint.id.as_bytes()).ok()?;
    elastos_identity::encode_did_key(&key).ok()
}

/// A node's answer as card text and the card it reads as. The card must name
/// the node that was dialed, not just one its ticket also reaches.
fn card_from_node_answer(
    own: &OwnHome,
    ticket: &str,
    dialed_did: &str,
    answer: &serde_json::Value,
) -> Result<(String, NodeCard), &'static str> {
    let text = node_card_from_answer(answer, ticket).map_err(|refusal| refusal.code())?;
    let card = read_remote_card(own, &text)?;
    if peer_did(&card.descriptor.transport).as_deref() != Some(dialed_did) {
        return Err("ticket_mismatch");
    }
    Ok((text, card))
}

/// A pasted card, or the refusal code the Custody app shows for it.
fn read_remote_card(own: &OwnHome, text: &str) -> Result<NodeCard, &'static str> {
    let card = parse_node_card(text).map_err(|refusal| refusal.code())?;
    let same_home = own.did.is_some() && peer_did(&card.descriptor.transport) == own.did;
    if same_home || own.local_node_bytes.as_ref() == Some(&card.node_bytes) {
        return Err("own_card");
    }
    Ok(card)
}

fn resolve_slots(data_dir: &Path, cards: &[CardInput]) -> (Vec<SlotMember>, Vec<CheckResult>) {
    let local = read_local_node_or_warn(data_dir);
    let local_refusal = local
        .as_ref()
        .and_then(|node| match local_node_keyed(data_dir, node) {
            Keyed::Yes => None,
            Keyed::No => Some("local_node_no_keys"),
            Keyed::Unknown(error) => {
                tracing::debug!(error = %format!("{error:#}"), "this Home's custody root is unreadable");
                Some("local_node_unreadable")
            }
        });
    let own = own_home(data_dir, local.as_ref());
    let mut members: Vec<SlotMember> = Vec::new();
    let mut results = Vec::new();
    for (index, input) in cards.iter().enumerate() {
        let slot = index + 1;
        let member = match input {
            CardInput::Remote { text } => match read_remote_card(&own, text) {
                Ok(card) => SlotMember {
                    slot,
                    node_bytes: card.node_bytes,
                    descriptor: card.descriptor,
                    provides: card.provides,
                    ipfs_peer_id: card.ipfs_peer_id,
                    fingerprint: card.fingerprint,
                    card: Some(
                        text.chars()
                            .filter(|ch| !ch.is_ascii_whitespace())
                            .collect(),
                    ),
                },
                Err(code) => {
                    results.push(slot_failure("card", vec![slot], Some(code)));
                    continue;
                }
            },
            // A node file whose root does not hold its key has none to serve
            // with: Remove ended part way, or the root was deleted or
            // replaced. A root that cannot be read now fails closed too.
            CardInput::ThisHome if local_refusal.is_some() => {
                results.push(slot_failure("card", vec![slot], local_refusal));
                continue;
            }
            // Each slot owns its descriptor; the stored bytes validated above.
            CardInput::ThisHome => match local.as_ref().and_then(|node| {
                validated_custody_node_descriptor(&node.bytes, "this Home's custody node")
                    .ok()
                    .map(|descriptor| (node, descriptor))
            }) {
                Some((node, descriptor)) => SlotMember {
                    slot,
                    node_bytes: node.bytes.clone(),
                    descriptor,
                    provides: local_provides(),
                    ipfs_peer_id: None,
                    fingerprint: fingerprint(&node.bytes),
                    card: None,
                },
                None => {
                    results.push(slot_failure("card", vec![slot], Some("local_node_missing")));
                    continue;
                }
            },
        };
        if let Some(first) = members
            .iter()
            .find(|earlier| earlier.node_bytes == member.node_bytes)
        {
            results.push(slot_failure("duplicate", vec![first.slot, slot], None));
            continue;
        }
        members.push(member);
    }
    (members, results)
}

/// This Home's node has its keys: its root trusts this Home. A root that
/// cannot be read now counts as without keys.
/// Whether this Home's node file names keys its custody root holds.
enum Keyed {
    Yes,
    /// No root that trusts this Home, or one holding another node key.
    No,
    /// The root could not be read now: nothing is decided on it.
    Unknown(anyhow::Error),
}

/// The one answer the summary, the pool checks and Include share, so they
/// never disagree about this Home's node. Only the node's public key is
/// read from the root; its secrets stay with the custody provider.
fn local_node_keyed(data_dir: &Path, node: &LocalNode) -> Keyed {
    let root_path = match own_root_path(data_dir) {
        Ok(Some(root_path)) => root_path,
        Ok(None) => return Keyed::No,
        Err(error) => return Keyed::Unknown(error),
    };
    match root_trusts_this_home_at(data_dir, &root_path) {
        Ok(true) => {}
        Ok(false) => return Keyed::No,
        Err(error) => return Keyed::Unknown(error),
    }
    let root = crate::protected_content_runtime::custody_root_dir(data_dir, &root_path);
    match custody_provider::load_node_public_key(&root) {
        Ok(key) if key == node.descriptor.node_public_key => Keyed::Yes,
        Ok(_) => Keyed::No,
        Err(error) => Keyed::Unknown(anyhow::anyhow!("custody root is unreadable: {error:?}")),
    }
}

fn slot_failure(id: &'static str, slots: Vec<usize>, detail: Option<&str>) -> CheckResult {
    CheckResult {
        id,
        result: CheckOutcome::Fail,
        names: slots.iter().map(usize::to_string).collect(),
        detail: detail.map(str::to_string),
    }
}

/// The rules of `distinct_custody_node_descriptors` one at a time, plus the
/// role and copy checks the pool needs, so each result names its nodes.
fn rule_results(members: &[SlotMember]) -> Vec<CheckResult> {
    let total = usize::from(CUSTODY_THRESHOLD_TOTAL);
    let mut results = vec![CheckResult {
        id: "members",
        result: outcome(members.len() == total),
        names: members.iter().map(SlotMember::run_by).collect(),
        detail: None,
    }];

    let same_node_key = sharing(members, |member| {
        Some(member.descriptor.node_public_key.as_bytes().to_vec())
    });
    let same_custody_key = sharing(members, |member| {
        Some(member.descriptor.custody_public_key.as_bytes().to_vec())
    });
    let same_keys: Vec<&SlotMember> = members
        .iter()
        .filter(|member| {
            [&same_node_key, &same_custody_key]
                .iter()
                .any(|group| group.iter().any(|shared| shared.slot == member.slot))
        })
        .collect();
    results.push(named_failure("keys", &same_keys, SlotMember::run_by, None));

    let same_home = sharing(members, SlotMember::peer_did);
    results.push(named_failure("homes", &same_home, SlotMember::run_by, None));

    let same_run_by = sharing(members, |member| Some(member.run_by()));
    let shared_run_by = same_run_by.first().map(|member| member.run_by());
    results.push(named_failure(
        "run_by",
        &same_run_by,
        |member| member.descriptor.failure_domain.clone(),
        shared_run_by,
    ));

    let same_location = sharing(members, |member| {
        Some(member.descriptor.failure_domain.clone())
    });
    let shared_location = same_location
        .first()
        .map(|member| member.descriptor.failure_domain.clone());
    results.push(named_failure(
        "location",
        &same_location,
        SlotMember::run_by,
        shared_location,
    ));

    let local: Vec<&SlotMember> = members.iter().filter(|member| member.is_local()).collect();
    let local = if local.len() > 1 { local } else { Vec::new() };
    results.push(named_failure("this_home", &local, SlotMember::run_by, None));

    let missing_roles = |member: &SlotMember| -> Vec<&'static str> {
        REQUIRED_ROLES
            .into_iter()
            .filter(|role| !member.provides.iter().any(|provided| provided == role))
            .collect()
    };
    let lacking: Vec<&SlotMember> = members
        .iter()
        .filter(|member| !missing_roles(member).is_empty())
        .collect();
    let missing: Vec<&str> = REQUIRED_ROLES
        .into_iter()
        .filter(|role| {
            lacking
                .iter()
                .any(|member| missing_roles(member).contains(role))
        })
        .collect();
    let missing = (!missing.is_empty()).then(|| missing.join(","));
    results.push(named_failure(
        "roles",
        &lacking,
        SlotMember::run_by,
        missing,
    ));

    // The publisher keeps one copy; the rest of the minimum must be remote.
    let remote_copies_needed =
        usize::try_from(PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET.saturating_sub(1))
            .unwrap_or(usize::MAX);
    let keepers: Vec<String> = members
        .iter()
        .filter(|member| {
            !member.is_local()
                && member
                    .provides
                    .iter()
                    .any(|role| role == OPERATOR_PROVIDES_IPFS)
        })
        .map(SlotMember::run_by)
        .collect();
    results.push(CheckResult {
        id: "copies",
        result: if keepers.len() >= remote_copies_needed {
            CheckOutcome::Pass
        } else {
            CheckOutcome::Advice
        },
        names: keepers,
        detail: None,
    });
    results
}

fn outcome(passed: bool) -> CheckOutcome {
    if passed {
        CheckOutcome::Pass
    } else {
        CheckOutcome::Fail
    }
}

/// Members whose key is shared with another member, in slot order.
fn sharing<K: Ord>(
    members: &[SlotMember],
    key: impl Fn(&SlotMember) -> Option<K>,
) -> Vec<&SlotMember> {
    let mut counts = BTreeMap::new();
    for value in members.iter().filter_map(&key) {
        *counts.entry(value).or_insert(0usize) += 1;
    }
    members
        .iter()
        .filter(|member| key(member).is_some_and(|value| counts[&value] > 1))
        .collect()
}

/// Passes when nobody breaks the rule, else fails naming who does.
fn named_failure(
    id: &'static str,
    breaking: &[&SlotMember],
    name: impl Fn(&SlotMember) -> String,
    detail: Option<String>,
) -> CheckResult {
    CheckResult {
        id,
        result: outcome(breaking.is_empty()),
        names: breaking.iter().map(|member| name(member)).collect(),
        detail: if breaking.is_empty() { None } else { detail },
    }
}

/// Add a remote member's node to this Home's peers, from its card.
fn register_record(data_dir: &Path, member: &PoolMemberRecordV1) -> anyhow::Result<()> {
    let Some(text) = &member.card else {
        // This Home's own node has no peer entry.
        return Ok(());
    };
    let card = parse_node_card(text)
        .map_err(|refusal| anyhow::anyhow!("kept node card is refused: {}", refusal.code()))?;
    let did =
        peer_did(&card.descriptor.transport).context("kept node card has no Carrier route")?;
    upsert_peer(
        data_dir,
        OperatorPeer {
            did,
            label: member.run_by.clone(),
            connect_ticket: card.ticket,
            allow: Vec::new(),
            provides: card.provides,
            ipfs_peer: card.ipfs_peer_id.map(|id| OperatorPeerIpfs {
                id,
                addrs: Vec::new(),
            }),
        },
    )?;
    tracing::debug!(share = member.share, "custody pool node registered");
    Ok(())
}

/// Keep the members beside the pool. The pool is already installed and
/// verified, so a failure here costs only names in the Active view.
fn write_members_record(data_dir: &Path, config_sha256: &str, members: &[PoolMemberRecordV1]) {
    let record = PoolMembersRecordV1 {
        schema: POOL_MEMBERS_SCHEMA_V1.to_string(),
        config_sha256: config_sha256.to_string(),
        members: members.to_vec(),
    };
    let written = serde_json::to_vec(&record)
        .map_err(anyhow::Error::from)
        .and_then(|bytes| {
            create_owner_only_file(&pool_members_path(data_dir), &bytes, "custody pool members")
        });
    if let Err(error) = written {
        tracing::warn!(error = %format!("{error:#}"), "custody pool members were not recorded");
    }
}

/// The members record for this pool file, if one was kept for it.
fn read_members_record(data_dir: &Path, config_sha256: &str) -> Option<PoolMembersRecordV1> {
    let record = match load_members_record(data_dir) {
        Ok(record) => record?,
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "custody pool members are unreadable");
            return None;
        }
    };
    if record.schema != POOL_MEMBERS_SCHEMA_V1 || record.config_sha256 != config_sha256 {
        tracing::debug!("custody pool members belong to another pool file");
        return None;
    }
    Some(record)
}

/// Item 10 (Plan B T4.3): the connect ticket for each member of this Home's
/// installed pool, by the member's Carrier peer DID, chosen as pool health
/// chooses it: the operator's peer entry first, then the member card this
/// Home kept (lead ruling C1). Pool descriptors carry no tickets; every
/// other route goes through Carrier discovery. Only the owner that formed
/// the pool from cards keeps them, so any other Home gets an empty map.
pub(crate) fn kept_card_tickets(data_dir: &Path) -> BTreeMap<String, String> {
    let pool = match installed_pool(data_dir) {
        Ok(Some(pool)) => pool,
        Ok(None) => return BTreeMap::new(),
        Err(error) => {
            tracing::debug!(error = %format!("{error:#}"), "no kept custody member cards");
            return BTreeMap::new();
        }
    };
    let record = read_members_record(data_dir, &pool.config_sha256);
    let peers = operator_peers_or_warn(data_dir);
    pool.nodes
        .iter()
        .filter_map(|node| {
            let peer_did = node.peer_did.clone()?;
            member_ticket(record.as_ref(), &peers, node).map(|ticket| (peer_did, ticket))
        })
        .collect()
}

/// With no pool file, a members record belongs to a pool removed by hand; it
/// would block the new pool's create-only record.
fn remove_stale_members_record(data_dir: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(pool_members_path(data_dir)) {
        Ok(()) => {
            tracing::debug!("stale custody pool members record removed");
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(anyhow::Error::new(error).context("stale custody pool members cannot be removed"))
        }
    }
}

fn load_members_record(data_dir: &Path) -> anyhow::Result<Option<PoolMembersRecordV1>> {
    let path = pool_members_path(data_dir);
    if !path_present(&path)? {
        return Ok(None);
    }
    let bytes = read_owner_only_file(&path, MAX_POOL_MEMBERS_FILE_BYTES, "custody pool members")?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

/// The pool the Runtime loader accepts, with the facts the Active view shows.
fn installed_pool(data_dir: &Path) -> anyhow::Result<Option<InstalledPool>> {
    let Some(composition) =
        load_runtime_custody_composition(data_dir, Arc::new(ProviderRegistry::new()))?
    else {
        return Ok(None);
    };
    // Routes are read from the file the loader just accepted, as
    // `verify-custody-composition` reports them.
    let config_bytes = read_owner_only_file(
        &runtime_custody_composition_config_path(data_dir),
        MAX_CUSTODY_COMPOSITION_FILE_BYTES,
        "custody composition",
    )?;
    let config: RuntimeCustodyCompositionConfigFile = serde_json::from_slice(&config_bytes)?;
    let config_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&config_bytes)));

    let epoch = composition.signed_epoch().statement();
    let pool_members = composition.signed_pool().statement().members();
    let start = pool_members
        .iter()
        .map(|member| member.valid_from())
        .max()
        .context("installed custody pool has no members")?;
    let end = pool_members
        .iter()
        .map(|member| member.valid_until())
        .min()
        .context("installed custody pool has no members")?;
    let nodes = epoch
        .nodes()
        .iter()
        .map(|node| {
            let key_base64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                node.node_public_key().as_bytes(),
            );
            let route = config
                .routes
                .iter()
                .find(|route| route.node_public_key_base64 == key_base64)
                .context("installed custody pool has a node without a route")?;
            Ok(InstalledNode {
                share: node.share_coordinate().get(),
                node_public_key_hex: format!(
                    "0x{}",
                    hex::encode(node.node_public_key().as_bytes())
                ),
                peer_did: peer_did(&route.transport),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(Some(InstalledPool {
        fingerprint: pool_fingerprint(&config_sha256)?,
        config_sha256,
        threshold: ThresholdView {
            required: epoch.threshold().required(),
            total: epoch.threshold().total(),
        },
        term: TermView {
            start,
            end,
            days: end.saturating_sub(start) / SECONDS_PER_DAY,
        },
        nodes,
    }))
}

/// A pool's fingerprint, from the `sha256:<hex>` its receipts report.
fn pool_fingerprint(config_sha256: &str) -> anyhow::Result<Fingerprint> {
    let digest: [u8; 32] = config_sha256
        .strip_prefix("sha256:")
        .and_then(|hex_digest| hex::decode(hex_digest).ok())
        .and_then(|bytes| bytes.try_into().ok())
        .context("custody pool digest is malformed")?;
    Ok(Fingerprint::of_digest(&digest))
}

fn node_public_key_hex(descriptor: &ValidatedCustodyNodeDescriptor) -> String {
    format!("0x{}", hex::encode(descriptor.node_public_key.as_bytes()))
}

fn peer_did(transport: &RuntimeCustodyRouteTransportConfig) -> Option<String> {
    match transport {
        RuntimeCustodyRouteTransportConfig::CarrierPeerDid { peer_did } => Some(peer_did.clone()),
        RuntimeCustodyRouteTransportConfig::Local => None,
    }
}

fn path_present(path: &Path) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(anyhow::Error::new(error).context("custody file is unavailable")),
    }
}

#[cfg(all(test, unix))]
pub(crate) mod tests {
    use super::*;
    use crate::custody_node_card::tests::{
        card_for_device, labelled_card, local_descriptor_bytes, TEST_IPFS_PEER_ID,
    };
    use crate::protected_content_config::tests::{
        install_successful_provision_script, owner_only_dir, safe_ancestor_tempdir,
    };
    use crate::protected_content_config::{
        distinct_custody_node_descriptors, install_custody_composition,
        validated_custody_node_descriptor,
    };

    const STORAGE: &[&str] = &["chain", "custody", "ipfs"];
    const CUSTODY_ONLY: &[&str] = &["chain", "custody"];

    fn data_dir(dir: &tempfile::TempDir) -> PathBuf {
        let data_dir = dir.path().join("data");
        owner_only_dir(&data_dir);
        // #388 A1: these Homes host custody, so they are WCI-operated.
        crate::host_trust::seed_for_test(&data_dir, true);
        data_dir
    }

    fn remote(text: &str) -> CardInput {
        CardInput::Remote {
            text: text.to_string(),
        }
    }

    fn ids(results: &[CheckResult]) -> Vec<&'static str> {
        results.iter().map(|result| result.id).collect()
    }

    fn result<'a>(results: &'a [CheckResult], id: &str) -> &'a CheckResult {
        results
            .iter()
            .find(|result| result.id == id)
            .unwrap_or_else(|| panic!("no {id} result in {results:?}"))
    }

    fn refusal(error: &anyhow::Error) -> &CustodyRefusal {
        error
            .downcast_ref::<CustodyRefusal>()
            .unwrap_or_else(|| panic!("expected a custody refusal, got {error:#}"))
    }

    fn peer_did(card: &str) -> String {
        match crate::custody_node_card::parse_node_card(card)
            .unwrap()
            .descriptor
            .transport
        {
            RuntimeCustodyRouteTransportConfig::CarrierPeerDid { peer_did } => peer_did,
            RuntimeCustodyRouteTransportConfig::Local => panic!("cards route over Carrier"),
        }
    }

    /// This Home's node as Include leaves it: the node file and a custody root
    /// that trusts this Home's own Runtime and holds the node's keys. Root
    /// files already there stay.
    pub(crate) fn write_included_node(data_dir: &Path, run_by: &str, location: &str) {
        write_included_node_seeded(data_dir, 0x5a, run_by, location);
    }

    /// [`write_included_node`] with the node signing key of fixture seed
    /// `seed` (`test_fixtures::signing_key`), so a fixture pool can name it.
    pub(crate) fn write_included_node_seeded(
        data_dir: &Path,
        seed: u8,
        run_by: &str,
        location: &str,
    ) {
        use x_wing::kem::Decapsulator as _;
        use x_wing::KeyExport as _;

        elastos_identity::load_or_create_device_key(data_dir).unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let custody_secret = [seed ^ 0x11; x_wing::DECAPSULATION_KEY_SIZE];
        let custody_public = elastos_protected_content_contracts::NodeCustodyPublicKeyV1::new(
            x_wing::DecapsulationKey::from(custody_secret)
                .encapsulation_key()
                .to_bytes()
                .into(),
        )
        .unwrap();
        let descriptor = crate::protected_content_config::CustodyNodeDescriptorV1 {
            schema: crate::protected_content_config::CUSTODY_NODE_DESCRIPTOR_SCHEMA_V1.to_string(),
            node_public_key_hex: format!("0x{}", hex::encode(signing.verifying_key().to_bytes())),
            node_custody_public_key_hex: format!("0x{}", hex::encode(custody_public.as_bytes())),
            operator: run_by.to_string(),
            failure_domain: location.to_string(),
            transport: crate::protected_content_config::CustodyNodeDescriptorTransportV1::Local,
        };
        ensure_owner_only_dir(&protected_content_root(data_dir), "protected-content root").unwrap();
        create_owner_only_file(
            &local_node_path(data_dir),
            &serde_json::to_vec(&serde_json::to_value(&descriptor).unwrap()).unwrap(),
            "test local node",
        )
        .unwrap();
        let root = inactive_root(data_dir);
        ensure_owner_only_dir(root.parent().unwrap(), "test custody dir").unwrap();
        ensure_owner_only_dir(&root, "test custody root").unwrap();
        ensure_owner_only_dir(&root.join("data"), "test custody data").unwrap();
        for (name, value) in [
            (
                "trusted-runtime-issuer",
                runtime_issuer_hex(data_dir).unwrap(),
            ),
            (
                "node-signing-key",
                format!("0x{}", hex::encode(signing.to_bytes())),
            ),
            (
                "node-custody-secret",
                format!("0x{}", hex::encode(custody_secret)),
            ),
        ] {
            if !root.join(name).exists() {
                create_owner_only_file(&root.join(name), value.as_bytes(), "test custody key")
                    .unwrap();
            }
        }
    }

    pub(crate) fn write_local_node(data_dir: &Path, run_by: &str, location: &str) {
        ensure_owner_only_dir(&protected_content_root(data_dir), "protected-content root").unwrap();
        create_owner_only_file(
            &local_node_path(data_dir),
            &local_descriptor_bytes(run_by, location),
            "test local node",
        )
        .unwrap();
    }

    const RULE_IDS: [&str; 8] = [
        "members",
        "keys",
        "homes",
        "run_by",
        "location",
        "this_home",
        "roles",
        "copies",
    ];

    #[test]
    fn check_reports_each_rule_with_slot_names() {
        let dir = tempfile::tempdir().unwrap();
        let results = check(
            dir.path(),
            &[
                remote(&labelled_card("Alice", "Lisbon", STORAGE)),
                remote(&labelled_card("Bob", "Lisbon", STORAGE)),
                remote(&labelled_card("Carol", "Kyiv", &["custody"])),
            ],
        );
        assert_eq!(ids(&results), RULE_IDS);

        let location = result(&results, "location");
        assert_eq!(location.result, CheckOutcome::Fail);
        assert_eq!(location.names, ["Alice", "Bob"]);
        assert_eq!(location.detail.as_deref(), Some("Lisbon"));

        let roles = result(&results, "roles");
        assert_eq!(roles.result, CheckOutcome::Fail);
        assert_eq!(roles.names, ["Carol"]);
        assert_eq!(roles.detail.as_deref(), Some("chain"));

        let members = result(&results, "members");
        assert_eq!(members.result, CheckOutcome::Pass);
        assert_eq!(members.names, ["Alice", "Bob", "Carol"]);
        for id in ["keys", "homes", "run_by", "this_home"] {
            assert_eq!(result(&results, id).result, CheckOutcome::Pass, "{id}");
        }
        let copies = result(&results, "copies");
        assert_eq!(copies.result, CheckOutcome::Pass);
        assert_eq!(copies.names, ["Alice", "Bob"]);

        // Live checks start from two slots: too few members fail. The
        // creator's Home holds the one required copy, so no remote copy is
        // needed.
        let results = check(
            dir.path(),
            &[
                remote(&labelled_card("Alice", "Lisbon", STORAGE)),
                remote(&labelled_card("Alice", "Oslo", CUSTODY_ONLY)),
            ],
        );
        let members = result(&results, "members");
        assert_eq!(members.result, CheckOutcome::Fail);
        assert_eq!(members.names.len(), 2);
        let run_by = result(&results, "run_by");
        assert_eq!(run_by.result, CheckOutcome::Fail);
        assert_eq!(run_by.names, ["Lisbon", "Oslo"]);
        assert_eq!(run_by.detail.as_deref(), Some("Alice"));
        let copies = result(&results, "copies");
        assert_eq!(copies.result, CheckOutcome::Pass);
        assert_eq!(copies.names, ["Alice"]);
    }

    #[test]
    fn check_flags_duplicate_card() {
        let dir = tempfile::tempdir().unwrap();
        let alice = labelled_card("Alice", "Lisbon", STORAGE);
        // The same card again, as an email client wraps it.
        let wrapped = alice
            .as_bytes()
            .chunks(76)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n");
        let results = check(
            dir.path(),
            &[
                remote(&alice),
                remote(&labelled_card("Bob", "Oslo", STORAGE)),
                remote(&wrapped),
            ],
        );
        assert_eq!(
            results[0],
            CheckResult {
                id: "duplicate",
                result: CheckOutcome::Fail,
                names: vec!["1".to_string(), "3".to_string()],
                detail: None,
            }
        );
        assert_eq!(ids(&results[1..]), RULE_IDS);
        assert_eq!(result(&results, "members").names, ["Alice", "Bob"]);

        let results = check(dir.path(), &[remote("hello"), CardInput::ThisHome]);
        assert_eq!(
            results[..2],
            [
                CheckResult {
                    id: "card",
                    result: CheckOutcome::Fail,
                    names: vec!["1".to_string()],
                    detail: Some("not_a_card".to_string()),
                },
                CheckResult {
                    id: "card",
                    result: CheckOutcome::Fail,
                    names: vec!["2".to_string()],
                    detail: Some("local_node_missing".to_string()),
                },
            ]
        );
    }

    #[tokio::test]
    async fn install_refuses_second_pool_and_registers_nothing() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        create_signing_key(&data_dir).unwrap();
        let cards = [
            remote(&labelled_card("Alice", "Lisbon", STORAGE)),
            remote(&labelled_card("Bob", "Oslo", STORAGE)),
            remote(&labelled_card("Carol", "Kyiv", CUSTODY_ONLY)),
        ];
        install(&data_dir, &cards, 365).await.unwrap();
        let pool_path = runtime_custody_composition_config_path(&data_dir);
        let peers_path = crate::operator_control::operator_control_path(&data_dir);
        let pool = std::fs::read(&pool_path).unwrap();
        let peers = std::fs::read(&peers_path).unwrap();

        let others = [
            remote(&labelled_card("Dan", "Rome", STORAGE)),
            remote(&labelled_card("Eve", "Riga", STORAGE)),
            remote(&labelled_card("Fay", "Pune", STORAGE)),
        ];
        let error = install(&data_dir, &others, 365).await.unwrap_err();
        assert_eq!(refusal(&error).code(), "already_installed");
        assert_eq!(std::fs::read(&pool_path).unwrap(), pool);
        assert_eq!(std::fs::read(&peers_path).unwrap(), peers);
    }

    #[tokio::test]
    async fn summary_reports_an_installed_pool_the_loader_refuses() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        create_signing_key(&data_dir).unwrap();
        let cards = [
            remote(&labelled_card("Alice", "Lisbon", STORAGE)),
            remote(&labelled_card("Bob", "Oslo", STORAGE)),
            remote(&labelled_card("Carol", "Kyiv", CUSTODY_ONLY)),
        ];
        install(&data_dir, &cards, 365).await.unwrap();
        let shown = summary(&data_dir, None, None, None).await;
        assert!(shown.pool_installed && shown.pool.is_some() && shown.pool_problem.is_none());

        // Flip one character of the signed pool, keeping the file owner-only.
        let pool_path = runtime_custody_composition_config_path(&data_dir);
        let mut bytes = std::fs::read(&pool_path).unwrap();
        let marker = b"\"signed_pool_base64\":\"";
        let at = bytes
            .windows(marker.len())
            .position(|window| window == marker)
            .unwrap()
            + marker.len();
        bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
        std::fs::remove_file(&pool_path).unwrap();
        create_owner_only_file(&pool_path, &bytes, "test custody pool").unwrap();

        let shown = summary(&data_dir, None, None, None).await;
        assert!(shown.pool_installed);
        assert!(shown.pool.is_none());
        let problem = shown
            .pool_problem
            .expect("a refused pool reports its problem");
        assert_eq!(problem.code, "verify_failed");
        assert!(problem.detail.is_some());
        let error = install(&data_dir, &cards, 365).await.unwrap_err();
        assert_eq!(refusal(&error).code(), "already_installed");
    }

    /// Item 10 (Plan B T4.3): the owner keeps each remote member's card
    /// ticket by its peer DID; before a pool is installed there is none.
    #[tokio::test]
    async fn kept_card_tickets_name_each_carded_member_by_peer_did() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        assert!(kept_card_tickets(&data_dir).is_empty());
        create_signing_key(&data_dir).unwrap();
        let texts = [
            labelled_card("Alice", "Lisbon", STORAGE),
            labelled_card("Bob", "Oslo", STORAGE),
            labelled_card("Carol", "Kyiv", CUSTODY_ONLY),
        ];
        let cards = texts.iter().map(|text| remote(text)).collect::<Vec<_>>();
        install(&data_dir, &cards, 365).await.unwrap();

        let kept = kept_card_tickets(&data_dir);
        assert_eq!(kept.len(), texts.len());
        for text in &texts {
            assert_eq!(
                kept.get(&peer_did(text)),
                Some(&parse_node_card(text).unwrap().ticket)
            );
        }

        // Lead ruling C1: the operator's peer entry comes before the kept
        // card, as in pool health.
        let alice = peer_did(&texts[0]);
        let entry_ticket = parse_node_card(&labelled_card("Dave", "Rome", STORAGE))
            .unwrap()
            .ticket;
        upsert_peer(
            &data_dir,
            OperatorPeer {
                did: alice.clone(),
                connect_ticket: entry_ticket.clone(),
                ..OperatorPeer::default()
            },
        )
        .unwrap();
        let kept = kept_card_tickets(&data_dir);
        assert_eq!(kept.len(), texts.len());
        assert_eq!(kept.get(&alice), Some(&entry_ticket));
        for text in &texts[1..] {
            assert_eq!(
                kept.get(&peer_did(text)),
                Some(&parse_node_card(text).unwrap().ticket)
            );
        }
    }

    #[tokio::test]
    async fn install_replaces_a_stale_members_record() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        create_signing_key(&data_dir).unwrap();
        // Left behind by a pool removed by hand.
        let stale = PoolMembersRecordV1 {
            schema: POOL_MEMBERS_SCHEMA_V1.to_string(),
            config_sha256: format!("sha256:{}", "0".repeat(64)),
            members: Vec::new(),
        };
        create_owner_only_file(
            &pool_members_path(&data_dir),
            &serde_json::to_vec(&stale).unwrap(),
            "test custody pool members",
        )
        .unwrap();

        let cards = [
            remote(&labelled_card("Alice", "Lisbon", STORAGE)),
            remote(&labelled_card("Bob", "Oslo", STORAGE)),
            remote(&labelled_card("Carol", "Kyiv", CUSTODY_ONLY)),
        ];
        install(&data_dir, &cards, 365).await.unwrap();
        let pool = installed_pool(&data_dir).unwrap().unwrap();
        let record = load_members_record(&data_dir).unwrap().unwrap();
        assert_eq!(record.config_sha256, pool.config_sha256);
        assert_eq!(record.members.len(), pool.nodes.len());
        let read = read_pool(&data_dir).unwrap().unwrap();
        assert!(read.members.iter().all(|member| member.location.is_some()));
        register_member(&data_dir, pool.nodes[0].share).unwrap();
    }

    #[tokio::test]
    async fn install_refuses_failed_checks_and_writes_nothing() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        let cards = [
            remote(&labelled_card("Alice", "Lisbon", STORAGE)),
            remote(&labelled_card("Bob", "Lisbon", STORAGE)),
            remote(&labelled_card("Carol", "Kyiv", STORAGE)),
        ];
        let error = install(&data_dir, &cards, 365).await.unwrap_err();
        assert_eq!(refusal(&error).code(), "no_signing_key");

        create_signing_key(&data_dir).unwrap();
        let error = install(&data_dir, &cards, 365).await.unwrap_err();
        let refused = refusal(&error);
        assert_eq!(refused.code(), "checks_failed");
        assert_eq!(refused.detail(), Some("location"));
        assert!(!runtime_custody_composition_config_path(&data_dir).exists());
        assert!(!crate::operator_control::operator_control_path(&data_dir).exists());
    }

    #[tokio::test]
    async fn install_rolls_back_and_registers_nothing_when_loader_rejects() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        let cards = [
            remote(&labelled_card("Alice", "Lisbon", STORAGE)),
            remote(&labelled_card("Bob", "Oslo", STORAGE)),
            remote(&labelled_card("Carol", "Kyiv", CUSTODY_ONLY)),
        ];
        let nothing_written = |data_dir: &Path| {
            assert!(!runtime_custody_composition_config_path(data_dir).exists());
            assert!(!pool_members_path(data_dir).exists());
            assert!(!crate::operator_control::operator_control_path(data_dir).exists());
        };

        // Before the pool file: a signing key of the wrong length.
        ensure_owner_only_dir(&protected_content_root(&data_dir), "protected-content root")
            .unwrap();
        create_owner_only_file(
            &policy_authority_key_path(&data_dir),
            &[7; 31],
            "test signing key",
        )
        .unwrap();
        let error = install(&data_dir, &cards, 365).await.unwrap_err();
        assert_eq!(refusal(&error).code(), "install_failed");
        nothing_written(&data_dir);

        // After the pool file: signing and the committee rules accept a term
        // that ends now, and only the Runtime loader refuses it as expired.
        std::fs::remove_file(policy_authority_key_path(&data_dir)).unwrap();
        create_signing_key(&data_dir).unwrap();
        let error = install(&data_dir, &cards, 0).await.unwrap_err();
        let refused = refusal(&error);
        assert_eq!(refused.code(), "install_failed");
        assert!(
            refused
                .detail()
                .is_some_and(|detail| detail.contains("loader validation")),
            "{error:#}"
        );
        nothing_written(&data_dir);
    }

    #[tokio::test]
    async fn install_registers_remote_members_with_ticket_and_ipfs_peer() {
        use std::os::unix::fs::PermissionsExt;

        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        create_signing_key(&data_dir).unwrap();
        write_included_node(&data_dir, "Home", "Paris");
        let alice = labelled_card("Alice", "Lisbon", STORAGE);
        let bob = labelled_card("Bob", "Oslo", CUSTODY_ONLY);
        let cards = [CardInput::ThisHome, remote(&alice), remote(&bob)];
        let check_results = check(&data_dir, &cards);
        assert!(
            check_results
                .iter()
                .all(|result| result.result != CheckOutcome::Fail),
            "{check_results:?}"
        );

        let installed = install(&data_dir, &cards, 365).await.unwrap();
        assert!(installed.verified);
        assert_eq!(installed.registered.len(), 2, "{:?}", installed.registered);
        assert!(installed.registered.iter().all(|entry| entry.ok));

        let peers = load_operator_control(&data_dir).unwrap().peers;
        assert_eq!(peers.len(), 2);
        for (card, run_by) in [(&alice, "Alice"), (&bob, "Bob")] {
            let parsed = crate::custody_node_card::parse_node_card(card).unwrap();
            let peer = peers
                .iter()
                .find(|peer| peer.did == peer_did(card))
                .unwrap();
            assert_eq!(peer.label, run_by);
            assert_eq!(peer.connect_ticket, parsed.ticket);
            assert_eq!(peer.provides, parsed.provides);
            assert!(peer.allow.is_empty());
            assert_eq!(
                peer.ipfs_peer,
                parsed.ipfs_peer_id.map(|id| OperatorPeerIpfs {
                    id,
                    addrs: Vec::new()
                })
            );
        }
        let alice_peer = peers
            .iter()
            .find(|peer| peer.did == peer_did(&alice))
            .unwrap();
        assert_eq!(
            alice_peer.ipfs_peer.as_ref().map(|ipfs| ipfs.id.as_str()),
            Some(TEST_IPFS_PEER_ID)
        );
        let mode = std::fs::metadata(pool_members_path(&data_dir))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        let pool = read_pool(&data_dir).unwrap().unwrap();
        assert_eq!(
            pool.threshold,
            ThresholdView {
                required: CUSTODY_THRESHOLD_REQUIRED,
                total: CUSTODY_THRESHOLD_TOTAL,
            }
        );
        assert_eq!(pool.term.days, 365);
        assert_eq!(pool.fingerprint, installed.fingerprint);
        assert!(pool.cards_kept);
        let shares: Vec<u8> = pool.members.iter().map(|member| member.share).collect();
        assert_eq!(shares, (1..=CUSTODY_THRESHOLD_TOTAL).collect::<Vec<_>>());
        for (run_by, location, this_home) in [
            ("Home", "Paris", true),
            ("Alice", "Lisbon", false),
            ("Bob", "Oslo", false),
        ] {
            let member = pool
                .members
                .iter()
                .find(|member| member.run_by.as_deref() == Some(run_by))
                .unwrap();
            assert_eq!(member.location.as_deref(), Some(location));
            assert_eq!(member.this_home, this_home);
            assert_eq!(member.home_id.is_none(), this_home);
            assert!(member.registered);
        }

        assert_eq!(
            verify(&data_dir).unwrap().fingerprint,
            installed.fingerprint
        );
        let bob_share = pool
            .members
            .iter()
            .find(|member| member.run_by.as_deref() == Some("Bob"))
            .unwrap()
            .share;
        register_member(&data_dir, bob_share).unwrap();
        let error = register_member(&data_dir, CUSTODY_THRESHOLD_TOTAL + 1).unwrap_err();
        assert_eq!(refusal(&error).code(), "unknown_share");
        assert_eq!(
            summary(&data_dir, None, None, None)
                .await
                .pool
                .unwrap()
                .fingerprint,
            pool.fingerprint
        );
    }

    #[tokio::test]
    async fn pool_read_names_members_from_peer_labels_without_members_record() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        create_signing_key(&data_dir).unwrap();
        let cards = [
            labelled_card("Alice", "Lisbon", STORAGE),
            labelled_card("Bob", "Oslo", STORAGE),
            labelled_card("Carol", "Kyiv", CUSTODY_ONLY),
        ];
        // The terminal route: generate-custody-composition, then
        // `node peer add` for two of the three nodes.
        let descriptors = cards
            .iter()
            .map(|card| {
                let parsed = crate::custody_node_card::parse_node_card(card).unwrap();
                validated_custody_node_descriptor(&parsed.node_bytes, "test card").unwrap()
            })
            .collect();
        install_custody_composition(
            &data_dir,
            &policy_authority_key_path(&data_dir),
            distinct_custody_node_descriptors(descriptors).unwrap(),
            365,
        )
        .unwrap();
        for (card, label) in [(&cards[0], "alice-node"), (&cards[1], "bob-node")] {
            crate::operator_control::upsert_peer(
                &data_dir,
                OperatorPeer {
                    did: peer_did(card),
                    label: label.to_string(),
                    ..OperatorPeer::default()
                },
            )
            .unwrap();
        }

        let pool = read_pool(&data_dir).unwrap().unwrap();
        assert!(!pool.cards_kept, "no cards were kept for Register again");
        let member = |card: &str| {
            let did = peer_did(card);
            pool.members
                .iter()
                .find(|member| member.home_id.as_deref() == Some(did.as_str()))
                .unwrap()
                .clone()
        };
        let alice = member(&cards[0]);
        assert_eq!(alice.run_by.as_deref(), Some("alice-node"));
        assert_eq!(alice.location, None);
        assert!(alice.registered);
        let carol = member(&cards[2]);
        assert_eq!(carol.run_by, None);
        assert!(!carol.registered);

        let error = register_member(&data_dir, carol.share).unwrap_err();
        assert_eq!(refusal(&error).code(), "no_card");
    }

    #[tokio::test]
    async fn everyday_home_include_refuses_host_trust_required() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        crate::host_trust::seed_for_test(&data_dir, false);
        let write = crate::custody_consent::lock_custody_writes().await;
        let error = include_local_node(&write, &data_dir, None, "Home", "Paris")
            .await
            .unwrap_err();
        assert_eq!(refusal(&error).code(), "host_trust_required");
        assert!(!local_node_path(&data_dir).exists());
        assert!(!include_marker_path(&data_dir).exists());
    }

    /// A388-I1: the setting is captured at startup, not at the first Include
    /// or Offer. An everyday Home that boots with no custody roots (so no
    /// custody provider registers) and then has its file switched to
    /// WCI-operated still refuses both until a restart.
    #[tokio::test]
    async fn host_trust_is_captured_at_startup_not_on_first_include_or_offer() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        crate::host_trust::restart_for_test(&data_dir);
        crate::host_trust::capture_at_startup(&data_dir);
        crate::host_trust::write_host_trust(
            &data_dir,
            crate::host_trust::HostTrustModeV1::WciOperated,
            Some(1 << 30),
        )
        .unwrap();

        let write = crate::custody_consent::lock_custody_writes().await;
        let error = include_local_node(&write, &data_dir, None, "Home", "Paris")
            .await
            .unwrap_err();
        assert_eq!(refusal(&error).code(), "host_trust_required");
        let error =
            crate::custody_consent::set_offer(&write, &data_dir, None, true, "Home", "Paris")
                .unwrap_err();
        assert_eq!(refusal(&error).code(), "host_trust_required");
        assert!(!local_node_path(&data_dir).exists());
        drop(write);

        // The next clean start reads it.
        crate::host_trust::restart_for_test(&data_dir);
        crate::host_trust::capture_at_startup(&data_dir);
        assert!(crate::host_trust::host_trusted(&data_dir));

        // The Runtime's startup captures it first, before anything is
        // served and outside every provider branch.
        const SERVER_INFRA: &str = include_str!("server_infra.rs");
        let boot = SERVER_INFRA
            .find("async fn setup_server_infrastructure_impl(")
            .unwrap();
        let capture = SERVER_INFRA[boot..]
            .find("capture_host_trust_at_startup(&data_dir)")
            .expect("startup captures the host trust setting");
        let first_service = SERVER_INFRA[boot..]
            .find("serve_capability_store(&data_dir)")
            .unwrap();
        assert!(
            capture < first_service,
            "captured before any request is served"
        );
    }

    #[tokio::test]
    async fn include_local_node_without_provider_reports_reason_and_writes_nothing() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        elastos_identity::load_or_create_device_key(&data_dir).unwrap();

        let write = crate::custody_consent::lock_custody_writes().await;
        let error = include_local_node(&write, &data_dir, None, " Home", "Paris")
            .await
            .unwrap_err();
        assert_eq!(refusal(&error).code(), "bad_labels");

        let error = include_local_node(&write, &data_dir, None, "Home", "Paris")
            .await
            .unwrap_err();
        let refused = refusal(&error);
        assert_eq!(refused.code(), "provision_failed");
        assert_eq!(
            refused.detail(),
            Some("verified custody provider binary is unavailable")
        );
        assert!(!local_node_path(&data_dir).exists());
        assert!(!include_marker_path(&data_dir).exists());
        assert!(
            !summary(&data_dir, None, None, None)
                .await
                .local_node
                .provisioned
        );
    }

    /// Stands in for a custody provider the Runtime already serves.
    struct ReadyCustodyProvider;

    #[async_trait::async_trait]
    impl elastos_runtime::provider::Provider for ReadyCustodyProvider {
        async fn handle(
            &self,
            _request: elastos_runtime::provider::ResourceRequest,
        ) -> Result<
            elastos_runtime::provider::ResourceResponse,
            elastos_runtime::provider::ProviderError,
        > {
            Err(elastos_runtime::provider::ProviderError::Provider(
                "test provider".to_string(),
            ))
        }

        fn schemes(&self) -> Vec<&'static str> {
            Vec::new()
        }

        fn name(&self) -> &'static str {
            "ready-custody"
        }
    }

    #[tokio::test]
    async fn include_local_node_provisions_once_and_registers_live() {
        use std::os::unix::fs::PermissionsExt;

        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        let issuer = runtime_issuer_hex(&data_dir).unwrap();
        install_successful_provision_script(dir.path(), &data_dir, &issuer, 0x61);

        let write = crate::custody_consent::lock_custody_writes().await;
        let included = include_local_node(&write, &data_dir, None, "Home", "Paris")
            .await
            .unwrap();
        assert!(included.node.provisioned);
        assert_eq!(included.node.run_by.as_deref(), Some("Home"));
        assert_eq!(included.node.location.as_deref(), Some("Paris"));
        assert!(included.needs_restart, "no live Runtime to register with");
        assert!(!included.node.running);
        let mode = std::fs::metadata(local_node_path(&data_dir))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(
            summary(&data_dir, None, None, None).await.local_node,
            included.node
        );
        // A local route is never fetched, so this Home holds no node card.
        assert!(!crate::protected_content_config::custody_node_descriptor_path(&data_dir).exists());

        // Included again, the node keeps its keys and labels: nothing is
        // provisioned, so a missing provider no longer matters.
        std::fs::remove_file(data_dir.join("components.json")).unwrap();
        let registry = Arc::new(ProviderRegistry::new());
        // After a reload the summary still tells a node that is not serving.
        assert!(
            !summary(&data_dir, Some(&registry), None, None)
                .await
                .local_node
                .running
        );
        registry
            .register_runtime_provider_target(CUSTODY_PROVIDER_ID, Arc::new(ReadyCustodyProvider))
            .await
            .unwrap();
        let again = include_local_node(&write, &data_dir, Some(&registry), "Other", "Rome")
            .await
            .unwrap();
        assert_eq!(
            again.node,
            LocalNodeSummary {
                running: true,
                ..included.node
            }
        );
        assert!(!again.needs_restart);
        assert_eq!(
            summary(&data_dir, Some(&registry), None, None)
                .await
                .local_node,
            again.node
        );
    }

    /// A custody root, or the tombstone a removal renames it to, that a
    /// stopped removal left without its trusted issuer.
    fn half_removed_root(data_dir: &Path, root: &Path) {
        ensure_owner_only_dir(&protected_content_root(data_dir), "protected-content root").unwrap();
        ensure_owner_only_dir(root.parent().unwrap(), "test custody dir").unwrap();
        ensure_owner_only_dir(root, "test custody root").unwrap();
        create_owner_only_file(&root.join("node-signing-key"), &[7; 32], "test key").unwrap();
    }

    fn inactive_root(data_dir: &Path) -> PathBuf {
        crate::protected_content_runtime::inactive_custody_state_root(data_dir)
    }

    #[tokio::test]
    async fn remove_local_node_deletes_the_included_node_before_install() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        let issuer = runtime_issuer_hex(&data_dir).unwrap();
        install_successful_provision_script(dir.path(), &data_dir, &issuer, 0x62);
        let write = crate::custody_consent::lock_custody_writes().await;
        include_local_node(&write, &data_dir, None, "Home", "Paris")
            .await
            .unwrap();
        let root = inactive_root(&data_dir);
        assert!(root.is_dir());
        assert!(holds_custody_state(&data_dir).unwrap());
        let registry = Arc::new(ProviderRegistry::new());
        registry
            .register_runtime_provider_target(CUSTODY_PROVIDER_ID, Arc::new(ReadyCustodyProvider))
            .await
            .unwrap();

        let removed = remove_local_node(&write, &data_dir, Some(&registry))
            .await
            .unwrap();
        assert!(!removed.provisioned);
        assert!(!local_node_path(&data_dir).exists());
        assert!(!root.exists());
        assert!(!removal_tombstone(&data_dir, "inactive").exists());
        assert!(
            !registry
                .has_ready_runtime_provider_target(CUSTODY_PROVIDER_ID)
                .await,
            "the removed node's provider no longer serves"
        );
        // This Home holds no custody state, so it may offer custody again.
        assert!(!holds_custody_state(&data_dir).unwrap());
        assert!(
            !summary(&data_dir, Some(&registry), None, None)
                .await
                .local_node
                .provisioned
        );
        // Removing again finds nothing to remove.
        let error = remove_local_node(&write, &data_dir, Some(&registry))
            .await
            .unwrap_err();
        assert_eq!(refusal(&error).code(), "no_local_node");
    }

    #[tokio::test]
    async fn remove_local_node_keeps_a_node_an_installed_pool_or_another_owner_uses() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        let write = crate::custody_consent::lock_custody_writes().await;
        write_local_node(&data_dir, "Home", "Paris");
        let pool = runtime_custody_composition_config_path(&data_dir);
        create_owner_only_file(&pool, b"{}", "test pool").unwrap();
        let error = remove_local_node(&write, &data_dir, None)
            .await
            .unwrap_err();
        assert_eq!(refusal(&error).code(), "pool_installed");
        assert!(local_node_path(&data_dir).exists());

        std::fs::remove_file(&pool).unwrap();
        // Plan B T2.2 (removal approved 2026-11-12 10:35): a served node no
        // longer blocks Remove of this Home's own node; the served node stays.
        let served = crate::protected_content_config::custody_node_descriptor_path(&data_dir);
        create_owner_only_file(&served, b"{}", "test served node").unwrap();
        let node_bytes = std::fs::read(local_node_path(&data_dir)).unwrap();
        remove_local_node(&write, &data_dir, None).await.unwrap();
        assert!(!local_node_path(&data_dir).exists());
        assert!(served.exists());
        std::fs::remove_file(&served).unwrap();
        create_owner_only_file(&local_node_path(&data_dir), &node_bytes, "test node").unwrap();

        // A root that trusts another Runtime stays, with or without a node
        // file beside it: it is a served pool's, never Remove's.
        let other = safe_ancestor_tempdir();
        let other_data = self::data_dir(&other);
        elastos_identity::load_or_create_device_key(&other_data).unwrap();
        let other_issuer = runtime_issuer_hex(&other_data).unwrap();
        elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        install_successful_provision_script(dir.path(), &data_dir, &other_issuer, 0x63);
        crate::protected_content_config::provision_custody_node(
            &data_dir,
            &other_issuer,
            "Olivia",
            "Oslo",
            None,
        )
        .await
        .unwrap();
        // With the node file, only the file goes.
        remove_local_node(&write, &data_dir, None).await.unwrap();
        assert!(!local_node_path(&data_dir).exists());
        assert!(inactive_root(&data_dir)
            .join("trusted-runtime-issuer")
            .exists());
        // Without it there is nothing of this Home's to remove.
        let error = remove_local_node(&write, &data_dir, None)
            .await
            .unwrap_err();
        assert_eq!(refusal(&error).code(), "no_local_node");
        assert!(inactive_root(&data_dir)
            .join("trusted-runtime-issuer")
            .exists());
    }

    /// Lead ruling 2026-11-13: the node-file case of `own_root_path` never
    /// applies to a root that names another owner.
    #[test]
    fn a_root_naming_another_owner_beside_the_node_file_is_not_this_homes_own() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        let other = safe_ancestor_tempdir();
        let other_data = self::data_dir(&other);
        elastos_identity::load_or_create_device_key(&other_data).unwrap();
        let other_issuer = runtime_issuer_hex(&other_data).unwrap();
        write_local_node(&data_dir, "Home", "Paris");
        let root = inactive_root(&data_dir);
        half_removed_root(&data_dir, &root);
        // Names nobody, beside the node file: this Home's own.
        assert_eq!(
            own_root_path(&data_dir).unwrap().as_deref(),
            Some("inactive")
        );
        // Names another owner, beside the node file: not this Home's own.
        create_owner_only_file(
            &root.join("trusted-runtime-issuer"),
            other_issuer.as_bytes(),
            "test issuer",
        )
        .unwrap();
        assert_eq!(own_root_path(&data_dir).unwrap(), None);
        // Without the node file a root naming nobody is not this Home's own.
        std::fs::remove_file(root.join("trusted-runtime-issuer")).unwrap();
        std::fs::remove_file(local_node_path(&data_dir)).unwrap();
        assert_eq!(own_root_path(&data_dir).unwrap(), None);
    }

    #[tokio::test]
    async fn remove_local_node_finishes_an_interrupted_removal() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        let write = crate::custody_consent::lock_custody_writes().await;
        let root = inactive_root(&data_dir);
        let tombstone = removal_tombstone(&data_dir, "inactive");

        // A root left half deleted: its node file says it is this Home's own.
        write_local_node(&data_dir, "Home", "Paris");
        half_removed_root(&data_dir, &root);
        remove_local_node(&write, &data_dir, None).await.unwrap();
        assert!(!root.exists());
        assert!(!tombstone.exists());
        assert!(!local_node_path(&data_dir).exists());

        // Stopped after the rename: the tombstone and the node file are left.
        write_local_node(&data_dir, "Home", "Paris");
        half_removed_root(&data_dir, &tombstone);
        remove_local_node(&write, &data_dir, None).await.unwrap();
        assert!(!tombstone.exists());
        assert!(!local_node_path(&data_dir).exists());

        // Stopped after the node file: the tombstone alone holds no custody
        // state, and the next Remove deletes it.
        half_removed_root(&data_dir, &tombstone);
        assert!(!holds_custody_state(&data_dir).unwrap());
        let error = remove_local_node(&write, &data_dir, None)
            .await
            .unwrap_err();
        assert_eq!(refusal(&error).code(), "no_local_node");
        assert!(!tombstone.exists());
        assert!(!holds_custody_state(&data_dir).unwrap());
    }

    #[tokio::test]
    async fn include_and_the_offer_switch_finish_a_leftover_tombstone() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        let write = crate::custody_consent::lock_custody_writes().await;
        let tombstone = removal_tombstone(&data_dir, "inactive");

        half_removed_root(&data_dir, &tombstone);
        crate::custody_consent::set_offer(&write, &data_dir, None, false, "Home", "Paris").unwrap();
        assert!(!tombstone.exists());

        half_removed_root(&data_dir, &tombstone);
        let issuer = runtime_issuer_hex(&data_dir).unwrap();
        install_successful_provision_script(dir.path(), &data_dir, &issuer, 0x64);
        include_local_node(&write, &data_dir, None, "Home", "Paris")
            .await
            .unwrap();
        assert!(!tombstone.exists());
        assert!(inactive_root(&data_dir).is_dir());
    }

    #[tokio::test]
    async fn remove_local_node_cleans_a_root_an_interrupted_include_left() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        let issuer = runtime_issuer_hex(&data_dir).unwrap();
        install_successful_provision_script(dir.path(), &data_dir, &issuer, 0x65);
        let write = crate::custody_consent::lock_custody_writes().await;
        include_local_node(&write, &data_dir, None, "Home", "Paris")
            .await
            .unwrap();
        // Include stopped between the root and the node file.
        std::fs::remove_file(local_node_path(&data_dir)).unwrap();
        assert!(holds_custody_state(&data_dir).unwrap());

        remove_local_node(&write, &data_dir, None).await.unwrap();
        assert!(!inactive_root(&data_dir).exists());
        assert!(!removal_tombstone(&data_dir, "inactive").exists());
        assert!(!holds_custody_state(&data_dir).unwrap());
    }

    #[tokio::test]
    async fn a_removal_stopped_after_the_rename_leaves_no_node_without_keys() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        let tombstone = removal_tombstone(&data_dir, "inactive");

        // The rename is the commit point: boot drops the node with no keys.
        write_local_node(&data_dir, "Home", "Paris");
        half_removed_root(&data_dir, &tombstone);
        finish_interrupted_local_node_changes(&data_dir).await;
        assert!(!local_node_path(&data_dir).exists());
        assert!(!tombstone.exists());
        assert!(!holds_custody_state(&data_dir).unwrap());

        // Include in the same state sets up a fresh node.
        write_local_node(&data_dir, "Home", "Paris");
        half_removed_root(&data_dir, &tombstone);
        let issuer = runtime_issuer_hex(&data_dir).unwrap();
        install_successful_provision_script(dir.path(), &data_dir, &issuer, 0x66);
        let write = crate::custody_consent::lock_custody_writes().await;
        let included = include_local_node(&write, &data_dir, None, "Fresh", "Rome")
            .await
            .unwrap();
        drop(write);
        assert_eq!(included.node.run_by.as_deref(), Some("Fresh"));
        assert!(!tombstone.exists());
        assert!(inactive_root(&data_dir).is_dir());

        // A tombstone beside a root: an Include came after, and its node stays.
        half_removed_root(&data_dir, &tombstone);
        finish_interrupted_local_node_changes(&data_dir).await;
        assert!(!tombstone.exists());
        assert!(local_node_path(&data_dir).exists());
        assert!(inactive_root(&data_dir).is_dir());
    }

    #[tokio::test]
    async fn boot_removes_only_a_root_an_interrupted_include_left() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        let issuer = runtime_issuer_hex(&data_dir).unwrap();
        install_successful_provision_script(dir.path(), &data_dir, &issuer, 0x67);
        let marker = include_marker_path(&data_dir);
        let mark = || create_owner_only_file(&marker, b"", "test marker").unwrap();
        let own_root_without_node = || async {
            let write = crate::custody_consent::lock_custody_writes().await;
            include_local_node(&write, &data_dir, None, "Home", "Paris")
                .await
                .unwrap();
            std::fs::remove_file(local_node_path(&data_dir)).unwrap();
        };

        // Include finished leaves no marker.
        own_root_without_node().await;
        assert!(!marker.exists());
        // A root made from the terminal, with no marker, survives boot.
        finish_interrupted_local_node_changes(&data_dir).await;
        assert!(inactive_root(&data_dir).join("node-signing-key").exists());

        // Once a pool is installed, the root stays.
        mark();
        let pool = runtime_custody_composition_config_path(&data_dir);
        create_owner_only_file(&pool, b"{}", "test pool").unwrap();
        finish_interrupted_local_node_changes(&data_dir).await;
        assert!(inactive_root(&data_dir).is_dir());
        std::fs::remove_file(&pool).unwrap();

        // The marker says Include stopped between the root and its node file.
        if !marker.exists() {
            mark();
        }
        finish_interrupted_local_node_changes(&data_dir).await;
        assert!(!inactive_root(&data_dir).exists());
        assert!(!removal_tombstone(&data_dir, "inactive").exists());
        assert!(!marker.exists());
        assert!(!holds_custody_state(&data_dir).unwrap());

        // Stopped before the root: only the marker goes.
        mark();
        finish_interrupted_local_node_changes(&data_dir).await;
        assert!(!marker.exists());

        // Stopped after the node file: the node stays.
        write_included_node(&data_dir, "Home", "Paris");
        mark();
        finish_interrupted_local_node_changes(&data_dir).await;
        assert!(!marker.exists());
        assert!(local_node_path(&data_dir).exists());
        assert!(inactive_root(&data_dir).is_dir());

        // A root that trusts another Runtime is never touched.
        std::fs::remove_file(local_node_path(&data_dir)).unwrap();
        std::fs::remove_dir_all(inactive_root(&data_dir)).unwrap();
        let other = safe_ancestor_tempdir();
        let other_data = self::data_dir(&other);
        elastos_identity::load_or_create_device_key(&other_data).unwrap();
        let other_issuer = runtime_issuer_hex(&other_data).unwrap();
        install_successful_provision_script(dir.path(), &data_dir, &other_issuer, 0x68);
        crate::protected_content_config::provision_custody_node(
            &data_dir,
            &other_issuer,
            "Olivia",
            "Oslo",
            None,
        )
        .await
        .unwrap();
        mark();
        finish_interrupted_local_node_changes(&data_dir).await;
        assert!(inactive_root(&data_dir)
            .join("trusted-runtime-issuer")
            .exists());
    }

    #[tokio::test]
    async fn include_sets_up_again_a_node_whose_keys_are_gone_or_differ() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        let issuer = runtime_issuer_hex(&data_dir).unwrap();
        install_successful_provision_script(dir.path(), &data_dir, &issuer, 0x6b);

        // A node file with no root: the summary offers Include, which sets
        // the node up again.
        write_local_node(&data_dir, "Home", "Paris");
        assert!(
            !summary(&data_dir, None, None, None)
                .await
                .local_node
                .provisioned
        );
        let write = crate::custody_consent::lock_custody_writes().await;
        let included = include_local_node(&write, &data_dir, None, "Fresh", "Rome")
            .await
            .unwrap();
        assert_eq!(included.node.run_by.as_deref(), Some("Fresh"));
        assert!(
            summary(&data_dir, None, None, None)
                .await
                .local_node
                .provisioned
        );
        assert!(!include_marker_path(&data_dir).exists());

        // A node file whose key is not the root's.
        std::fs::remove_file(local_node_path(&data_dir)).unwrap();
        write_local_node(&data_dir, "Home", "Paris");
        assert!(
            !summary(&data_dir, None, None, None)
                .await
                .local_node
                .provisioned
        );
        include_local_node(&write, &data_dir, None, "Fresh", "Rome")
            .await
            .unwrap();
        assert!(
            summary(&data_dir, None, None, None)
                .await
                .local_node
                .provisioned
        );
    }

    #[tokio::test]
    async fn include_over_its_own_root_without_a_node_file_recovers() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        let issuer = runtime_issuer_hex(&data_dir).unwrap();
        install_successful_provision_script(dir.path(), &data_dir, &issuer, 0x69);
        let write = crate::custody_consent::lock_custody_writes().await;
        include_local_node(&write, &data_dir, None, "Home", "Paris")
            .await
            .unwrap();
        std::fs::remove_file(local_node_path(&data_dir)).unwrap();

        let again = include_local_node(&write, &data_dir, None, "Home", "Paris")
            .await
            .unwrap();
        assert!(again.node.provisioned);
        assert!(local_node_path(&data_dir).exists());
        assert!(inactive_root(&data_dir).is_dir());
    }

    #[tokio::test]
    async fn this_home_joins_a_pool_only_with_its_own_keys() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        let alice = labelled_card("Alice", "Lisbon", STORAGE);
        let cards = [CardInput::ThisHome, remote(&alice)];
        let card_refusal = |results: Vec<CheckResult>| {
            results
                .into_iter()
                .find(|result| result.id == "card")
                .and_then(|result| result.detail)
        };

        // The node file alone: its keys are gone.
        write_local_node(&data_dir, "Home", "Paris");
        assert_eq!(
            card_refusal(check(&data_dir, &cards)).as_deref(),
            Some("local_node_no_keys")
        );
        create_signing_key(&data_dir).unwrap();
        let error = install(&data_dir, &cards, 365).await.unwrap_err();
        assert_eq!(refusal(&error).code(), "checks_failed");

        // A root that trusts another Runtime holds no keys for this Home.
        let other = safe_ancestor_tempdir();
        let other_data = self::data_dir(&other);
        elastos_identity::load_or_create_device_key(&other_data).unwrap();
        let other_issuer = runtime_issuer_hex(&other_data).unwrap();
        install_successful_provision_script(dir.path(), &data_dir, &other_issuer, 0x6a);
        crate::protected_content_config::provision_custody_node(
            &data_dir,
            &other_issuer,
            "Olivia",
            "Oslo",
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            card_refusal(check(&data_dir, &cards)).as_deref(),
            Some("local_node_no_keys")
        );

        // Its own root: no card refusal.
        std::fs::remove_dir_all(inactive_root(&data_dir)).unwrap();
        std::fs::remove_file(local_node_path(&data_dir)).unwrap();
        write_included_node(&data_dir, "Home", "Paris");
        assert_eq!(card_refusal(check(&data_dir, &cards)), None);

        // A node file whose key is not the one its root holds.
        std::fs::remove_file(local_node_path(&data_dir)).unwrap();
        write_local_node(&data_dir, "Home", "Paris");
        assert_eq!(
            card_refusal(check(&data_dir, &cards)).as_deref(),
            Some("local_node_no_keys")
        );
    }

    #[tokio::test]
    async fn a_failed_include_never_marks_a_root_the_terminal_made() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        let issuer = runtime_issuer_hex(&data_dir).unwrap();
        install_successful_provision_script(dir.path(), &data_dir, &issuer, 0x6c);
        // `provision-custody-node` for this Home: a root, no node file.
        crate::protected_content_config::provision_custody_node(
            &data_dir, &issuer, "Home", "Paris", None,
        )
        .await
        .unwrap();
        let key = inactive_root(&data_dir).join("node-signing-key");
        let write = crate::custody_consent::lock_custody_writes().await;

        let error = include_local_node(&write, &data_dir, None, " Home", "Paris")
            .await
            .unwrap_err();
        assert_eq!(refusal(&error).code(), "bad_labels");
        assert!(!include_marker_path(&data_dir).exists());

        // The provider fails after an update.
        std::fs::remove_file(data_dir.join("components.json")).unwrap();
        let error = include_local_node(&write, &data_dir, None, "Home", "Paris")
            .await
            .unwrap_err();
        assert_eq!(refusal(&error).code(), "provision_failed");
        assert!(!include_marker_path(&data_dir).exists());
        drop(write);

        finish_interrupted_local_node_changes(&data_dir).await;
        assert!(key.exists(), "the terminal's keys survive boot");
    }

    #[tokio::test]
    async fn include_refuses_once_a_pool_is_installed() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        write_included_node(&data_dir, "Home", "Paris");
        // Not keyed, so Include would otherwise set it up again.
        std::fs::remove_file(local_node_path(&data_dir)).unwrap();
        write_local_node(&data_dir, "Home", "Paris");
        let node = std::fs::read(local_node_path(&data_dir)).unwrap();
        create_owner_only_file(
            &runtime_custody_composition_config_path(&data_dir),
            b"{}",
            "test pool",
        )
        .unwrap();
        let write = crate::custody_consent::lock_custody_writes().await;
        let error = include_local_node(&write, &data_dir, None, "Other", "Rome")
            .await
            .unwrap_err();
        assert_eq!(refusal(&error).code(), "pool_installed");
        assert_eq!(std::fs::read(local_node_path(&data_dir)).unwrap(), node);
    }

    #[tokio::test]
    async fn a_node_key_that_cannot_be_read_is_neither_used_nor_set_up_again() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        write_included_node(&data_dir, "Home", "Paris");
        let key = inactive_root(&data_dir).join("node-signing-key");
        std::fs::remove_file(&key).unwrap();
        create_owner_only_file(&key, b"not a key", "test unreadable key").unwrap();
        let node = std::fs::read(local_node_path(&data_dir)).unwrap();

        // Unknown is not "gone": the summary still shows the node.
        assert!(
            summary(&data_dir, None, None, None)
                .await
                .local_node
                .provisioned
        );
        let alice = labelled_card("Alice", "Lisbon", STORAGE);
        let refused = check(&data_dir, &[CardInput::ThisHome, remote(&alice)])
            .into_iter()
            .find(|result| result.id == "card")
            .and_then(|result| result.detail);
        assert_eq!(refused.as_deref(), Some("local_node_unreadable"));
        let write = crate::custody_consent::lock_custody_writes().await;
        let error = include_local_node(&write, &data_dir, None, "Home", "Paris")
            .await
            .unwrap_err();
        assert_eq!(refusal(&error).code(), "local_node_unreadable");
        assert_eq!(std::fs::read(local_node_path(&data_dir)).unwrap(), node);
    }

    #[tokio::test]
    async fn create_signing_key_refuses_existing_key() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        let shown = summary(&data_dir, None, None, None).await;
        assert!(!shown.signing_key.present);
        assert_eq!(shown.term_presets_days, POOL_TERM_DAYS);

        let fingerprint = create_signing_key(&data_dir).unwrap();
        let key = std::fs::read(policy_authority_key_path(&data_dir)).unwrap();
        let shown = summary(&data_dir, None, None, None).await.signing_key;
        assert!(shown.present);
        assert_eq!(
            shown.fingerprint.as_deref(),
            Some(fingerprint.short.as_str())
        );

        let error = create_signing_key(&data_dir).unwrap_err();
        assert_eq!(refusal(&error).code(), "key_exists");
        assert_eq!(
            std::fs::read(policy_authority_key_path(&data_dir)).unwrap(),
            key
        );
    }

    #[test]
    fn read_card_refuses_own_card() {
        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        let device_key = elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        let (home_key, home_did) = elastos_identity::derive_did(&device_key);

        let own = card_for_device(&home_key.verifying_key(), "Home", "Paris", STORAGE);
        assert_eq!(
            read_card(&data_dir, &own),
            CardView::Refused {
                refused: "own_card"
            }
        );

        let alice = labelled_card("Alice", "Lisbon", CUSTODY_ONLY);
        let CardView::Read {
            run_by,
            location,
            home_id,
            provides,
            local,
            ..
        } = read_card(&data_dir, &alice)
        else {
            panic!("a remote card must read");
        };
        assert_eq!((run_by.as_str(), location.as_str()), ("Alice", "Lisbon"));
        assert_ne!(home_id, home_did);
        assert_eq!(home_id, peer_did(&alice));
        assert_eq!(provides, ["chain", "custody"]);
        assert!(!local);
        assert_eq!(
            read_card(&data_dir, "elastos-node-card:v2:abc"),
            CardView::Refused {
                refused: "newer_version"
            }
        );
    }

    fn refused(fetched: FetchedCard) -> &'static str {
        match fetched {
            FetchedCard::Refused { refused, .. } => refused,
            FetchedCard::Card { view, .. } => panic!("expected a refusal, got {view:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_card_refuses_bad_address() {
        use crate::custody_node_card::tests::ticket_for;

        let dir = tempfile::tempdir().unwrap();
        let one = ticket_for(&ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key());
        let two = ticket_for(&ed25519_dalek::SigningKey::from_bytes(&[2; 32]).verifying_key());
        let decode = |ticket: &str| {
            let bytes = data_encoding::BASE32_NOPAD
                .decode(ticket.to_ascii_uppercase().as_bytes())
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        };
        let encode = |endpoints: Vec<serde_json::Value>| {
            let ticket = serde_json::json!({ "topic": null, "endpoints": endpoints });
            data_encoding::BASE32_NOPAD
                .encode(&serde_json::to_vec(&ticket).unwrap())
                .to_ascii_lowercase()
        };
        let both = encode(vec![
            decode(&one)["endpoints"][0].clone(),
            decode(&two)["endpoints"][0].clone(),
        ]);
        let empty = encode(Vec::new());
        for address in ["", "  ", "not a ticket", empty.as_str(), both.as_str()] {
            assert_eq!(
                refused(fetch_card(dir.path(), address).await),
                "bad_address",
                "{address:?}"
            );
        }
    }

    #[test]
    fn card_from_node_answer_reads_the_card_and_requires_the_dialed_node() {
        use crate::custody_node_card::tests::{carrier_descriptor_bytes, ticket_for};
        use base64::Engine as _;

        let device = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let device_did = elastos_identity::encode_did_key(&device).unwrap();
        let ticket = ticket_for(&device);
        let node = carrier_descriptor_bytes(&device, "Alice", "Lisbon");
        let answer = |node: &[u8]| {
            serde_json::json!({
                "schema": "elastos.protected-content.custody-node-card-read/v1",
                "node": base64::engine::general_purpose::STANDARD.encode(node),
                "provides": ["chain", "custody", "ipfs"],
                "ipfs_peer_id": TEST_IPFS_PEER_ID,
            })
        };
        let stranger = OwnHome {
            did: None,
            local_node_bytes: None,
        };

        let (text, card) =
            card_from_node_answer(&stranger, &ticket, &device_did, &answer(&node)).unwrap();
        let pasted = parse_node_card(&text).unwrap();
        assert_eq!(pasted.node_bytes, node);
        assert_eq!(pasted.ticket, ticket);
        assert_eq!(pasted.ipfs_peer_id.as_deref(), Some(TEST_IPFS_PEER_ID));
        assert_eq!(card.descriptor.operator, "Alice");
        assert_eq!(card.provides, STORAGE);

        // The card must name the node that was dialed.
        let other_did = elastos_identity::encode_did_key(
            &ed25519_dalek::SigningKey::from_bytes(&[8; 32]).verifying_key(),
        )
        .unwrap();
        assert_eq!(
            card_from_node_answer(&stranger, &ticket, &other_did, &answer(&node)).err(),
            Some("ticket_mismatch")
        );
        // A node answering with another node's descriptor fails the same way.
        let elsewhere = ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key();
        let foreign = carrier_descriptor_bytes(&elsewhere, "Alice", "Lisbon");
        assert_eq!(
            card_from_node_answer(&stranger, &ticket, &device_did, &answer(&foreign)).err(),
            Some("ticket_mismatch")
        );
        // Our own node's card is refused like a pasted one.
        let this_home = OwnHome {
            did: Some(device_did.clone()),
            local_node_bytes: None,
        };
        assert_eq!(
            card_from_node_answer(&this_home, &ticket, &device_did, &answer(&node)).err(),
            Some("own_card")
        );

        let mut bad_node = answer(&node);
        bad_node["node"] = serde_json::json!("not base64!");
        let mut newer = answer(&node);
        newer["schema"] = serde_json::json!("elastos.protected-content.custody-node-card-read/v2");
        let mut unknown = answer(&node);
        unknown["schema"] = serde_json::json!("something-else/v1");
        let mut extra = answer(&node);
        extra["secret"] = serde_json::json!("never");
        for (answer, code) in [
            (bad_node, "not_a_card"),
            (newer, "newer_version"),
            (unknown, "not_a_card"),
            (extra, "not_a_card"),
            (serde_json::Value::Null, "not_a_card"),
        ] {
            assert_eq!(
                card_from_node_answer(&stranger, &ticket, &device_did, &answer).err(),
                Some(code),
                "{answer}"
            );
        }
    }

    /// The owner dials a live node over loopback Carrier.
    #[cfg(unix)]
    #[tokio::test]
    async fn fetch_card_reads_the_card_from_its_node() {
        use crate::custody_node_card::tests::carrier_descriptor_bytes;
        use crate::operator_control::tests::{
            start_custody_test_node, test_home, write_custody_node_descriptor,
        };

        let (owner_home, owner_did) = test_home(51);
        let (owner_sk, _) = elastos_identity::derive_did(&[51; 32]);
        let node = start_custody_test_node(52, &owner_sk.verifying_key()).await;
        let ticket = node.peer.connect_ticket.clone();

        assert_eq!(
            refused(fetch_card(owner_home.path(), &ticket).await),
            "no_card"
        );

        let descriptor = carrier_descriptor_bytes(&node.device, "Bob", "Porto");
        write_custody_node_descriptor(&node.data_dir, &descriptor);
        let FetchedCard::Card { card, view } = fetch_card(owner_home.path(), &ticket).await else {
            panic!("the trusted owner must get the card");
        };
        let pasted = parse_node_card(&card).unwrap();
        assert_eq!(pasted.node_bytes, descriptor);
        assert_eq!(pasted.ticket, ticket);
        let CardView::Read {
            run_by,
            location,
            home_id,
            provides,
            local,
            ..
        } = view
        else {
            panic!("a fetched card reads like a pasted one");
        };
        assert_eq!((run_by.as_str(), location.as_str()), ("Bob", "Porto"));
        assert_eq!(home_id, node.peer.did);
        // No provider host receipt: custody and chain, no copies.
        assert_eq!(provides, CUSTODY_ONLY);
        assert!(!local);

        let (stranger_home, _) = test_home(53);
        let FetchedCard::Refused { refused, detail } =
            fetch_card(stranger_home.path(), &ticket).await
        else {
            panic!("only the trusted owner gets the card");
        };
        assert_eq!(refused, "not_owner");
        let detail = detail.unwrap();
        assert!(!detail.contains(&owner_did), "{detail}");
    }

    /// A full Home serving `owner`'s pool: its live Carrier node, with the
    /// node descriptor provisioning stores.
    async fn serving_home(
        seed: u8,
        owner: &ed25519_dalek::VerifyingKey,
    ) -> (crate::operator_control::tests::CustodyTestNode, Vec<u8>) {
        use crate::custody_node_card::tests::carrier_descriptor_bytes;
        use crate::operator_control::tests::{
            start_custody_test_node, write_custody_node_descriptor,
        };

        let node = start_custody_test_node(seed, owner).await;
        let descriptor = carrier_descriptor_bytes(&node.device, "Bob", "Porto");
        write_custody_node_descriptor(&node.data_dir, &descriptor);
        (node, descriptor)
    }

    #[tokio::test]
    async fn summary_reports_node_address_for_a_carrier_node() {
        let (owner_home, _) = crate::operator_control::tests::test_home(81);
        let (owner_sk, _) = elastos_identity::derive_did(&[81; 32]);
        let (node, _) = serving_home(82, &owner_sk.verifying_key()).await;
        let endpoint = &node.node.endpoint;

        // Without the running Carrier node there is no address to tell.
        assert_eq!(
            summary(&node.data_dir, None, None, None)
                .await
                .local_node
                .address,
            None
        );
        let address = summary(&node.data_dir, None, Some(endpoint), None)
            .await
            .local_node
            .address
            .expect("a Carrier-routed node shows its address");
        let [shown] = <[iroh::EndpointAddr; 1]>::try_from(decode_ticket_endpoints(&address))
            .expect("one endpoint: this Home");
        assert_eq!(shown.id.as_bytes(), node.device.as_bytes());
        assert!(
            shown.ip_addrs().next().is_some(),
            "its bound Carrier addresses: {shown:?}"
        );
        // The owner fetches this node's card with exactly that address.
        let FetchedCard::Card { view, .. } = fetch_card(owner_home.path(), &address).await else {
            panic!("the owner reaches the node at the address it shows");
        };
        assert!(matches!(view, CardView::Read { ref run_by, .. } if run_by == "Bob"));
    }

    #[tokio::test]
    async fn summary_reports_serving_with_last_owner_contact() {
        use crate::custody_node_card::tests::TEST_IPFS_PEER_ID;
        use std::os::unix::fs::PermissionsExt;

        let (owner_sk, owner_did) = elastos_identity::derive_did(&[83; 32]);
        let (_, stranger_did) = elastos_identity::derive_did(&[85; 32]);
        let (node, descriptor) = serving_home(84, &owner_sk.verifying_key()).await;
        // The node's audit, as it writes it: the owner's accepted read, a
        // stranger's newer one, then the owner's newest, refused.
        let entry = |ts: u64, requester_did: &str, accepted: bool| {
            let mut entry = serde_json::json!({
                "ts": ts,
                "request_id": format!("req-{ts}"),
                "requester_did": requester_did,
                "action": crate::operator_control::OPERATOR_ACTION_CUSTODY_NODE_CARD_READ,
                "accepted": accepted,
            });
            if !accepted {
                entry["error"] = "operator request timestamp is outside the allowed window".into();
            }
            format!("{entry}\n")
        };
        std::fs::write(
            node.data_dir.join("operator-control-audit.jsonl"),
            [
                entry(1_793_040_166, &owner_did, true),
                entry(1_793_040_200, &stranger_did, true),
                entry(1_793_040_300, &owner_did, false),
            ]
            .concat(),
        )
        .unwrap();

        let shown = summary(&node.data_dir, None, None, None).await;
        // Plan B T2.3: a list; this node, served before consents were kept,
        // has no pool key.
        assert_eq!(
            shown.serving,
            vec![ServingView {
                owner_did: Some(owner_did.clone()),
                owner_name: None,
                run_by: "Bob".to_string(),
                location: "Porto".to_string(),
                provides: CUSTODY_ONLY.iter().map(|role| role.to_string()).collect(),
                fingerprint: fingerprint(&descriptor),
                fingerprint_full: Fingerprint::of(&descriptor).full,
                provider_running: false,
                needs_restart: true,
                last_owner_contact: Some(1_793_040_166),
                // Its owner has not told it about a pool yet.
                pool: None,
                pool_fingerprint: String::new(),
            }]
        );
        let json = serde_json::to_string(&shown).unwrap();
        assert!(!json.contains(&stranger_did), "{json}");

        // Its own kubo makes it a storage node, and a ready custody provider
        // is serving.
        let repo = node.data_dir.join("ipfs-repo");
        crate::protected_content_config::tests::owner_only_dir(&repo);
        let config = repo.join("config");
        std::fs::write(
            &config,
            serde_json::to_vec(&serde_json::json!({
                "Identity": { "PeerID": TEST_IPFS_PEER_ID, "PrivKey": "CAESQPrivateKeyMaterial" },
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        let registry = Arc::new(ProviderRegistry::new());
        registry
            .register_runtime_provider_target(CUSTODY_PROVIDER_ID, Arc::new(ReadyCustodyProvider))
            .await
            .unwrap();
        let serving = summary(&node.data_dir, Some(&registry), None, None)
            .await
            .serving
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(serving.provides, STORAGE);
        assert!(serving.provider_running);
    }

    #[tokio::test]
    async fn summary_reports_local_profile_name() {
        use crate::collaboration_profile_authority::tests::write_test_profile;

        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        let principal_id = "person:local:custody-profile";
        // No signed-in admin, and an admin without a Profile, name nothing.
        assert_eq!(
            summary(&data_dir, None, None, None)
                .await
                .local_profile_name,
            None
        );
        assert_eq!(
            summary(&data_dir, None, None, Some(principal_id))
                .await
                .local_profile_name,
            None
        );

        write_test_profile(&data_dir, principal_id, "Ada Lovelace");
        let shown = summary(&data_dir, None, None, Some(principal_id)).await;
        assert_eq!(shown.local_profile_name.as_deref(), Some("Ada Lovelace"));
        // Only the signed-in admin's own Profile names this Home.
        assert_eq!(
            summary(&data_dir, None, None, Some("person:local:someone-else"))
                .await
                .local_profile_name,
            None
        );
    }

    /// Every short fingerprint in `value` sits beside the full digest it
    /// shows; returns how many it found.
    fn assert_full_fingerprints(value: &serde_json::Value) -> usize {
        match value {
            serde_json::Value::Object(object) => {
                let here = match object.get("fingerprint") {
                    Some(serde_json::Value::String(short)) => {
                        let full = object
                            .get("fingerprint_full")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or_else(|| {
                                panic!("no fingerprint_full beside {short}: {value}")
                            });
                        let hex = full
                            .strip_prefix("sha256:")
                            .unwrap_or_else(|| panic!("{full}"));
                        assert!(
                            hex.len() == 64
                                && hex
                                    .bytes()
                                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
                            "{full}"
                        );
                        let groups: Vec<&str> = short.split(' ').collect();
                        let upper = hex.to_ascii_uppercase();
                        assert_eq!(
                            (&upper[..8], &upper[56..]),
                            (
                                format!("{}{}", groups[0], groups[1]).as_str(),
                                format!("{}{}", groups[3], groups[4]).as_str()
                            ),
                            "{short} vs {full}"
                        );
                        1
                    }
                    Some(serde_json::Value::Null) => {
                        assert_eq!(
                            object.get("fingerprint_full"),
                            Some(&serde_json::Value::Null)
                        );
                        0
                    }
                    _ => 0,
                };
                here + object.values().map(assert_full_fingerprints).sum::<usize>()
            }
            serde_json::Value::Array(items) => items.iter().map(assert_full_fingerprints).sum(),
            _ => 0,
        }
    }

    #[tokio::test]
    async fn every_fingerprint_comes_with_its_full_digest() {
        use crate::custody_node_card::tests::carrier_descriptor_bytes;
        use crate::operator_control::tests::write_custody_node_descriptor;

        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        // Nothing yet: the empty views carry null for both forms.
        let empty = serde_json::to_value(summary(&data_dir, None, None, None).await).unwrap();
        assert_eq!(assert_full_fingerprints(&empty), 0);
        assert_eq!(
            empty["local_node"].get("fingerprint_full"),
            Some(&serde_json::Value::Null)
        );
        assert_eq!(
            empty["signing_key"].get("fingerprint_full"),
            Some(&serde_json::Value::Null)
        );

        // A Home with a signing key, its own node in an installed pool, and a
        // node it serves for another owner.
        let created = create_signing_key(&data_dir).unwrap();
        assert_full_fingerprints(&serde_json::json!({
            "fingerprint": created.short, "fingerprint_full": created.full,
        }));
        write_included_node(&data_dir, "Home", "Paris");
        let card = labelled_card("Alice", "Lisbon", STORAGE);
        let card_view = serde_json::to_value(read_card(&data_dir, &card)).unwrap();
        assert_eq!(assert_full_fingerprints(&card_view), 1);
        let cards = [
            CardInput::ThisHome,
            remote(&card),
            remote(&labelled_card("Bob", "Oslo", STORAGE)),
        ];
        let installed =
            serde_json::to_value(install(&data_dir, &cards, 365).await.unwrap()).unwrap();
        assert_eq!(assert_full_fingerprints(&installed), 1);
        let verified = serde_json::to_value(verify(&data_dir).unwrap()).unwrap();
        assert_eq!(assert_full_fingerprints(&verified), 1);
        assert_eq!(verified["fingerprint_full"], installed["fingerprint_full"]);
        let device = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]).verifying_key();
        write_custody_node_descriptor(
            &data_dir,
            &carrier_descriptor_bytes(&device, "Bob", "Porto"),
        );

        let shown = serde_json::to_value(summary(&data_dir, None, None, None).await).unwrap();
        // Signing key, this Home's node, the pool and the served node.
        assert_eq!(assert_full_fingerprints(&shown), 4, "{shown}");
        assert_eq!(
            shown["pool"]["fingerprint_full"],
            installed["fingerprint_full"]
        );
    }

    #[tokio::test]
    async fn serving_absent_for_owner_only_home() {
        // A Home with its own pool and node, whose custody root trusts its own
        // Runtime, and a live Carrier node, but no node descriptor: it serves
        // nobody else's pool.
        let (own_sk, _) = elastos_identity::derive_did(&[87; 32]);
        let home =
            crate::operator_control::tests::start_custody_test_node(87, &own_sk.verifying_key())
                .await;
        write_included_node(&home.data_dir, "Home", "Paris");
        create_signing_key(&home.data_dir).unwrap();
        let cards = [
            CardInput::ThisHome,
            remote(&labelled_card("Alice", "Lisbon", STORAGE)),
            remote(&labelled_card("Bob", "Oslo", STORAGE)),
        ];
        install(&home.data_dir, &cards, 365).await.unwrap();

        let shown = summary(&home.data_dir, None, Some(&home.node.endpoint), None).await;
        assert!(shown.pool.is_some() && shown.local_node.provisioned);
        assert!(shown.serving.is_empty());
        assert_eq!(shown.local_node.address, None);
        let json = serde_json::to_value(&shown).unwrap();
        assert_eq!(json["serving"], serde_json::json!([]));
        assert_eq!(json["local_node"]["address"], serde_json::Value::Null);
    }

    #[test]
    fn pool_status_weighs_online_members_against_the_pools_threshold() {
        use PoolHealth::{AtRisk, Down, Healthy};

        let cases: [(ThresholdView, &[PoolHealth]); 2] = [
            (
                ThresholdView {
                    required: 2,
                    total: 3,
                },
                &[Down, Down, AtRisk, Healthy],
            ),
            (
                ThresholdView {
                    required: 3,
                    total: 5,
                },
                &[Down, Down, Down, AtRisk, AtRisk, Healthy],
            ),
        ];
        for (threshold, by_online) in cases {
            for (online, status) in by_online.iter().enumerate() {
                assert_eq!(
                    pool_status(online as u8, threshold),
                    *status,
                    "{online} online of {threshold:?}"
                );
            }
        }
    }

    /// This Home's DID key, which the test nodes trust as their pool owner.
    fn owner_key(data_dir: &Path) -> ed25519_dalek::VerifyingKey {
        let device_key = elastos_identity::load_or_create_device_key(data_dir).unwrap();
        elastos_identity::derive_did(&device_key).0.verifying_key()
    }

    /// The installed share of the member at `home_id`; `None` is this Home.
    fn share_of(data_dir: &Path, home_id: Option<&str>) -> u8 {
        read_pool(data_dir)
            .unwrap()
            .unwrap()
            .members
            .iter()
            .find(|member| member.home_id.as_deref() == home_id)
            .unwrap()
            .share
    }

    fn member_health(health: &PoolHealthView, share: u8) -> (MemberState, Option<&str>) {
        let member = health
            .members
            .iter()
            .find(|member| member.share == share)
            .unwrap_or_else(|| panic!("no share {share} in {health:?}"));
        (member.state, member.detail.as_deref())
    }

    async fn fetched_card(data_dir: &Path, ticket: &str) -> String {
        match fetch_card(data_dir, ticket).await {
            FetchedCard::Card { card, .. } => card,
            FetchedCard::Refused { refused, detail } => panic!("{refused}: {detail:?}"),
        }
    }

    /// Two live members and one whose ticket reaches no node, over loopback
    /// Carrier, then one live member that loses its card.
    #[cfg(unix)]
    #[tokio::test]
    async fn pool_health_counts_online_against_threshold() {
        use crate::custody_node_card::tests::{carrier_descriptor_bytes, ticket_at};
        use crate::operator_control::tests::{
            start_custody_test_node, write_custody_node_descriptor,
        };

        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        let owner = owner_key(&data_dir);
        create_signing_key(&data_dir).unwrap();
        assert!(pool_health(&data_dir, None).await.unwrap().is_none());

        let alice = start_custody_test_node(61, &owner).await;
        let bob = start_custody_test_node(62, &owner).await;
        let mut cards = Vec::new();
        for (node, run_by, location) in [(&alice, "Alice", "Lisbon"), (&bob, "Bob", "Oslo")] {
            let descriptor = carrier_descriptor_bytes(&node.device, run_by, location);
            write_custody_node_descriptor(&node.data_dir, &descriptor);
            cards.push(remote(
                &fetched_card(&data_dir, &node.peer.connect_ticket).await,
            ));
        }
        // Carol's node is stopped: her address takes packets and never answers.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let carol_device = ed25519_dalek::SigningKey::from_bytes(&[66; 32]).verifying_key();
        let carol = crate::custody_node_card::encode_node_card(
            &carrier_descriptor_bytes(&carol_device, "Carol", "Kyiv"),
            &ticket_at(&carol_device, &silent.local_addr().unwrap().to_string()),
            &CUSTODY_ONLY
                .iter()
                .map(|role| role.to_string())
                .collect::<Vec<_>>(),
            None,
        )
        .unwrap();
        cards.push(remote(&carol));
        install(&data_dir, &cards, 365).await.unwrap();
        let alice_share = share_of(&data_dir, Some(&alice.peer.did));
        let bob_share = share_of(&data_dir, Some(&bob.peer.did));
        let carol_share = share_of(&data_dir, Some(&peer_did(&carol)));

        let started = std::time::Instant::now();
        let health = pool_health(&data_dir, None).await.unwrap().unwrap();
        // A stopped member costs the short probe timeout, within about five
        // seconds, not the operator default.
        assert!(
            started.elapsed() < std::time::Duration::from_secs(6),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(
            (health.required, health.total),
            (CUSTODY_THRESHOLD_REQUIRED, CUSTODY_THRESHOLD_TOTAL)
        );
        assert_eq!(health.online, 2, "{health:?}");
        assert_eq!(health.status, PoolHealth::AtRisk);
        assert!(health.checked_at > 0);
        let shares: Vec<u8> = health.members.iter().map(|member| member.share).collect();
        assert_eq!(shares, (1..=CUSTODY_THRESHOLD_TOTAL).collect::<Vec<_>>());
        assert_eq!(
            member_health(&health, alice_share),
            (MemberState::Online, None)
        );
        assert_eq!(
            member_health(&health, bob_share),
            (MemberState::Online, None)
        );
        let (state, detail) = member_health(&health, carol_share);
        assert_eq!(state, MemberState::NotAnswering);
        assert!(
            detail.is_some_and(|detail| detail.contains("timed out")),
            "{detail:?}"
        );

        // Bob's Home still answers, but signs a refusal: no node is serving.
        std::fs::remove_file(
            crate::protected_content_config::custody_node_descriptor_path(&bob.data_dir),
        )
        .unwrap();
        let health = pool_health(&data_dir, None).await.unwrap().unwrap();
        assert_eq!(
            member_health(&health, bob_share),
            (MemberState::Refused, Some(CUSTODY_NODE_HAS_NO_CARD))
        );
        assert_eq!(health.online, 1);
        assert_eq!(health.status, PoolHealth::Down);
    }

    /// A Home that answers for the member with another node's key is not that
    /// member: the pool's routes name the key.
    #[cfg(unix)]
    #[tokio::test]
    async fn pool_health_flags_a_different_node() {
        use crate::custody_node_card::tests::carrier_descriptor_bytes;
        use crate::operator_control::tests::{
            start_custody_test_node, write_custody_node_descriptor,
        };

        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        let owner = owner_key(&data_dir);
        create_signing_key(&data_dir).unwrap();
        let alice = start_custody_test_node(63, &owner).await;
        write_custody_node_descriptor(
            &alice.data_dir,
            &carrier_descriptor_bytes(&alice.device, "Alice", "Lisbon"),
        );
        let cards = [
            remote(&fetched_card(&data_dir, &alice.peer.connect_ticket).await),
            remote(&labelled_card("Bob", "Oslo", STORAGE)),
            remote(&labelled_card("Carol", "Kyiv", CUSTODY_ONLY)),
        ];
        install(&data_dir, &cards, 365).await.unwrap();
        let alice_share = share_of(&data_dir, Some(&alice.peer.did));
        let health = pool_health(&data_dir, None).await.unwrap().unwrap();
        assert_eq!(
            member_health(&health, alice_share),
            (MemberState::Online, None)
        );

        // Alice's Home is set up again: same Home, a new node key.
        let descriptor_path =
            crate::protected_content_config::custody_node_descriptor_path(&alice.data_dir);
        std::fs::remove_file(&descriptor_path).unwrap();
        write_custody_node_descriptor(
            &alice.data_dir,
            &carrier_descriptor_bytes(&alice.device, "Alice", "Lisbon"),
        );
        let health = pool_health(&data_dir, None).await.unwrap().unwrap();
        assert_eq!(
            member_health(&health, alice_share).0,
            MemberState::DifferentNode
        );
        assert_eq!(health.online, 0);
        assert_eq!(health.status, PoolHealth::Down);
    }

    /// A member that moved and was added again with `node peer add` is dialed
    /// at its new address, not at the one on its kept card.
    #[cfg(unix)]
    #[tokio::test]
    async fn pool_health_dials_the_peer_entry_before_the_kept_card() {
        use crate::custody_node_card::tests::{carrier_descriptor_bytes, ticket_at};
        use crate::operator_control::tests::{
            start_custody_test_node, write_custody_node_descriptor,
        };

        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        let owner = owner_key(&data_dir);
        create_signing_key(&data_dir).unwrap();
        let alice = start_custody_test_node(67, &owner).await;
        let descriptor = carrier_descriptor_bytes(&alice.device, "Alice", "Lisbon");
        write_custody_node_descriptor(&alice.data_dir, &descriptor);
        // Her card still names her old address, which takes packets and never
        // answers.
        let old_address = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let card = crate::custody_node_card::encode_node_card(
            &descriptor,
            &ticket_at(
                &alice.device,
                &old_address.local_addr().unwrap().to_string(),
            ),
            &CUSTODY_ONLY
                .iter()
                .map(|role| role.to_string())
                .collect::<Vec<_>>(),
            None,
        )
        .unwrap();
        let cards = [
            remote(&card),
            remote(&labelled_card("Bob", "Oslo", STORAGE)),
            remote(&labelled_card("Carol", "Kyiv", CUSTODY_ONLY)),
        ];
        install(&data_dir, &cards, 365).await.unwrap();
        assert!(read_members_record(
            &data_dir,
            &installed_pool(&data_dir).unwrap().unwrap().config_sha256
        )
        .is_some());
        upsert_peer(
            &data_dir,
            OperatorPeer {
                did: alice.peer.did.clone(),
                connect_ticket: alice.peer.connect_ticket.clone(),
                ..OperatorPeer::default()
            },
        )
        .unwrap();

        let health = pool_health(&data_dir, None).await.unwrap().unwrap();
        assert_eq!(
            member_health(&health, share_of(&data_dir, Some(&alice.peer.did))),
            (MemberState::Online, None)
        );
        assert_eq!(health.online, 1);
    }

    /// A pool installed from the terminal has no members record: members are
    /// dialed by their peer entries, and this Home's member by its provider.
    #[cfg(unix)]
    #[tokio::test]
    async fn pool_health_uses_peer_store_ticket_without_members_record() {
        use crate::custody_node_card::tests::carrier_descriptor_bytes;
        use crate::operator_control::tests::{
            start_custody_test_node, write_custody_node_descriptor,
        };

        let dir = safe_ancestor_tempdir();
        let data_dir = data_dir(&dir);
        let owner = owner_key(&data_dir);
        create_signing_key(&data_dir).unwrap();
        write_included_node(&data_dir, "Home", "Paris");
        let alice = start_custody_test_node(64, &owner).await;
        let bob = start_custody_test_node(65, &owner).await;
        let alice_bytes = carrier_descriptor_bytes(&alice.device, "Alice", "Lisbon");
        let bob_bytes = carrier_descriptor_bytes(&bob.device, "Bob", "Oslo");
        write_custody_node_descriptor(&alice.data_dir, &alice_bytes);
        write_custody_node_descriptor(&bob.data_dir, &bob_bytes);
        let local_bytes = std::fs::read(local_node_path(&data_dir)).unwrap();
        let descriptors = [local_bytes, alice_bytes, bob_bytes]
            .iter()
            .map(|bytes| validated_custody_node_descriptor(bytes, "test node").unwrap())
            .collect();
        install_custody_composition(
            &data_dir,
            &policy_authority_key_path(&data_dir),
            distinct_custody_node_descriptors(descriptors).unwrap(),
            365,
        )
        .unwrap();
        assert!(!pool_members_path(&data_dir).exists());
        let peer_entry = |node: &crate::operator_control::tests::CustodyTestNode| OperatorPeer {
            did: node.peer.did.clone(),
            label: "custody-node".to_string(),
            connect_ticket: node.peer.connect_ticket.clone(),
            ..OperatorPeer::default()
        };
        upsert_peer(&data_dir, peer_entry(&alice)).unwrap();
        let home_share = share_of(&data_dir, None);
        let alice_share = share_of(&data_dir, Some(&alice.peer.did));
        let bob_share = share_of(&data_dir, Some(&bob.peer.did));

        let health = pool_health(&data_dir, None).await.unwrap().unwrap();
        assert_eq!(
            member_health(&health, home_share),
            (MemberState::NotAnswering, Some("not_running"))
        );
        assert_eq!(
            member_health(&health, alice_share),
            (MemberState::Online, None)
        );
        assert_eq!(
            member_health(&health, bob_share),
            (MemberState::NotAnswering, Some("no_address"))
        );
        assert_eq!((health.online, health.status), (1, PoolHealth::Down));

        let registry = Arc::new(ProviderRegistry::new());
        registry
            .register_runtime_provider_target(CUSTODY_PROVIDER_ID, Arc::new(ReadyCustodyProvider))
            .await
            .unwrap();
        let health = pool_health(&data_dir, Some(&registry))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            member_health(&health, home_share),
            (MemberState::Online, None)
        );
        assert_eq!((health.online, health.status), (2, PoolHealth::AtRisk));

        upsert_peer(&data_dir, peer_entry(&bob)).unwrap();
        let health = pool_health(&data_dir, Some(&registry))
            .await
            .unwrap()
            .unwrap();
        assert_eq!((health.online, health.status), (3, PoolHealth::Healthy));
    }

    /// Plan B T2.3: an approved pool with no pool-active yet waits; the
    /// consent ends under seven days.
    #[test]
    fn waiting_pool_shows_waiting_for_pool() {
        let now = 1_000_000;
        assert_eq!(
            served_pool_status(true, None, now),
            ServedPoolStatus::WaitingForPool
        );
        assert_eq!(
            served_pool_status(false, None, now),
            ServedPoolStatus::NeedsRestart
        );
        assert_eq!(
            served_pool_status(false, Some(now + 30 * SECONDS_PER_DAY), now),
            ServedPoolStatus::NeedsRestart
        );
        assert_eq!(
            served_pool_status(true, Some(now + CONSENT_ENDING_SECS), now),
            ServedPoolStatus::Serving
        );
        assert_eq!(
            served_pool_status(true, Some(now + CONSENT_ENDING_SECS - 1), now),
            ServedPoolStatus::ConsentEnding
        );
        assert_eq!(
            serde_json::to_value(ServedPoolStatus::WaitingForPool).unwrap(),
            serde_json::json!("waiting_for_pool")
        );
        assert_eq!(
            serde_json::to_value(ServedPoolStatus::ConsentEnding).unwrap(),
            serde_json::json!("consent_ending")
        );
    }
}
