//! The custody wire surface, declared once.
//!
//! Every custody Carrier target, Carrier op, gateway route, passkey step-up
//! operation, Custody capsule method, signed message type, operator action
//! and Inbox entry is a row of [`CUSTODY_SURFACE`]. Call sites use the
//! constants below, and the Carrier allow-list and the runtime-target check
//! read the table, so a new item lands in one place together with its
//! approval state. An item still waiting for its #173 approval record says
//! [`Approval::Pending173`]; [`pending_approvals`] lists them for that record.
//!
//! The wire values are fixed: Homes already running speak them. Later work
//! only adds rows.
//!
//! `stage` names the work that brought an item:
//! - `runtime-custody`: the custody provider plane of protected content;
//! - `custody-app`: the Custody app that forms and installs a pool;
//! - `custody-discovery`: finding, requesting and confirming custody nodes
//!   among contacts;
//! - `pool-release`: releases to a pool's vouched recipients (Plan B S1);
//! - `pool-session`: pool descriptors and viewing sessions (Plan B S3);
//! - `pool-play`: playing from any Home through the item's pool (Plan B S4);
//! - `pool-hosting`: a Home that serves several pools, and its Hosting view
//!   (Plan B S2).

/// What kind of wire item a row declares.
// Rows are read by the conformance tests and the #173 record today; later
// Plan B tasks read their ops and approvals at run time.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SurfaceKind {
    /// A provider target that a Carrier peer may invoke. A runtime provider
    /// target is served by the Runtime's own provider registry entry.
    CarrierTarget { runtime_provider: bool },
    /// An op that a Carrier peer may invoke on `target`.
    CarrierOp { target: &'static str },
    /// An op of `target` that only the Runtime's own local provider plane
    /// may invoke. The Carrier allow-list never admits it.
    RuntimeLocalOp { target: &'static str },
    /// A gateway route; `id` is its path pattern.
    Route { method: &'static str },
    /// A passkey step-up operation the Runtime asks for before a write.
    StepUpOp,
    /// A method of the Custody capsule's interface.
    CapsuleMethod,
    /// The payload type of a signed custody collaboration message.
    MessageType,
    /// An operator-control action a custody node answers over Carrier.
    OperatorAction,
    /// The kind of an Inbox entry the Runtime shows for custody.
    InboxKind,
    /// The id prefix of an Inbox action that decides a custody request.
    InboxAction,

    /// A provider target only the Runtime itself invokes. The Carrier
    /// allow-list never admits it.
    RuntimeOnlyTarget,
    /// A setting only the operator's local `elastos setup` writes. No
    /// capsule, app, gateway route or Carrier peer reaches it.
    OperatorSetting,
    /// A code a node's signed decision declines a request with; `message`
    /// is the message type that carries it.
    DeclineCode { message: &'static str },
}

/// Whether the #173 approval record already covers an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Approval {
    Existing,
    Pending173,
}

/// One declared custody wire item.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SurfaceItem {
    pub id: &'static str,
    pub kind: SurfaceKind,
    pub stage: &'static str,
    pub approval: Approval,
}

impl SurfaceItem {
    /// The identity of a row: one id may be a route for two methods, or a
    /// step-up op and a capsule method of the same name.
    #[cfg(test)]
    pub(crate) fn key(&self) -> (SurfaceKind, &'static str) {
        (self.kind, self.id)
    }
}

const STAGE_RUNTIME_CUSTODY: &str = "runtime-custody";
const STAGE_CUSTODY_APP: &str = "custody-app";
const STAGE_CUSTODY_DISCOVERY: &str = "custody-discovery";
const STAGE_POOL_RELEASE: &str = "pool-release";
const STAGE_POOL_SESSION: &str = "pool-session";
pub(crate) const STAGE_POOL_PLAY: &str = "pool-play";
/// #388 and Plan B S2: who may host other parties' keys.
pub(crate) const STAGE_POOL_HOSTING: &str = "pool-hosting";
/// Plan B S7-lite: admitted Homes mint into a pool.
pub(crate) const STAGE_POOL_SEAL: &str = "pool-seal";

// Carrier targets and their ops.
pub(crate) const TARGET_CUSTODY: &str = "custody";
pub(crate) const TARGET_COLLABORATION_CUSTODY: &str = "collaboration-custody";
/// Plan B T3.4: a pool member's viewing-session service (runtime provider).
pub(crate) const TARGET_CUSTODY_POOL: &str = "custody-pool";
pub(crate) const OP_CUSTODY_STATUS: &str = "status";
pub(crate) const OP_CUSTODY_PROVISION_NODE_SHARE: &str = "provision_node_share";
pub(crate) const OP_CUSTODY_RELEASE_CONTRIBUTION: &str = "release_contribution";
pub(crate) const OP_CUSTODY_RELEASE_POOL_CONTRIBUTION: &str = "release_pool_contribution";
pub(crate) const OP_CUSTODY_SIGN_POOL_STATEMENT: &str = "sign_pool_statement";
/// Plan B S7-lite T7.3: an admitted minter provisions a pool node's share.
pub(crate) const OP_CUSTODY_PROVISION_POOL_NODE_SHARE: &str = "provision_pool_node_share";
pub(crate) const OP_CUSTODY_EVALUATE: &str = "evaluate";
pub(crate) const OP_COLLABORATION_CUSTODY_QUERY: &str = "query";
pub(crate) const OP_COLLABORATION_CUSTODY_DELIVER: &str = "deliver";
pub(crate) const OP_CUSTODY_POOL_DESCRIBE: &str = "describe";
pub(crate) const OP_CUSTODY_POOL_SESSION_PREPARE: &str = "session.prepare";
pub(crate) const OP_CUSTODY_POOL_SESSION_OPEN: &str = "session.open";
pub(crate) const OP_CUSTODY_POOL_SESSION_READ: &str = "session.read";
pub(crate) const OP_CUSTODY_POOL_SESSION_CLOSE: &str = "session.close";

// Gateway routes of the Custody app.
pub(crate) const ROUTE_SUMMARY: &str = "/api/apps/custody/summary";
pub(crate) const ROUTE_SIGNING_KEY: &str = "/api/apps/custody/signing-key";
pub(crate) const ROUTE_NODE_CARDS_READ: &str = "/api/apps/custody/node-cards/read";
pub(crate) const ROUTE_NODE_CARDS_FETCH: &str = "/api/apps/custody/node-cards/fetch";
pub(crate) const ROUTE_LOCAL_NODE: &str = "/api/apps/custody/local-node";
pub(crate) const ROUTE_POOL_CHECK: &str = "/api/apps/custody/pool/check";
pub(crate) const ROUTE_POOL: &str = "/api/apps/custody/pool";
pub(crate) const ROUTE_POOL_VERIFY: &str = "/api/apps/custody/pool/verify";
pub(crate) const ROUTE_POOL_NOTIFY: &str = "/api/apps/custody/pool/notify";
pub(crate) const ROUTE_POOL_HEALTH: &str = "/api/apps/custody/pool/health";
pub(crate) const ROUTE_POOL_MEMBER_REGISTER: &str =
    "/api/apps/custody/pool/members/:share/register";
pub(crate) const ROUTE_OFFER: &str = "/api/apps/custody/offer";
pub(crate) const ROUTE_NODES_FIND: &str = "/api/apps/custody/nodes/find";
pub(crate) const ROUTE_NODE_REQUESTS: &str = "/api/apps/custody/node-requests";
pub(crate) const ROUTE_MESSAGES_ENABLE: &str = "/api/apps/custody/messages/enable";
/// Plan B T4.3: the pools this Home uses (GET lists, POST adds by address).
pub(crate) const ROUTE_POOLS_KNOWN: &str = "/api/apps/custody/pools/known";
/// Plan B T2.3: the pools this Home serves (GET), and Stop serving one
/// (DELETE; `:pool` is the pool fingerprint's 64 hex digits, never a DID).
pub(crate) const ROUTE_POOLS_SERVED: &str = "/api/apps/custody/pools/served";
pub(crate) const ROUTE_POOL_SERVED: &str = "/api/apps/custody/pools/served/:pool";
/// Plan B T2.3 (S2-A3, S2-R3-F1): Confirm publisher for a served pool or this
/// Home's own pool (POST).
pub(crate) const ROUTE_POOL_SERVED_PUBLISHER: &str =
    "/api/apps/custody/pools/served/:pool/publisher";

// Passkey step-up operations.
pub(crate) const STEP_UP_LOCAL_NODE_INCLUDE: &str = "custody.local_node.include";
pub(crate) const STEP_UP_LOCAL_NODE_REMOVE: &str = "custody.local_node.remove";
pub(crate) const STEP_UP_POOL_INSTALL: &str = "custody.pool.install";
pub(crate) const STEP_UP_MESSAGES_ENABLE: &str = "custody.messages.enable";
pub(crate) const STEP_UP_NODE_REQUEST_APPROVE: &str = "custody.node_request.approve";
pub(crate) const STEP_UP_KNOWN_POOL_ADD: &str = "custody.known_pool.add";
pub(crate) const STEP_UP_SERVED_POOL_REMOVE: &str = "custody.served_pool.remove";
pub(crate) const STEP_UP_SERVED_POOL_CONFIRM_PUBLISHER: &str =
    "custody.served_pool.confirm_publisher";

// Custody capsule methods declared by later stages (the earlier ones are
// named in their rows).
pub(crate) const METHOD_KNOWN_POOLS_READ: &str = "custody.known_pools.read";
pub(crate) const METHOD_KNOWN_POOL_ADD: &str = "custody.known_pool.add";
pub(crate) const METHOD_SERVED_POOLS_READ: &str = "custody.served_pools.read";
pub(crate) const METHOD_SERVED_POOL_REMOVE: &str = "custody.served_pool.remove";
pub(crate) const METHOD_SERVED_POOL_CONFIRM_PUBLISHER: &str =
    "custody.served_pool.confirm_publisher";

// Signed custody messages: the collaboration service and its payload types.
pub(crate) const MESSAGE_SERVICE_CUSTODY: &str = "custody";
pub(crate) const MESSAGE_OFFER_QUERY: &str = "elastos.custody.offer-query/v1";
pub(crate) const MESSAGE_OFFER: &str = "elastos.custody.offer/v1";
pub(crate) const MESSAGE_NODE_REQUEST: &str = "elastos.custody.node-request/v1";
pub(crate) const MESSAGE_NODE_DECISION: &str = "elastos.custody.node-decision/v1";
pub(crate) const MESSAGE_POOL_ACTIVE: &str = "elastos.custody.pool-active/v1";
pub(crate) const MESSAGE_POOL_DESCRIPTOR: &str = "elastos.custody.pool-descriptor/v1";

// The codes a node declines a custody request with (node-decision payload).
pub(crate) const DECLINE_NOT_OFFERING: &str = "not_offering";
pub(crate) const DECLINE_ALREADY_SERVING: &str = "already_serving";
pub(crate) const DECLINE_NOT_ADMIN: &str = "not_admin";
pub(crate) const DECLINE_DECLINED: &str = "declined";
pub(crate) const DECLINE_EXPIRED: &str = "expired";
/// Plan B T2.2 (S2-U1): a ninth pool request.
pub(crate) const DECLINE_TOO_MANY_POOLS: &str = "too_many_pools";

// Operator-control actions a custody node answers.
pub(crate) const OPERATOR_ACTION_NODE_CARD_READ: &str = "custody.node_card.read";
/// #388 A1: the host trust setting (`elastos setup --host-trust`); see
/// `crate::host_trust`.
pub(crate) const OPERATOR_SETTING_HOST_TRUST: &str = "protected-content.host_trust";

// Inbox entries and actions.
/// OPEN-LOOP F1 (ADV-14): the one consent a pool member gives names both of
/// its duties. The Inbox approval card shows the same sentence.
pub(crate) const NODE_REQUEST_DUTIES: &str =
    "This Home will hold a key share and keep a copy of this pool's files.";
pub(crate) const INBOX_KIND_NODE_REQUEST: &str = "custody_node_request";
pub(crate) const INBOX_KIND_NODE_APPROVING: &str = "custody_node_approving";
pub(crate) const INBOX_KIND_NODE_RESUMABLE: &str = "custody_node_resumable";
pub(crate) const INBOX_KIND_NODE_INCOMPLETE: &str = "custody_node_incomplete";
pub(crate) const INBOX_KIND_NODE_TAKEN: &str = "custody_node_taken";
pub(crate) const INBOX_KIND_POOL_ACTIVE: &str = "custody_pool_active";
pub(crate) const INBOX_ACTION_APPROVE_REQUEST: &str = "custody-approve-request";
pub(crate) const INBOX_ACTION_DECLINE_REQUEST: &str = "custody-decline-request";

const fn item(
    id: &'static str,
    kind: SurfaceKind,
    stage: &'static str,
    approval: Approval,
) -> SurfaceItem {
    SurfaceItem {
        id,
        kind,
        stage,
        approval,
    }
}

const fn existing(id: &'static str, kind: SurfaceKind, stage: &'static str) -> SurfaceItem {
    item(id, kind, stage, Approval::Existing)
}

const fn pending(id: &'static str, kind: SurfaceKind, stage: &'static str) -> SurfaceItem {
    item(id, kind, stage, Approval::Pending173)
}

const fn route(method: &'static str) -> SurfaceKind {
    SurfaceKind::Route { method }
}

const CUSTODY_OP: SurfaceKind = SurfaceKind::CarrierOp {
    target: TARGET_CUSTODY,
};
const CUSTODY_LOCAL_OP: SurfaceKind = SurfaceKind::RuntimeLocalOp {
    target: TARGET_CUSTODY,
};
const CUSTODY_POOL_OP: SurfaceKind = SurfaceKind::CarrierOp {
    target: TARGET_CUSTODY_POOL,
};
const COLLABORATION_CUSTODY_OP: SurfaceKind = SurfaceKind::CarrierOp {
    target: TARGET_COLLABORATION_CUSTODY,
};
const DECLINE: SurfaceKind = SurfaceKind::DeclineCode {
    message: MESSAGE_NODE_DECISION,
};
const STEP_UP: SurfaceKind = SurfaceKind::StepUpOp;
const METHOD: SurfaceKind = SurfaceKind::CapsuleMethod;
const MESSAGE: SurfaceKind = SurfaceKind::MessageType;
const INBOX_KIND: SurfaceKind = SurfaceKind::InboxKind;
const INBOX_ACTION: SurfaceKind = SurfaceKind::InboxAction;

/// Every custody wire item.
pub(crate) const CUSTODY_SURFACE: &[SurfaceItem] = &[
    // Carrier targets.
    existing(
        TARGET_CUSTODY,
        SurfaceKind::CarrierTarget {
            runtime_provider: true,
        },
        STAGE_RUNTIME_CUSTODY,
    ),
    pending(
        TARGET_COLLABORATION_CUSTODY,
        SurfaceKind::CarrierTarget {
            runtime_provider: false,
        },
        STAGE_CUSTODY_DISCOVERY,
    ),
    pending(
        TARGET_CUSTODY_POOL,
        SurfaceKind::CarrierTarget {
            runtime_provider: true,
        },
        STAGE_POOL_SESSION,
    ),
    // Carrier ops.
    existing(OP_CUSTODY_STATUS, CUSTODY_OP, STAGE_RUNTIME_CUSTODY),
    existing(
        OP_CUSTODY_PROVISION_NODE_SHARE,
        CUSTODY_OP,
        STAGE_RUNTIME_CUSTODY,
    ),
    existing(
        OP_CUSTODY_RELEASE_CONTRIBUTION,
        CUSTODY_OP,
        STAGE_RUNTIME_CUSTODY,
    ),
    existing(OP_CUSTODY_EVALUATE, CUSTODY_OP, STAGE_RUNTIME_CUSTODY),
    pending(
        OP_CUSTODY_RELEASE_POOL_CONTRIBUTION,
        CUSTODY_OP,
        STAGE_POOL_RELEASE,
    ),
    pending(
        OP_CUSTODY_SIGN_POOL_STATEMENT,
        CUSTODY_LOCAL_OP,
        STAGE_POOL_RELEASE,
    ),
    pending(
        OP_CUSTODY_PROVISION_POOL_NODE_SHARE,
        CUSTODY_OP,
        STAGE_POOL_SEAL,
    ),
    pending(
        OP_COLLABORATION_CUSTODY_QUERY,
        COLLABORATION_CUSTODY_OP,
        STAGE_CUSTODY_DISCOVERY,
    ),
    pending(
        OP_COLLABORATION_CUSTODY_DELIVER,
        COLLABORATION_CUSTODY_OP,
        STAGE_CUSTODY_DISCOVERY,
    ),
    pending(
        OP_CUSTODY_POOL_DESCRIBE,
        CUSTODY_POOL_OP,
        STAGE_POOL_SESSION,
    ),
    pending(
        OP_CUSTODY_POOL_SESSION_PREPARE,
        CUSTODY_POOL_OP,
        STAGE_POOL_SESSION,
    ),
    pending(
        OP_CUSTODY_POOL_SESSION_OPEN,
        CUSTODY_POOL_OP,
        STAGE_POOL_SESSION,
    ),
    pending(
        OP_CUSTODY_POOL_SESSION_READ,
        CUSTODY_POOL_OP,
        STAGE_POOL_SESSION,
    ),
    pending(
        OP_CUSTODY_POOL_SESSION_CLOSE,
        CUSTODY_POOL_OP,
        STAGE_POOL_SESSION,
    ),
    // Routes.
    existing(ROUTE_SUMMARY, route("GET"), STAGE_CUSTODY_APP),
    existing(ROUTE_SIGNING_KEY, route("POST"), STAGE_CUSTODY_APP),
    existing(ROUTE_NODE_CARDS_READ, route("POST"), STAGE_CUSTODY_APP),
    existing(ROUTE_NODE_CARDS_FETCH, route("POST"), STAGE_CUSTODY_APP),
    existing(ROUTE_LOCAL_NODE, route("POST"), STAGE_CUSTODY_APP),
    pending(ROUTE_LOCAL_NODE, route("DELETE"), STAGE_CUSTODY_APP),
    existing(ROUTE_POOL_CHECK, route("POST"), STAGE_CUSTODY_APP),
    existing(ROUTE_POOL, route("GET"), STAGE_CUSTODY_APP),
    existing(ROUTE_POOL, route("POST"), STAGE_CUSTODY_APP),
    existing(ROUTE_POOL_VERIFY, route("POST"), STAGE_CUSTODY_APP),
    pending(ROUTE_POOL_NOTIFY, route("POST"), STAGE_CUSTODY_DISCOVERY),
    existing(ROUTE_POOL_HEALTH, route("GET"), STAGE_CUSTODY_APP),
    existing(ROUTE_POOL_MEMBER_REGISTER, route("POST"), STAGE_CUSTODY_APP),
    pending(ROUTE_OFFER, route("GET"), STAGE_CUSTODY_DISCOVERY),
    pending(ROUTE_OFFER, route("POST"), STAGE_CUSTODY_DISCOVERY),
    pending(ROUTE_NODES_FIND, route("POST"), STAGE_CUSTODY_DISCOVERY),
    pending(ROUTE_NODE_REQUESTS, route("POST"), STAGE_CUSTODY_DISCOVERY),
    pending(
        ROUTE_MESSAGES_ENABLE,
        route("POST"),
        STAGE_CUSTODY_DISCOVERY,
    ),
    pending(ROUTE_POOLS_KNOWN, route("GET"), STAGE_POOL_PLAY),
    pending(ROUTE_POOLS_KNOWN, route("POST"), STAGE_POOL_PLAY),
    pending(ROUTE_POOLS_SERVED, route("GET"), STAGE_POOL_HOSTING),
    pending(ROUTE_POOL_SERVED, route("DELETE"), STAGE_POOL_HOSTING),
    pending(
        ROUTE_POOL_SERVED_PUBLISHER,
        route("POST"),
        STAGE_POOL_HOSTING,
    ),
    // Passkey step-up operations.
    existing(STEP_UP_LOCAL_NODE_INCLUDE, STEP_UP, STAGE_CUSTODY_APP),
    pending(STEP_UP_LOCAL_NODE_REMOVE, STEP_UP, STAGE_CUSTODY_APP),
    existing(STEP_UP_POOL_INSTALL, STEP_UP, STAGE_CUSTODY_APP),
    pending(STEP_UP_MESSAGES_ENABLE, STEP_UP, STAGE_CUSTODY_DISCOVERY),
    pending(
        STEP_UP_NODE_REQUEST_APPROVE,
        STEP_UP,
        STAGE_CUSTODY_DISCOVERY,
    ),
    pending(STEP_UP_KNOWN_POOL_ADD, STEP_UP, STAGE_POOL_PLAY),
    pending(STEP_UP_SERVED_POOL_REMOVE, STEP_UP, STAGE_POOL_HOSTING),
    pending(
        STEP_UP_SERVED_POOL_CONFIRM_PUBLISHER,
        STEP_UP,
        STAGE_POOL_HOSTING,
    ),
    // Custody capsule methods (capsules/custody/capsule.json).
    existing("custody.summary", METHOD, STAGE_CUSTODY_APP),
    existing("custody.signing_key.create", METHOD, STAGE_CUSTODY_APP),
    existing("custody.node_card.read", METHOD, STAGE_CUSTODY_APP),
    existing("custody.node_card.fetch", METHOD, STAGE_CUSTODY_APP),
    existing("custody.local_node.include", METHOD, STAGE_CUSTODY_APP),
    pending("custody.local_node.remove", METHOD, STAGE_CUSTODY_APP),
    existing("custody.pool.check", METHOD, STAGE_CUSTODY_APP),
    existing("custody.pool.install", METHOD, STAGE_CUSTODY_APP),
    existing("custody.pool.verify", METHOD, STAGE_CUSTODY_APP),
    pending("custody.pool.notify", METHOD, STAGE_CUSTODY_DISCOVERY),
    existing("custody.pool.read", METHOD, STAGE_CUSTODY_APP),
    existing("custody.pool.health", METHOD, STAGE_CUSTODY_APP),
    existing("custody.node.register", METHOD, STAGE_CUSTODY_APP),
    pending("custody.offer.read", METHOD, STAGE_CUSTODY_DISCOVERY),
    pending("custody.offer.set", METHOD, STAGE_CUSTODY_DISCOVERY),
    pending("custody.messages.enable", METHOD, STAGE_CUSTODY_DISCOVERY),
    pending("custody.nodes.find", METHOD, STAGE_CUSTODY_DISCOVERY),
    pending(
        "custody.node_requests.send",
        METHOD,
        STAGE_CUSTODY_DISCOVERY,
    ),
    pending(METHOD_KNOWN_POOLS_READ, METHOD, STAGE_POOL_PLAY),
    pending(METHOD_SERVED_POOLS_READ, METHOD, STAGE_POOL_HOSTING),
    pending(METHOD_SERVED_POOL_REMOVE, METHOD, STAGE_POOL_HOSTING),
    pending(
        METHOD_SERVED_POOL_CONFIRM_PUBLISHER,
        METHOD,
        STAGE_POOL_HOSTING,
    ),
    pending(METHOD_KNOWN_POOL_ADD, METHOD, STAGE_POOL_PLAY),
    // Signed custody message types.
    pending(MESSAGE_OFFER_QUERY, MESSAGE, STAGE_CUSTODY_DISCOVERY),
    pending(MESSAGE_OFFER, MESSAGE, STAGE_CUSTODY_DISCOVERY),
    pending(MESSAGE_NODE_REQUEST, MESSAGE, STAGE_CUSTODY_DISCOVERY),
    pending(MESSAGE_NODE_DECISION, MESSAGE, STAGE_CUSTODY_DISCOVERY),
    pending(MESSAGE_POOL_ACTIVE, MESSAGE, STAGE_CUSTODY_DISCOVERY),
    pending(MESSAGE_POOL_DESCRIPTOR, MESSAGE, STAGE_POOL_SESSION),
    // Operator-control actions.
    existing(
        OPERATOR_ACTION_NODE_CARD_READ,
        SurfaceKind::OperatorAction,
        STAGE_CUSTODY_APP,
    ),
    // Inbox entries and actions.
    pending(INBOX_KIND_NODE_REQUEST, INBOX_KIND, STAGE_CUSTODY_DISCOVERY),
    pending(
        INBOX_KIND_NODE_APPROVING,
        INBOX_KIND,
        STAGE_CUSTODY_DISCOVERY,
    ),
    pending(
        INBOX_KIND_NODE_RESUMABLE,
        INBOX_KIND,
        STAGE_CUSTODY_DISCOVERY,
    ),
    pending(
        INBOX_KIND_NODE_INCOMPLETE,
        INBOX_KIND,
        STAGE_CUSTODY_DISCOVERY,
    ),
    pending(INBOX_KIND_NODE_TAKEN, INBOX_KIND, STAGE_CUSTODY_DISCOVERY),
    pending(INBOX_KIND_POOL_ACTIVE, INBOX_KIND, STAGE_CUSTODY_DISCOVERY),
    pending(
        INBOX_ACTION_APPROVE_REQUEST,
        INBOX_ACTION,
        STAGE_CUSTODY_DISCOVERY,
    ),
    pending(
        INBOX_ACTION_DECLINE_REQUEST,
        INBOX_ACTION,
        STAGE_CUSTODY_DISCOVERY,
    ),
    // #388 A1: the host trust operator setting.
    pending(
        OPERATOR_SETTING_HOST_TRUST,
        SurfaceKind::OperatorSetting,
        STAGE_POOL_HOSTING,
    ),
    // The decline codes of a node decision (Plan B T2.2 declares them).
    existing(DECLINE_NOT_OFFERING, DECLINE, STAGE_CUSTODY_DISCOVERY),
    existing(DECLINE_ALREADY_SERVING, DECLINE, STAGE_CUSTODY_DISCOVERY),
    existing(DECLINE_NOT_ADMIN, DECLINE, STAGE_CUSTODY_DISCOVERY),
    existing(DECLINE_DECLINED, DECLINE, STAGE_CUSTODY_DISCOVERY),
    existing(DECLINE_EXPIRED, DECLINE, STAGE_CUSTODY_DISCOVERY),
    pending(DECLINE_TOO_MANY_POOLS, DECLINE, STAGE_POOL_HOSTING),
];

/// META-PUBLIC: the Creator's public IPFS store.
const STAGE_META_PUBLIC: &str = "meta-public";

/// A5 (META-PUBLIC amendment §2.1): the `config.toml` key that offers public
/// metadata sharing on this Home, beside protected content, and its default.
/// Sharing stays closed until both opening conditions hold:
/// 1. Anders' 5 Nov "Done means" (#388) is met with the creator's Home
///    stopped, the indexer refresh included (amendment §2.2 evidence);
/// 2. the #173 approval record covers the rows below.
///
/// Opening flips [`PUBLIC_METADATA_DEFAULT`]. Proof Homes open it locally with
/// `elastos config set public_metadata true`.
pub(crate) const PUBLIC_METADATA_CONFIG_KEY: &str = "public_metadata";
pub(crate) const PUBLIC_METADATA_DEFAULT: bool = false;

// The Creator's read-only status of its public IPFS store. Consent and Stop
// live in Inbox (A4).
pub(crate) const ROUTE_PUBLIC_IPFS: &str = "/api/apps/creator/public-ipfs";

// A4: the public metadata card in Inbox, one kind per state (amendment
// §1.3), and its two actions.
pub(crate) const INBOX_KIND_PUBLIC_METADATA_CONSENT: &str = "public_metadata_consent";
pub(crate) const INBOX_KIND_PUBLIC_METADATA_SHARING: &str = "public_metadata_sharing";
pub(crate) const INBOX_KIND_PUBLIC_METADATA_PAUSED: &str = "public_metadata_paused";
pub(crate) const INBOX_KIND_PUBLIC_METADATA_STOPPING: &str = "public_metadata_stopping";
pub(crate) const INBOX_KIND_PUBLIC_METADATA_UNREADABLE: &str = "public_metadata_unreadable";
pub(crate) const INBOX_ACTION_PUBLIC_METADATA_ENABLE: &str = "public-metadata-enable";
pub(crate) const INBOX_ACTION_PUBLIC_METADATA_STOP: &str = "public-metadata-stop";

/// The public IPFS store's wire items, declared beside the custody surface.
/// None of them is a Carrier item: its target is Runtime-only, so the
/// Carrier allow-list, which reads [`CUSTODY_SURFACE`], never sees them.
pub(crate) const PUBLIC_STORE_SURFACE: &[SurfaceItem] = &[
    pending(ROUTE_PUBLIC_IPFS, route("GET"), STAGE_META_PUBLIC),
    pending(
        crate::public_metadata_consent::ENABLE_OPERATION,
        STEP_UP,
        STAGE_META_PUBLIC,
    ),
    pending(
        elastos_runtime::provider::PUBLIC_IPFS_TARGET,
        SurfaceKind::RuntimeOnlyTarget,
        STAGE_META_PUBLIC,
    ),
    pending(
        INBOX_KIND_PUBLIC_METADATA_CONSENT,
        INBOX_KIND,
        STAGE_META_PUBLIC,
    ),
    pending(
        INBOX_KIND_PUBLIC_METADATA_SHARING,
        INBOX_KIND,
        STAGE_META_PUBLIC,
    ),
    pending(
        INBOX_KIND_PUBLIC_METADATA_PAUSED,
        INBOX_KIND,
        STAGE_META_PUBLIC,
    ),
    pending(
        INBOX_KIND_PUBLIC_METADATA_STOPPING,
        INBOX_KIND,
        STAGE_META_PUBLIC,
    ),
    pending(
        INBOX_KIND_PUBLIC_METADATA_UNREADABLE,
        INBOX_KIND,
        STAGE_META_PUBLIC,
    ),
    pending(
        INBOX_ACTION_PUBLIC_METADATA_ENABLE,
        INBOX_ACTION,
        STAGE_META_PUBLIC,
    ),
    pending(
        INBOX_ACTION_PUBLIC_METADATA_STOP,
        INBOX_ACTION,
        STAGE_META_PUBLIC,
    ),
];

fn carrier_target(target: &str) -> Option<&'static SurfaceItem> {
    CUSTODY_SURFACE
        .iter()
        .find(|item| item.id == target && matches!(item.kind, SurfaceKind::CarrierTarget { .. }))
}

/// Whether a Carrier peer may invoke the custody provider target `target`.
pub(crate) fn carrier_target_allowed(target: &str) -> bool {
    carrier_target(target).is_some()
}

/// Whether `target` is a custody target the Runtime serves from its own
/// provider registry entry rather than a provider process.
pub(crate) fn is_runtime_provider_target(target: &str) -> bool {
    matches!(
        carrier_target(target).map(|item| item.kind),
        Some(SurfaceKind::CarrierTarget {
            runtime_provider: true
        })
    )
}

/// Whether `op` is a declared Carrier op of the custody target `target`.
pub(crate) fn carrier_op_allowed(target: &str, op: &str) -> bool {
    CUSTODY_SURFACE.iter().any(|item| {
        item.id == op
            && matches!(item.kind, SurfaceKind::CarrierOp { target: declared } if declared == target)
    })
}

/// Whether `op` is an op of `target` reserved for the Runtime's own local
/// provider plane. The local plane admits these and every Carrier op.
pub(crate) fn runtime_local_op_allowed(target: &str, op: &str) -> bool {
    CUSTODY_SURFACE.iter().any(|item| {
        item.id == op
            && matches!(item.kind, SurfaceKind::RuntimeLocalOp { target: declared } if declared == target)
    })
}

/// Every op `target` declares, on either plane, in surface order.
pub(crate) fn declared_ops(target: &str) -> impl Iterator<Item = &'static str> + '_ {
    CUSTODY_SURFACE
        .iter()
        .filter_map(move |item| match item.kind {
            SurfaceKind::CarrierOp { target: declared }
            | SurfaceKind::RuntimeLocalOp { target: declared }
                if declared == target =>
            {
                Some(item.id)
            }
            _ => None,
        })
}

/// Every decline code the surface declares, in surface order.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn declared_decline_codes() -> impl Iterator<Item = &'static str> {
    CUSTODY_SURFACE.iter().filter_map(|item| match item.kind {
        SurfaceKind::DeclineCode { .. } => Some(item.id),
        _ => None,
    })
}

/// The items still waiting for their #173 approval record.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn pending_approvals() -> Vec<&'static SurfaceItem> {
    CUSTODY_SURFACE
        .iter()
        .chain(PUBLIC_STORE_SURFACE)
        .filter(|item| item.approval == Approval::Pending173)
        .collect()
}

#[cfg(test)]
mod tests;
