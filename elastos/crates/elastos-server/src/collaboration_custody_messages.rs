//! Runtime-owned custody message transport between contacts' Homes.
//!
//! A Home finds, asks and confirms custody nodes among its accepted People
//! contacts over this plane: `query` answers an offer query synchronously,
//! and `deliver` hands a request, decision or pool notice to the receiving
//! Home and returns a signed acceptance receipt. It is its own provider
//! scheme, like Profile updates, so no custody message ever rides on Chat.
//!
//! The transport proves who is speaking and nothing else: the authenticated
//! Carrier source endpoint is the contact Profile's sole endpoint, which is
//! the verified signer. What a message means is the business of the
//! [`CustodyMessageHandler`] the node and owner sides install.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::Context as _;
use base64::Engine as _;
use elastos_common::collaboration_protocol::SignedCollaborationMessage;
use elastos_runtime::provider::{
    Provider, ProviderCarrierRoute, ProviderError, ProviderInvocation, ProviderInvocationTransport,
    ProviderRegistry, ProviderTransfer,
};
use elastos_runtime::signature::SigningKey;
use serde::{Deserialize, Serialize};

use crate::collaboration_contact_store::CollaborationContactStore;
use crate::collaboration_network::VerifiedCollaborationNetworkProfile;
use crate::collaboration_profile_authority::VerifiedCollaborationProfileDocument;
use crate::custody_consent_protocol::{
    claimed_custody_message_type, prepare_custody_message, verify_custody_message,
    CustodyDeclineCode, CustodyMessageRefusal, CustodyMessageType, CustodyNodeDecisionPayload,
    CustodyNodeRequestPayload, CustodyOfferPayload, CustodyOfferQueryPayload, CustodyPayload,
    CustodyPoolActivePayload, CustodyPoolDescriptorPayload, VerifiedCustodyMessage,
    CUSTODY_SERVICE, CUSTODY_SIGNING_SCOPE,
};

pub(crate) const CUSTODY_MESSAGE_PROVIDER_SCHEME: &str =
    crate::custody_surface::TARGET_COLLABORATION_CUSTODY;
/// How long one custody call to a peer may take.
pub(crate) const CUSTODY_PROVIDER_TIMEOUT_MS: u64 = 5_000;
const MAX_CUSTODY_CONTEXTS: usize = 32;
const MAX_CUSTODY_WIRE_BASE64_BYTES: usize = 128 * 1024;
const MAX_CUSTODY_REFUSAL_CODE_BYTES: usize = 32;
/// Receipts kept so a sender's retry of a message this Home already took
/// settles without reaching the handler again.
const MAX_CUSTODY_RECEIPTS: usize = 256;
const MAX_CUSTODY_OUTBOX_ITEMS: usize = 32;
const MAX_CUSTODY_OUTBOX_KEY_BYTES: usize = 128;
const MAX_CUSTODY_DELIVERIES_PER_PASS: usize = 4;
const CUSTODY_SYNC_CADENCE_SECS: u64 = 15;
/// Declared end-of-life for custody deliveries: an envelope the recipient
/// never took within its signed lifetime is shown as expired and never
/// re-delivered. Durable truth (requests, decisions, pool notices) lives with
/// the node and owner sides, which sign a fresh envelope when they want one.
const DECLARED_CUSTODY_END_OF_LIFE: crate::collaboration_delivery::DeliveryEndOfLife =
    crate::collaboration_delivery::DeliveryEndOfLife::TerminalExpired;

/// Enables custody messages for this Home's admin: a new passkey-bound
/// Profile revision grants the custody scope to the current endpoint
/// signer, re-granting it after an endpoint rotation. The app's
/// "Enable custody messages" route calls it after a passkey step.
pub(crate) fn ensure_custody_signing_scope(
    data_dir: &Path,
    principal_id: &str,
    localhost_root: &str,
    proof_binding_id: &str,
    now: u64,
) -> anyhow::Result<VerifiedCollaborationProfileDocument> {
    crate::collaboration_profile_authority::grant_profile_signing_scope(
        data_dir,
        principal_id,
        localhost_root,
        proof_binding_id,
        CUSTODY_SIGNING_SCOPE,
        now,
    )
}

/// A stable refusal code on the custody plane. Before the sender is proven
/// to be an accepted contact the codes say nothing about who this Home knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CustodyRefusal(&'static str);

impl CustodyRefusal {
    /// Malformed request, or a message type the invoked op does not carry.
    pub(crate) const INVALID_REQUEST: Self = Self("invalid_request");
    /// Not an accepted contact of the addressed Profile, or not from that
    /// contact's Profile endpoint. One code, so it is no contact oracle.
    pub(crate) const NOT_CONTACT: Self = Self("not_contact");
    /// This Home cannot answer for the addressed Profile right now.
    pub(crate) const UNAVAILABLE: Self = Self("unavailable");
    /// The sender's Profile, as this Home knows it, lacks the custody scope.
    pub(crate) const NEEDS_UPDATE: Self = Self("needs_update");
    pub(crate) const NOT_OFFERING: Self = Self("not_offering");
    pub(crate) const REFUSED: Self = Self("refused");

    /// A handler's own code: lowercase snake case, at most 32 bytes.
    pub(crate) const fn new(code: &'static str) -> Self {
        Self(code)
    }

    pub(crate) fn code(self) -> &'static str {
        if is_wire_code(self.0) {
            self.0
        } else {
            Self::REFUSED.0
        }
    }
}

impl From<CustodyMessageRefusal> for CustodyRefusal {
    fn from(refusal: CustodyMessageRefusal) -> Self {
        match refusal {
            CustodyMessageRefusal::SignerNotAuthorized => Self::NEEDS_UPDATE,
            other => Self(other.code()),
        }
    }
}

impl From<CustodyDeclineCode> for CustodyRefusal {
    fn from(code: CustodyDeclineCode) -> Self {
        Self(code.code())
    }
}

impl std::fmt::Display for CustodyRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "custody message refused: {}", self.code())
    }
}

impl std::error::Error for CustodyRefusal {}

fn is_wire_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= MAX_CUSTODY_REFUSAL_CODE_BYTES
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

/// What the transport proved about one received custody message. The sender
/// is an accepted contact of `local_profile`, the message arrived from that
/// contact's Profile endpoint, and that endpoint signed it.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct CustodyInbound<'a> {
    pub(crate) data_dir: &'a Path,
    pub(crate) principal_id: &'a str,
    pub(crate) localhost_root: &'a str,
    /// The receiving Profile, as currently signed on this Home.
    pub(crate) local_profile: &'a VerifiedCollaborationProfileDocument,
    /// The contact's accepted Profile.
    pub(crate) sender_profile: &'a VerifiedCollaborationProfileDocument,
    /// The contact's signed display name.
    pub(crate) sender_display_name: &'a str,
    /// The verified message; its `signer_did` is the sender's Home DID.
    pub(crate) message: &'a VerifiedCustodyMessage,
    /// The exact envelope bytes, for a handler that keeps them.
    pub(crate) envelope: &'a [u8],
    pub(crate) now: u64,
}

/// What the node and owner sides do with verified custody messages. Each
/// method answers or refuses with a stable code. A sender retries a delivery
/// it did not see settle, and this Home forgets receipts on restart, so every
/// method must treat a repeat of the same message as a no-op that succeeds.
pub(crate) trait CustodyMessageHandler: Send + Sync {
    /// A contact asks whether this Home offers custody; the transport signs
    /// the returned offer and answers with it.
    fn on_offer_query(
        &self,
        inbound: &CustodyInbound<'_>,
    ) -> Result<CustodyOfferPayload, CustodyRefusal>;

    fn on_request(
        &self,
        inbound: &CustodyInbound<'_>,
        request: &CustodyNodeRequestPayload,
    ) -> Result<(), CustodyRefusal>;

    fn on_decision(
        &self,
        inbound: &CustodyInbound<'_>,
        decision: &CustodyNodeDecisionPayload,
    ) -> Result<(), CustodyRefusal>;

    fn on_pool_active(
        &self,
        inbound: &CustodyInbound<'_>,
        notice: &CustodyPoolActivePayload,
    ) -> Result<(), CustodyRefusal>;

    /// Plan B T3.3: the owner's signed pool descriptor (L13). A Home that
    /// serves no pool takes none.
    fn on_pool_descriptor(
        &self,
        _inbound: &CustodyInbound<'_>,
        _descriptor: &CustodyPoolDescriptorPayload,
    ) -> Result<(), CustodyRefusal> {
        Err(CustodyRefusal::REFUSED)
    }

    /// Runs before each delivery pass, so a side queues again what its own
    /// records still want sent, such as a message a restart dropped from the
    /// outbox.
    fn before_delivery_pass(&self, _now: u64) {}
}

/// The handler a Home has until custody consent is wired: it offers nothing
/// and takes nothing.
pub(crate) struct NotOfferingCustodyHandler;

impl CustodyMessageHandler for NotOfferingCustodyHandler {
    fn on_offer_query(
        &self,
        _inbound: &CustodyInbound<'_>,
    ) -> Result<CustodyOfferPayload, CustodyRefusal> {
        Err(CustodyRefusal::NOT_OFFERING)
    }

    fn on_request(
        &self,
        _inbound: &CustodyInbound<'_>,
        _request: &CustodyNodeRequestPayload,
    ) -> Result<(), CustodyRefusal> {
        Err(CustodyRefusal::REFUSED)
    }

    fn on_decision(
        &self,
        _inbound: &CustodyInbound<'_>,
        _decision: &CustodyNodeDecisionPayload,
    ) -> Result<(), CustodyRefusal> {
        Err(CustodyRefusal::REFUSED)
    }

    fn on_pool_active(
        &self,
        _inbound: &CustodyInbound<'_>,
        _notice: &CustodyPoolActivePayload,
    ) -> Result<(), CustodyRefusal> {
        Err(CustodyRefusal::REFUSED)
    }

    fn on_pool_descriptor(
        &self,
        _inbound: &CustodyInbound<'_>,
        _descriptor: &CustodyPoolDescriptorPayload,
    ) -> Result<(), CustodyRefusal> {
        Err(CustodyRefusal::REFUSED)
    }
}

/// How a contact answered an offer query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CustodyQueryOutcome {
    /// The contact's signed offer, verified against its accepted Profile.
    Offering(Box<VerifiedCustodyMessage>),
    Refused(String),
    Unreachable,
}

/// One delivery attempt's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CustodyDeliveryOutcome {
    /// The recipient's endpoint returned a verified acceptance receipt.
    Delivered,
    Refused(String),
    Unreachable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CustodyOutboxState {
    Pending,
    Delivered,
    Refused(String),
    /// The envelope's lifetime ended before the recipient took it.
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyProviderOp {
    Query,
    Deliver,
}

impl CustodyProviderOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::Query => crate::custody_surface::OP_COLLABORATION_CUSTODY_QUERY,
            Self::Deliver => crate::custody_surface::OP_COLLABORATION_CUSTODY_DELIVER,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        [Self::Query, Self::Deliver]
            .into_iter()
            .find(|op| op.as_str() == value)
    }

    /// `query` carries only offer queries; offers travel only as its answer.
    fn carries(self, kind: CustodyMessageType) -> bool {
        match self {
            Self::Query => kind == CustodyMessageType::OfferQuery,
            Self::Deliver => matches!(
                kind,
                CustodyMessageType::NodeRequest
                    | CustodyMessageType::NodeDecision
                    | CustodyMessageType::PoolActive
                    | CustodyMessageType::PoolDescriptor
            ),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyProviderRequest {
    op: String,
    message: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyProviderResponse {
    status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    offer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CustodyReply {
    Offer(Vec<u8>),
    Receipt(Vec<u8>),
}

enum CustodyWireReply {
    Offer(Vec<u8>),
    Receipt(Vec<u8>),
    Refused(String),
}

#[derive(Clone)]
pub(crate) struct CollaborationCustodyMessageService {
    inner: Arc<CustodyInner>,
}

/// The service as a handler installed in it holds it: without keeping it
/// alive, so the two never form a cycle.
#[derive(Clone)]
pub(crate) struct WeakCustodyMessageService {
    inner: std::sync::Weak<CustodyInner>,
}

impl WeakCustodyMessageService {
    pub(crate) fn upgrade(&self) -> Option<CollaborationCustodyMessageService> {
        self.inner
            .upgrade()
            .map(|inner| CollaborationCustodyMessageService { inner })
    }
}

struct CustodyInner {
    signing_key: SigningKey,
    /// This Runtime's DID: its Carrier endpoint, and the Profile endpoint
    /// every custody message it sends or answers is signed as.
    signer_did: String,
    network: VerifiedCollaborationNetworkProfile,
    registry: Arc<ProviderRegistry>,
    contexts: Mutex<BTreeMap<String, CustodyContext>>,
    handler: RwLock<Arc<dyn CustodyMessageHandler>>,
    receipts: Mutex<BTreeMap<String, StoredCustodyReceipt>>,
    outbox: Mutex<BTreeMap<String, CustodyOutboxItem>>,
    schedule: Mutex<CustodyPassSchedule>,
}

#[derive(Clone)]
struct CustodyContext {
    contact_store: Arc<CollaborationContactStore>,
    profile: VerifiedCollaborationProfileDocument,
    authority: CustodyContextAuthority,
}

/// Custody messages reach a Home whenever it runs, so its contexts are
/// Runtime-owned: registered at startup for each Profile, and ended by
/// revoking the passkey that bound them.
#[derive(Clone)]
enum CustodyContextAuthority {
    RuntimeOwned { proof_binding_id: String },
}

struct StoredCustodyReceipt {
    receipt: Vec<u8>,
    expires_at: u64,
}

struct CustodyOutboxItem {
    local_profile_did: String,
    envelope: Vec<u8>,
    expires_at: u64,
    state: CustodyOutboxState,
    last_attempt_at: u64,
}

#[derive(Default)]
struct CustodyPassSchedule {
    next_wake_at: u64,
    failures: u8,
}

struct OutboundRoute {
    verified: VerifiedCustodyMessage,
    recipient_endpoint_did: String,
}

impl CollaborationCustodyMessageService {
    pub(crate) async fn new(
        signing_key: SigningKey,
        network: VerifiedCollaborationNetworkProfile,
        registry: Arc<ProviderRegistry>,
    ) -> anyhow::Result<Self> {
        let signer_did = crate::crypto::encode_signing_key_did(&signing_key);
        let inner = Arc::new(CustodyInner {
            signing_key,
            signer_did,
            network,
            registry: registry.clone(),
            contexts: Mutex::new(BTreeMap::new()),
            handler: RwLock::new(Arc::new(NotOfferingCustodyHandler)),
            receipts: Mutex::new(BTreeMap::new()),
            outbox: Mutex::new(BTreeMap::new()),
            schedule: Mutex::new(CustodyPassSchedule::default()),
        });
        let provider: Arc<dyn Provider> = Arc::new(CollaborationCustodyMessageProvider {
            inner: inner.clone(),
        });
        registry.register(provider.clone()).await;
        registry
            .register_sub_provider(CUSTODY_MESSAGE_PROVIDER_SCHEME, provider)
            .await?;
        Ok(Self { inner })
    }

    pub(crate) fn downgrade(&self) -> WeakCustodyMessageService {
        WeakCustodyMessageService {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// Installs what this Home does with verified custody messages.
    pub(crate) fn set_handler(&self, handler: Arc<dyn CustodyMessageHandler>) {
        match self.inner.handler.write() {
            Ok(mut current) => *current = handler,
            Err(poisoned) => *poisoned.into_inner() = handler,
        }
    }

    fn handler(&self) -> Arc<dyn CustodyMessageHandler> {
        match self.inner.handler.read() {
            Ok(current) => current.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Registers the receiving and sending side for a Home's Profile without
    /// a session. A newer Profile revision replaces an older one.
    pub(crate) fn register_runtime_owned_context(
        &self,
        contact_store: Arc<CollaborationContactStore>,
        profile: VerifiedCollaborationProfileDocument,
        proof_binding_id: &str,
    ) -> anyhow::Result<()> {
        self.insert_context(
            contact_store,
            profile,
            CustodyContextAuthority::RuntimeOwned {
                proof_binding_id: proof_binding_id.to_string(),
            },
        )
    }

    fn insert_context(
        &self,
        contact_store: Arc<CollaborationContactStore>,
        profile: VerifiedCollaborationProfileDocument,
        authority: CustodyContextAuthority,
    ) -> anyhow::Result<()> {
        if contact_store.local_profile_did() != profile.document().profile_did {
            anyhow::bail!("custody context profile does not match the scoped store");
        }
        let mut contexts = self
            .inner
            .contexts
            .lock()
            .map_err(|_| anyhow::anyhow!("custody context lock is poisoned"))?;
        let key = profile.document().profile_did.clone();
        match contexts.get(&key) {
            Some(existing)
                if existing.profile.document().revision > profile.document().revision =>
            {
                return Ok(());
            }
            Some(_) => {}
            None if contexts.len() >= MAX_CUSTODY_CONTEXTS => {
                anyhow::bail!("custody context limit reached");
            }
            None => {}
        }
        contexts.insert(
            key,
            CustodyContext {
                contact_store,
                profile,
                authority,
            },
        );
        Ok(())
    }

    fn context(&self, local_profile_did: &str) -> anyhow::Result<CustodyContext> {
        let context = self
            .inner
            .contexts
            .lock()
            .map_err(|_| anyhow::anyhow!("custody context lock is poisoned"))?
            .get(local_profile_did)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("custody context is not registered"))?;
        self.revalidate_context(&context)?;
        Ok(context)
    }

    fn revalidate_context(&self, context: &CustodyContext) -> anyhow::Result<()> {
        match &context.authority {
            CustodyContextAuthority::RuntimeOwned { proof_binding_id } => {
                // Read the durable authority from disk, so a revoked passkey
                // stops custody messages in a running Home.
                let principal = crate::auth::load_principal_for_proof_binding(
                    context.contact_store.data_root(),
                    proof_binding_id,
                )?;
                crate::auth::ensure_proof_binding_not_revoked(&principal)?;
                if principal.principal_id != context.contact_store.principal_id() {
                    anyhow::bail!("custody principal no longer owns the contact store");
                }
                Ok(())
            }
        }
    }

    /// The Profile as currently signed on disk, so enabling custody messages
    /// takes effect without re-registering the context.
    fn current_profile(
        &self,
        context: &CustodyContext,
    ) -> anyhow::Result<VerifiedCollaborationProfileDocument> {
        let profile = match &context.authority {
            CustodyContextAuthority::RuntimeOwned { .. } => {
                crate::collaboration_profile_authority::load_profile_authority(
                    context.contact_store.data_root(),
                    context.contact_store.principal_id(),
                    context.contact_store.localhost_root(),
                )?
                .ok_or_else(|| anyhow::anyhow!("custody context Profile is missing"))?
            }
        };
        if profile.document().profile_did != context.profile.document().profile_did {
            anyhow::bail!("custody context Profile changed identity");
        }
        // A custody message names no issuer: the receiver derives this Home
        // from the signer, so the Profile endpoint must be this Runtime's key.
        if profile.sole_endpoint_did()? != self.inner.signer_did {
            anyhow::bail!("this Home's Profile endpoint is not this Runtime's DID");
        }
        Ok(profile)
    }

    /// Signs a custody message from a local Profile to one of its accepted
    /// contacts.
    pub(crate) fn prepare(
        &self,
        local_profile_did: &str,
        recipient_profile_did: &str,
        payload: &CustodyPayload,
        now: u64,
        expires_at: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let context = self.context(local_profile_did)?;
        let profile = self.current_profile(&context)?;
        if context
            .contact_store
            .accepted_profile(recipient_profile_did)?
            .is_none()
        {
            return Err(CustodyRefusal::NOT_CONTACT.into());
        }
        prepare_custody_message(
            &self.inner.signing_key,
            &self.inner.network,
            &profile,
            recipient_profile_did,
            payload,
            now,
            expires_at,
        )
    }

    /// Asks an accepted contact's Home whether it offers custody. A contact
    /// whose Profile cannot sign an offer is `needs_update` without a call.
    /// Fails with [`CustodyMessageRefusal::SignerNotAuthorized`] when this
    /// Home's own Profile lacks the custody scope.
    pub(crate) async fn query_offer(
        &self,
        local_profile_did: &str,
        contact_profile_did: &str,
        now: u64,
    ) -> anyhow::Result<CustodyQueryOutcome> {
        let context = self.context(local_profile_did)?;
        let profile = self.current_profile(&context)?;
        let contact_profile = context
            .contact_store
            .accepted_profile(contact_profile_did)?
            .ok_or(CustodyRefusal::NOT_CONTACT)?;
        let endpoint_did = contact_profile.sole_endpoint_did()?.to_string();
        if !contact_profile.authorizes_signer(
            &endpoint_did,
            CUSTODY_SERVICE,
            CustodyMessageType::Offer.payload_type(),
        ) {
            return Ok(CustodyQueryOutcome::Refused(
                CustodyRefusal::NEEDS_UPDATE.code().to_string(),
            ));
        }
        let query = prepare_custody_message(
            &self.inner.signing_key,
            &self.inner.network,
            &profile,
            contact_profile_did,
            &CustodyPayload::OfferQuery(CustodyOfferQueryPayload {}),
            now,
            now.saturating_add(CustodyMessageType::OfferQuery.max_lifetime_secs()),
        )?;
        let Some(reply) = self
            .invoke(CustodyProviderOp::Query, &query, &endpoint_did)
            .await?
        else {
            return Ok(CustodyQueryOutcome::Unreachable);
        };
        match reply {
            CustodyWireReply::Offer(offer) => Ok(CustodyQueryOutcome::Offering(Box::new(
                verify_custody_message(
                    &offer,
                    &self.inner.network,
                    &contact_profile,
                    Some(&profile),
                    CustodyMessageType::Offer,
                    now,
                )?,
            ))),
            CustodyWireReply::Refused(code) => Ok(CustodyQueryOutcome::Refused(code)),
            CustodyWireReply::Receipt(_) => {
                anyhow::bail!("custody offer query was answered with a receipt")
            }
        }
    }

    /// One delivery attempt of a signed custody message to its recipient.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn deliver(
        &self,
        local_profile_did: &str,
        envelope: &[u8],
        now: u64,
    ) -> anyhow::Result<CustodyDeliveryOutcome> {
        let route = self.outbound_route(local_profile_did, envelope, now)?;
        self.deliver_routed(envelope, &route, now).await
    }

    /// Re-establishes, for every attempt, that the envelope is this Home's
    /// own deliverable message to a current contact, and where that contact
    /// is reached now.
    fn outbound_route(
        &self,
        local_profile_did: &str,
        envelope: &[u8],
        now: u64,
    ) -> anyhow::Result<OutboundRoute> {
        let kind = claimed_custody_message_type(envelope)
            .filter(|kind| CustodyProviderOp::Deliver.carries(*kind))
            .ok_or(CustodyRefusal::INVALID_REQUEST)?;
        let context = self.context(local_profile_did)?;
        let profile = self.current_profile(&context)?;
        let raw: SignedCollaborationMessage =
            serde_json::from_slice(envelope).map_err(|_| CustodyRefusal::INVALID_REQUEST)?;
        let recipient_profile = context
            .contact_store
            .accepted_profile(&raw.payload.recipient.id)?
            .ok_or(CustodyRefusal::NOT_CONTACT)?;
        let verified = verify_custody_message(
            envelope,
            &self.inner.network,
            &profile,
            Some(&recipient_profile),
            kind,
            now,
        )?;
        Ok(OutboundRoute {
            verified,
            recipient_endpoint_did: recipient_profile.sole_endpoint_did()?.to_string(),
        })
    }

    async fn deliver_routed(
        &self,
        envelope: &[u8],
        route: &OutboundRoute,
        now: u64,
    ) -> anyhow::Result<CustodyDeliveryOutcome> {
        let Some(reply) = self
            .invoke(
                CustodyProviderOp::Deliver,
                envelope,
                &route.recipient_endpoint_did,
            )
            .await?
        else {
            return Ok(CustodyDeliveryOutcome::Unreachable);
        };
        match reply {
            CustodyWireReply::Receipt(receipt) => {
                let receipt =
                    crate::collaboration_protocol::verify_collaboration_acceptance_receipt(
                        &receipt,
                        route.verified.message(),
                        now,
                    )?;
                if receipt.accepting_endpoint_did() != route.recipient_endpoint_did {
                    anyhow::bail!("custody receipt came from another endpoint");
                }
                Ok(CustodyDeliveryOutcome::Delivered)
            }
            CustodyWireReply::Refused(code) => Ok(CustodyDeliveryOutcome::Refused(code)),
            CustodyWireReply::Offer(_) => {
                anyhow::bail!("custody delivery was answered with an offer")
            }
        }
    }

    /// One provider call. `None` means the peer could not be reached, which
    /// is not an error: a delivery stays pending and a query reads as
    /// unreachable.
    async fn invoke(
        &self,
        op: CustodyProviderOp,
        message: &[u8],
        recipient_endpoint_did: &str,
    ) -> anyhow::Result<Option<CustodyWireReply>> {
        let response = match self
            .inner
            .registry
            .invoke_provider(ProviderInvocation {
                source: CUSTODY_MESSAGE_PROVIDER_SCHEME.to_string(),
                target: CUSTODY_MESSAGE_PROVIDER_SCHEME.to_string(),
                op: op.as_str().to_string(),
                request: serde_json::to_value(CustodyProviderRequest {
                    op: op.as_str().to_string(),
                    message: encode(message),
                })?,
                transfer: ProviderTransfer::Json,
                range: None,
                progress: None,
                transport: ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                    peer_did: recipient_endpoint_did.to_string(),
                    timeout_ms: Some(CUSTODY_PROVIDER_TIMEOUT_MS),
                    reply_wait_ms: None,
                }),
            })
            .await
        {
            Ok(response) => response,
            Err(err) => {
                tracing::debug!(
                    peer_did = %recipient_endpoint_did,
                    op = op.as_str(),
                    error = %err,
                    "custody provider call did not reach the peer"
                );
                return Ok(None);
            }
        };
        let mut response = response;
        if let Some(object) = response.as_object_mut() {
            object.remove("_runtime_transfer");
        }
        let response: CustodyProviderResponse =
            serde_json::from_value(response).context("invalid custody provider response")?;
        let wire_bytes = |value: &str, label: &str| -> anyhow::Result<Vec<u8>> {
            if value.is_empty() || value.len() > MAX_CUSTODY_WIRE_BASE64_BYTES {
                anyhow::bail!("custody {label} has an invalid byte length");
            }
            decode(value, label)
        };
        let reply = match (
            response.status.as_str(),
            response.code,
            response.offer,
            response.receipt,
        ) {
            ("refused", Some(code), None, None) if is_wire_code(&code) => {
                CustodyWireReply::Refused(code)
            }
            ("ok", None, Some(offer), None) if op == CustodyProviderOp::Query => {
                CustodyWireReply::Offer(wire_bytes(&offer, "offer")?)
            }
            ("ok", None, None, Some(receipt)) if op == CustodyProviderOp::Deliver => {
                CustodyWireReply::Receipt(wire_bytes(&receipt, "receipt")?)
            }
            _ => anyhow::bail!("invalid custody provider response"),
        };
        Ok(Some(reply))
    }

    /// Queues a signed custody message under a caller key. The same key and
    /// envelope again is a no-op; a new envelope replaces the old one.
    pub(crate) fn enqueue(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<()> {
        if key.is_empty() || key.len() > MAX_CUSTODY_OUTBOX_KEY_BYTES {
            anyhow::bail!("custody outbox key has an invalid length");
        }
        let route = self.outbound_route(local_profile_did, &envelope, now)?;
        let mut outbox = self
            .inner
            .outbox
            .lock()
            .map_err(|_| anyhow::anyhow!("custody outbox lock is poisoned"))?;
        if outbox
            .get(key)
            .is_some_and(|item| item.envelope == envelope)
        {
            return Ok(());
        }
        if !outbox.contains_key(key) && outbox.len() >= MAX_CUSTODY_OUTBOX_ITEMS {
            // Settled items, and pending ones past their lifetime, give way
            // oldest first; live pending items never do.
            let settled = outbox
                .iter()
                .filter(|(_, item)| {
                    item.state != CustodyOutboxState::Pending || item.expires_at <= now
                })
                .min_by_key(|(_, item)| (item.last_attempt_at, item.expires_at))
                .map(|(key, _)| key.clone());
            match settled {
                Some(settled) => {
                    outbox.remove(&settled);
                }
                None => anyhow::bail!("custody outbox is full"),
            }
        }
        outbox.insert(
            key.to_string(),
            CustodyOutboxItem {
                local_profile_did: local_profile_did.to_string(),
                envelope,
                expires_at: route.verified.expires_at(),
                state: CustodyOutboxState::Pending,
                last_attempt_at: 0,
            },
        );
        drop(outbox);
        if let Ok(mut schedule) = self.inner.schedule.lock() {
            schedule.next_wake_at = now;
            schedule.failures = 0;
        }
        Ok(())
    }

    /// Queues a message and attempts it at once rather than at the next pass.
    pub(crate) async fn send(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<CustodyOutboxState> {
        self.enqueue(key, local_profile_did, envelope, now)?;
        if let Err(err) = self.deliver_keys(vec![key.to_string()], now).await {
            tracing::debug!(error = %format!("{err:#}"), "custody message stays queued");
        }
        self.outbox_state(key, now)
            .ok_or_else(|| anyhow::anyhow!("custody outbox item disappeared"))
    }

    /// Drops the message queued under `key`, so the next one under it starts
    /// afresh.
    pub(crate) fn forget(&self, key: &str) {
        if let Ok(mut outbox) = self.inner.outbox.lock() {
            outbox.remove(key);
        }
    }

    pub(crate) fn outbox_state(&self, key: &str, now: u64) -> Option<CustodyOutboxState> {
        let outbox = self.inner.outbox.lock().ok()?;
        let item = outbox.get(key)?;
        Some(match &item.state {
            CustodyOutboxState::Pending if item.expires_at <= now => CustodyOutboxState::Expired,
            state => state.clone(),
        })
    }

    /// The sync-loop pass: delivers due outbox items, a few at a time.
    pub(crate) async fn deliver_pending(&self, now: u64) -> anyhow::Result<()> {
        self.handler().before_delivery_pass(now);
        if self
            .inner
            .schedule
            .lock()
            .map_err(|_| anyhow::anyhow!("custody schedule lock is poisoned"))?
            .next_wake_at
            > now
        {
            return Ok(());
        }
        let due = {
            let mut outbox = self
                .inner
                .outbox
                .lock()
                .map_err(|_| anyhow::anyhow!("custody outbox lock is poisoned"))?;
            for item in outbox.values_mut() {
                if item.state == CustodyOutboxState::Pending && item.expires_at <= now {
                    item.state = CustodyOutboxState::Expired;
                }
            }
            let mut pending = outbox
                .iter()
                .filter(|(_, item)| item.state == CustodyOutboxState::Pending)
                .map(|(key, item)| (item.last_attempt_at, key.clone()))
                .collect::<Vec<_>>();
            pending.sort();
            pending
                .into_iter()
                .take(MAX_CUSTODY_DELIVERIES_PER_PASS)
                .map(|(_, key)| key)
                .collect::<Vec<_>>()
        };
        let result = self.deliver_keys(due, now).await;
        if let Ok(mut schedule) = self.inner.schedule.lock() {
            let schedule = &mut *schedule;
            crate::collaboration_discovery_runtime::update_sync_schedule(
                &mut schedule.next_wake_at,
                &mut schedule.failures,
                result.is_ok(),
                CUSTODY_SYNC_CADENCE_SECS,
                now,
            );
        }
        result
    }

    /// Attempts the named pending items through the shared delivery engine.
    async fn deliver_keys(&self, keys: Vec<String>, now: u64) -> anyhow::Result<()> {
        debug_assert!(matches!(
            DECLARED_CUSTODY_END_OF_LIFE,
            crate::collaboration_delivery::DeliveryEndOfLife::TerminalExpired
        ));
        let mut plan = Vec::new();
        let mut routes = BTreeMap::new();
        let mut first_failure = None;
        for key in keys {
            let Some((local_profile_did, envelope)) = self.pending_item(&key, now)? else {
                continue;
            };
            match self.outbound_route(&local_profile_did, &envelope, now) {
                Ok(route) => {
                    plan.push(crate::collaboration_delivery::DeliveryPlanItem {
                        key: key.clone(),
                        envelope,
                        recipient_endpoint_did: route.recipient_endpoint_did.clone(),
                    });
                    routes.insert(key, route);
                }
                Err(err) => {
                    // A message this Home can no longer stand behind (the
                    // contact is gone, or it expired) settles; anything else
                    // is this Home's own trouble and retries.
                    if let Some(state) = terminal_state_for(&err) {
                        self.settle(&key, &envelope, state)?;
                    }
                    first_failure.get_or_insert(err);
                }
            }
        }
        let routes = &routes;
        let service = self;
        let delivered = crate::collaboration_delivery::run_bounded_delivery_pass(
            plan,
            |item| async move {
                let route = routes
                    .get(&item.key)
                    .expect("every planned custody item has a route");
                let outcome = match service.deliver_routed(&item.envelope, route, now).await {
                    Ok(CustodyDeliveryOutcome::Delivered) => {
                        Ok(crate::collaboration_delivery::DeliveryAttempt::Settled)
                    }
                    Ok(CustodyDeliveryOutcome::Unreachable) => {
                        Ok(crate::collaboration_delivery::DeliveryAttempt::Unreachable)
                    }
                    Ok(CustodyDeliveryOutcome::Refused(code)) => {
                        // The recipient may not have this Home's newer
                        // Profile yet, or may be briefly unable to answer.
                        let retryable = code == CustodyRefusal::NEEDS_UPDATE.code()
                            || code == CustodyRefusal::UNAVAILABLE.code();
                        let settled = if retryable {
                            Ok(())
                        } else {
                            service.settle(
                                &item.key,
                                &item.envelope,
                                CustodyOutboxState::Refused(code.clone()),
                            )
                        };
                        settled.and(Err(anyhow::anyhow!("custody delivery refused: {code}")))
                    }
                    Err(err) => Err(err),
                };
                (item, outcome)
            },
            |item| self.settle(&item.key, &item.envelope, CustodyOutboxState::Delivered),
        )
        .await;
        match first_failure {
            Some(err) => Err(err),
            None => delivered,
        }
    }

    /// The item's sender and envelope if it is still pending, marking the
    /// attempt; an item past its lifetime becomes expired instead.
    fn pending_item(&self, key: &str, now: u64) -> anyhow::Result<Option<(String, Vec<u8>)>> {
        let mut outbox = self
            .inner
            .outbox
            .lock()
            .map_err(|_| anyhow::anyhow!("custody outbox lock is poisoned"))?;
        let Some(item) = outbox.get_mut(key) else {
            return Ok(None);
        };
        if item.state != CustodyOutboxState::Pending {
            return Ok(None);
        }
        if item.expires_at <= now {
            item.state = CustodyOutboxState::Expired;
            return Ok(None);
        }
        item.last_attempt_at = now;
        Ok(Some((
            item.local_profile_did.clone(),
            item.envelope.clone(),
        )))
    }

    /// Settles an item, unless a newer envelope replaced it meanwhile.
    fn settle(&self, key: &str, envelope: &[u8], state: CustodyOutboxState) -> anyhow::Result<()> {
        let mut outbox = self
            .inner
            .outbox
            .lock()
            .map_err(|_| anyhow::anyhow!("custody outbox lock is poisoned"))?;
        if let Some(item) = outbox.get_mut(key) {
            if item.envelope == envelope && item.state == CustodyOutboxState::Pending {
                item.state = state;
            }
        }
        Ok(())
    }

    fn receive(
        &self,
        op: CustodyProviderOp,
        message: &[u8],
        source_endpoint_did: &str,
        now: u64,
    ) -> Result<CustodyReply, CustodyRefusal> {
        let kind = claimed_custody_message_type(message)
            .filter(|kind| op.carries(*kind))
            .ok_or(CustodyRefusal::INVALID_REQUEST)?;
        // Routing hints only: nothing here is trusted until verified below.
        let raw: SignedCollaborationMessage =
            serde_json::from_slice(message).map_err(|_| CustodyRefusal::INVALID_REQUEST)?;
        let context = self
            .inner
            .contexts
            .lock()
            .map_err(|_| CustodyRefusal::UNAVAILABLE)?
            .get(&raw.payload.recipient.id)
            .cloned()
            .ok_or_else(|| {
                tracing::debug!("custody message is for a Profile this Home does not host");
                CustodyRefusal::NOT_CONTACT
            })?;
        let local_profile = self
            .revalidate_context(&context)
            .and_then(|()| self.current_profile(&context))
            .map_err(|err| {
                tracing::debug!(error = %format!("{err:#}"), "custody context unavailable");
                CustodyRefusal::UNAVAILABLE
            })?;
        let unavailable = |err: anyhow::Error| {
            tracing::debug!(error = %format!("{err:#}"), "custody contact lookup failed");
            CustodyRefusal::UNAVAILABLE
        };
        let contact = context
            .contact_store
            .snapshot()
            .map_err(unavailable)?
            .contacts()
            .iter()
            .find(|contact| contact.remote_profile_did() == raw.payload.sender_profile_did)
            .cloned()
            .ok_or_else(|| {
                tracing::debug!("custody message sender is not an accepted contact");
                CustodyRefusal::NOT_CONTACT
            })?;
        let sender_profile = context
            .contact_store
            .accepted_profile(contact.remote_profile_did())
            .map_err(unavailable)?
            .ok_or(CustodyRefusal::NOT_CONTACT)?;
        // The authenticated Carrier source is the contact Profile's sole
        // endpoint, and the protocol requires that endpoint to be the signer.
        if sender_profile.sole_endpoint_did().ok() != Some(source_endpoint_did) {
            tracing::debug!("custody message did not arrive from the contact's Profile endpoint");
            return Err(CustodyRefusal::NOT_CONTACT);
        }
        let verified = verify_custody_message(
            message,
            &self.inner.network,
            &sender_profile,
            Some(&local_profile),
            kind,
            now,
        )?;
        if verified.signer_did() != source_endpoint_did {
            return Err(CustodyRefusal::NOT_CONTACT);
        }
        if op == CustodyProviderOp::Deliver {
            if let Some(receipt) = self.stored_receipt(verified.envelope_sha256(), now) {
                return Ok(CustodyReply::Receipt(receipt));
            }
        }

        let inbound = CustodyInbound {
            data_dir: context.contact_store.data_root(),
            principal_id: context.contact_store.principal_id(),
            localhost_root: context.contact_store.localhost_root(),
            local_profile: &local_profile,
            sender_profile: &sender_profile,
            sender_display_name: contact.remote_display_name(),
            message: &verified,
            envelope: message,
            now,
        };
        let handler = self.handler();
        match verified.payload() {
            CustodyPayload::OfferQuery(_) => {
                let offer = handler.on_offer_query(&inbound)?;
                let envelope = prepare_custody_message(
                    &self.inner.signing_key,
                    &self.inner.network,
                    &local_profile,
                    verified.sender_profile_did(),
                    &CustodyPayload::Offer(offer),
                    now,
                    now.saturating_add(CustodyMessageType::Offer.max_lifetime_secs()),
                )
                .map_err(|err| match err.downcast_ref::<CustodyMessageRefusal>() {
                    // This Home never enabled custody messages: it offers nothing.
                    Some(CustodyMessageRefusal::SignerNotAuthorized) => {
                        CustodyRefusal::NOT_OFFERING
                    }
                    Some(refusal) => CustodyRefusal::from(*refusal),
                    None => {
                        tracing::debug!(error = %format!("{err:#}"), "custody offer not signed");
                        CustodyRefusal::UNAVAILABLE
                    }
                })?;
                return Ok(CustodyReply::Offer(envelope));
            }
            CustodyPayload::NodeRequest(request) => handler.on_request(&inbound, request)?,
            CustodyPayload::NodeDecision(decision) => handler.on_decision(&inbound, decision)?,
            CustodyPayload::PoolActive(notice) => handler.on_pool_active(&inbound, notice)?,
            CustodyPayload::PoolDescriptor(descriptor) => {
                handler.on_pool_descriptor(&inbound, descriptor)?
            }
            CustodyPayload::Offer(_) => return Err(CustodyRefusal::INVALID_REQUEST),
        }
        let receipt = crate::collaboration_direct_messages::acceptance_receipt_for(
            &self.inner.signing_key,
            verified.message(),
            now,
        )
        .map_err(|err| {
            tracing::debug!(error = %format!("{err:#}"), "custody receipt not signed");
            CustodyRefusal::UNAVAILABLE
        })?;
        self.store_receipt(
            verified.envelope_sha256(),
            &receipt,
            verified.expires_at(),
            now,
        );
        Ok(CustodyReply::Receipt(receipt))
    }

    fn stored_receipt(&self, envelope_sha256: &str, now: u64) -> Option<Vec<u8>> {
        let receipts = self.inner.receipts.lock().ok()?;
        receipts
            .get(envelope_sha256)
            .filter(|stored| stored.expires_at > now)
            .map(|stored| stored.receipt.clone())
    }

    fn store_receipt(&self, envelope_sha256: &str, receipt: &[u8], expires_at: u64, now: u64) {
        let Ok(mut receipts) = self.inner.receipts.lock() else {
            return;
        };
        receipts.retain(|_, stored| stored.expires_at > now);
        if receipts.len() >= MAX_CUSTODY_RECEIPTS {
            if let Some(oldest) = receipts
                .iter()
                .min_by_key(|(_, stored)| stored.expires_at)
                .map(|(key, _)| key.clone())
            {
                receipts.remove(&oldest);
            }
        }
        receipts.insert(
            envelope_sha256.to_string(),
            StoredCustodyReceipt {
                receipt: receipt.to_vec(),
                expires_at,
            },
        );
    }
}

/// The settled state for a local delivery error that no retry can fix.
pub(crate) fn terminal_state_for(err: &anyhow::Error) -> Option<CustodyOutboxState> {
    if let Some(refusal) = err.downcast_ref::<CustodyMessageRefusal>() {
        return Some(match refusal {
            CustodyMessageRefusal::Expired => CustodyOutboxState::Expired,
            other => CustodyOutboxState::Refused(CustodyRefusal::from(*other).code().to_string()),
        });
    }
    err.downcast_ref::<CustodyRefusal>()
        .map(|refusal| CustodyOutboxState::Refused(refusal.code().to_string()))
}

struct CollaborationCustodyMessageProvider {
    inner: Arc<CustodyInner>,
}

#[async_trait::async_trait]
impl Provider for CollaborationCustodyMessageProvider {
    async fn handle(
        &self,
        _request: elastos_runtime::provider::ResourceRequest,
    ) -> Result<elastos_runtime::provider::ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "custody messages do not expose resource routes".to_string(),
        ))
    }
    fn schemes(&self) -> Vec<&'static str> {
        vec![CUSTODY_MESSAGE_PROVIDER_SCHEME]
    }
    fn name(&self) -> &'static str {
        "collaboration-custody-message"
    }
    async fn send_raw(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, ProviderError> {
        let invalid = || ProviderError::Provider("invalid custody provider request".to_string());
        let mut request = request.clone();
        let object = request.as_object_mut().ok_or_else(invalid)?;
        let (op, source_endpoint_did) = validate_custody_runtime_invocation(
            object.get("_runtime_invocation"),
        )
        .map_err(|_| ProviderError::Provider("invalid custody provider invocation".to_string()))?;
        object.remove("_runtime_invocation");
        let request: CustodyProviderRequest =
            serde_json::from_value(request).map_err(|_| invalid())?;
        if request.op != op.as_str()
            || request.message.is_empty()
            || request.message.len() > MAX_CUSTODY_WIRE_BASE64_BYTES
        {
            return Err(invalid());
        }
        let message = decode(&request.message, "custody message").map_err(|_| invalid())?;
        let service = CollaborationCustodyMessageService {
            inner: self.inner.clone(),
        };
        let response = match service.receive(op, &message, &source_endpoint_did, now_ts()) {
            Ok(reply) => {
                let (offer, receipt) = match reply {
                    CustodyReply::Offer(bytes) => (Some(encode(&bytes)), None),
                    CustodyReply::Receipt(bytes) => (None, Some(encode(&bytes))),
                };
                if offer
                    .iter()
                    .chain(receipt.iter())
                    .any(|value| value.len() > MAX_CUSTODY_WIRE_BASE64_BYTES)
                {
                    refused_response(CustodyRefusal::UNAVAILABLE)
                } else {
                    CustodyProviderResponse {
                        status: "ok".to_string(),
                        code: None,
                        offer,
                        receipt,
                    }
                }
            }
            Err(refusal) => refused_response(refusal),
        };
        Ok(serde_json::to_value(response).expect("custody provider response serializes"))
    }
}

fn refused_response(refusal: CustodyRefusal) -> CustodyProviderResponse {
    CustodyProviderResponse {
        status: "refused".to_string(),
        code: Some(refusal.code().to_string()),
        offer: None,
        receipt: None,
    }
}

/// Two ops share this plane; the capability must name the invoked op, so a
/// `deliver` grant is not a `query` grant.
fn validate_custody_runtime_invocation(
    value: Option<&serde_json::Value>,
) -> anyhow::Result<(CustodyProviderOp, String)> {
    let runtime = value
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("custody provider invocation is missing"))?;
    let op = runtime
        .get("op")
        .and_then(serde_json::Value::as_str)
        .and_then(CustodyProviderOp::parse)
        .ok_or_else(|| anyhow::anyhow!("custody provider invocation is invalid"))?;
    let capability = format!(
        "provider:{0}->{0}:{1}",
        CUSTODY_MESSAGE_PROVIDER_SCHEME,
        op.as_str()
    );
    for (field, expected) in [
        ("schema", "elastos.provider.invocation/v1"),
        ("source", CUSTODY_MESSAGE_PROVIDER_SCHEME),
        ("target", CUSTODY_MESSAGE_PROVIDER_SCHEME),
        ("op", op.as_str()),
        ("capability", capability.as_str()),
        ("transport", "carrier-provider-plane"),
        ("transfer", "json"),
    ] {
        if runtime.get(field).and_then(serde_json::Value::as_str) != Some(expected) {
            anyhow::bail!("custody provider invocation is invalid");
        }
    }
    let source = crate::collaboration_protocol::authenticated_carrier_source_endpoint(
        runtime.get("carrier"),
    )?;
    Ok((op, source))
}

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode(value: &str, label: &str) -> anyhow::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .with_context(|| format!("invalid base64 {label}"))
}

#[cfg(test)]
mod tests;
