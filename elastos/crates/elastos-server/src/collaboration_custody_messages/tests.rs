use super::*;
use crate::collaboration_discovery_runtime::tests::{
    durable_profile_peer_pair, DurableProfileIdentity, DurableProfilePeerPair,
};
use crate::collaboration_profile_authority::{
    profile_chain_segment, signed_profile_document_for_test, with_signing_scope_for_test,
};
use crate::crypto::encode_signing_key_did;
use crate::custody_pool_setup::POOL_TERM_DAYS;
use elastos_runtime::signature::generate_keypair;

#[derive(Default)]
struct RecordingHandler {
    calls: Mutex<Vec<(CustodyMessageType, String)>>,
    refusal: Mutex<Option<CustodyRefusal>>,
}

impl RecordingHandler {
    fn calls(&self) -> Vec<CustodyMessageType> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(kind, _)| *kind)
            .collect()
    }

    fn refuse_with(&self, refusal: Option<CustodyRefusal>) {
        *self.refusal.lock().unwrap() = refusal;
    }

    fn record(&self, inbound: &CustodyInbound<'_>) -> Result<(), CustodyRefusal> {
        // The transport's identity rule, seen from the handler: the signer is
        // the sender Profile's sole endpoint.
        assert_eq!(
            inbound.message.signer_did(),
            inbound.sender_profile.sole_endpoint_did().unwrap()
        );
        assert_eq!(
            inbound.message.recipient_profile_did(),
            inbound.local_profile.document().profile_did
        );
        // What a handler keeps and shows: the exact bytes, and the contact's
        // signed name, under the receiving principal's own root.
        assert_eq!(
            inbound.message.envelope_sha256(),
            format!(
                "sha256:{}",
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(inbound.envelope))
            )
        );
        assert_eq!(inbound.sender_display_name, "Alice");
        assert!(inbound.data_dir.is_dir());
        assert!(inbound.principal_id.starts_with("person:local:"));
        assert!(!inbound.localhost_root.is_empty());
        assert!(inbound.now >= inbound.message.created_at());
        self.calls.lock().unwrap().push((
            inbound.message.message_type(),
            inbound.message.signer_did().to_string(),
        ));
        match *self.refusal.lock().unwrap() {
            Some(refusal) => Err(refusal),
            None => Ok(()),
        }
    }
}

impl CustodyMessageHandler for RecordingHandler {
    fn on_offer_query(
        &self,
        inbound: &CustodyInbound<'_>,
    ) -> Result<CustodyOfferPayload, CustodyRefusal> {
        self.record(inbound).map(|()| sample_offer())
    }

    fn on_request(
        &self,
        inbound: &CustodyInbound<'_>,
        _request: &CustodyNodeRequestPayload,
    ) -> Result<(), CustodyRefusal> {
        self.record(inbound)
    }

    fn on_decision(
        &self,
        inbound: &CustodyInbound<'_>,
        _decision: &CustodyNodeDecisionPayload,
    ) -> Result<(), CustodyRefusal> {
        self.record(inbound)
    }

    fn on_pool_active(
        &self,
        inbound: &CustodyInbound<'_>,
        _notice: &CustodyPoolActivePayload,
    ) -> Result<(), CustodyRefusal> {
        self.record(inbound)
    }
}

struct UnreachableCarrier;

#[async_trait::async_trait]
impl elastos_runtime::provider::ProviderCarrierInvoker for UnreachableCarrier {
    async fn invoke_carrier_provider(
        &self,
        _route: &ProviderCarrierRoute,
        _invocation: &ProviderInvocation,
        _request: serde_json::Value,
    ) -> Result<serde_json::Value, ProviderError> {
        Err(ProviderError::Provider("peer is offline".to_string()))
    }
}

fn sample_offer() -> CustodyOfferPayload {
    CustodyOfferPayload {
        location: "Lisbon".to_string(),
        provides: vec!["chain".to_string(), "custody".to_string()],
        run_by: "Bob".to_string(),
    }
}

fn node_request(seed: u8) -> CustodyPayload {
    CustodyPayload::NodeRequest(CustodyNodeRequestPayload {
        request_id: hex::encode([seed; 16]),
        signing_key_fingerprint_full: format!("sha256:{}", hex::encode([seed; 32])),
        term_days: POOL_TERM_DAYS[0],
    })
}

fn offer_query() -> CustodyPayload {
    CustodyPayload::OfferQuery(CustodyOfferQueryPayload {})
}

/// An owner Home (A) and a node Home (B), accepted contacts with durable
/// Profiles, both of which enabled custody messages. Only Runtime-owned
/// contexts are registered: no Home session exists anywhere.
struct CustodyPair {
    pair: DurableProfilePeerPair,
    owner: CollaborationCustodyMessageService,
    node: CollaborationCustodyMessageService,
    owner_profile_did: String,
    node_profile_did: String,
    owner_did: String,
    node_handler: Arc<RecordingHandler>,
}

/// `node_learns_owner_scope: false` leaves the node holding the owner's
/// Profile from before custody messages were enabled, as when the Profile
/// update has not reached it yet.
async fn custody_pair(root: &Path, node_learns_owner_scope: bool) -> CustodyPair {
    let pair = durable_profile_peer_pair(root).await;
    let now = crate::auth::now_ts();
    let (root_a, root_b) = (root.join("a"), root.join("b"));
    for (identity, data_dir) in [(&pair.identity_a, &root_a), (&pair.identity_b, &root_b)] {
        ensure_custody_signing_scope(
            data_dir,
            &identity.principal_id,
            &identity.localhost_root,
            &identity.proof_binding_id,
            now,
        )
        .unwrap();
    }
    // What a Profile update announcement would deliver.
    let learn =
        |store: &CollaborationContactStore, identity: &DurableProfileIdentity, data_dir: &Path| {
            let segment =
                profile_chain_segment(data_dir, &identity.principal_id, &identity.localhost_root)
                    .unwrap()
                    .unwrap();
            let bytes = segment
                .iter()
                .map(|signed| serde_json::to_vec(signed).unwrap())
                .collect::<Vec<_>>();
            store
                .apply_accepted_profile_chain(
                    &bytes,
                    &encode_signing_key_did(&identity.device_key),
                    now,
                )
                .unwrap();
        };
    learn(&pair.store_a, &pair.identity_b, &root_b);
    if node_learns_owner_scope {
        learn(&pair.store_b, &pair.identity_a, &root_a);
    }
    pair.service_a
        .register_runtime_owned_contexts(&root_a)
        .unwrap();
    pair.service_b
        .register_runtime_owned_contexts(&root_b)
        .unwrap();
    let node_handler = Arc::new(RecordingHandler::default());
    let owner = pair.service_a.custody_message_service();
    let node = pair.service_b.custody_message_service();
    node.set_handler(node_handler.clone());
    CustodyPair {
        owner_profile_did: pair.identity_a.profile.document().profile_did.clone(),
        node_profile_did: pair.identity_b.profile.document().profile_did.clone(),
        owner_did: encode_signing_key_did(&pair.identity_a.device_key),
        owner,
        node,
        node_handler,
        pair,
    }
}

impl CustodyPair {
    fn request(&self, seed: u8, now: u64, expires_at: u64) -> Vec<u8> {
        self.owner
            .prepare(
                &self.owner_profile_did,
                &self.node_profile_did,
                &node_request(seed),
                now,
                expires_at,
            )
            .unwrap()
    }

    fn query(&self, now: u64) -> Vec<u8> {
        self.owner
            .prepare(
                &self.owner_profile_did,
                &self.node_profile_did,
                &offer_query(),
                now,
                now + 60,
            )
            .unwrap()
    }

    async fn use_carrier(&self, invoker: Option<Arc<UnreachableCarrier>>) {
        let registry = self.owner.inner.registry.clone();
        match invoker {
            Some(invoker) => registry.set_carrier_invoker(invoker).await,
            None => {
                registry
                    .set_carrier_invoker(Arc::new(
                        crate::carrier::CarrierProviderInvoker::with_carrier_endpoint_and_registry(
                            self.pair._node_a.endpoint.clone(),
                            Arc::downgrade(&registry),
                        ),
                    ))
                    .await
            }
        }
    }
}

/// A custody-enabled Home that is nobody's contact.
fn stranger_message(
    network: &VerifiedCollaborationNetworkProfile,
    recipient_profile_did: &str,
    now: u64,
) -> (Vec<u8>, String) {
    let (device, _) = generate_keypair();
    let (profile_key, _) = generate_keypair();
    let device_did = encode_signing_key_did(&device);
    let profile = signed_profile_document_for_test(
        &profile_key,
        "Stranger",
        None,
        1,
        None,
        now - 10,
        vec![device_did.clone()],
    )
    .unwrap();
    let profile =
        with_signing_scope_for_test(&profile_key, &profile, CUSTODY_SIGNING_SCOPE).unwrap();
    let envelope = prepare_custody_message(
        &device,
        network,
        &profile,
        recipient_profile_did,
        &node_request(9),
        now,
        now + 3_600,
    )
    .unwrap();
    (envelope, device_did)
}

#[tokio::test]
async fn a_contact_queries_and_delivers_to_a_home_with_no_session() {
    let temp = tempfile::tempdir().unwrap();
    let fx = custody_pair(temp.path(), true).await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let now = crate::auth::now_ts();
    assert_eq!(
        fx.pair.service_b.registered_context_snapshot_for_test()["sync"],
        serde_json::json!([]),
        "the node has no Home session; only its Runtime-owned context receives"
    );

    let CustodyQueryOutcome::Offering(offer) = fx
        .owner
        .query_offer(&fx.owner_profile_did, &fx.node_profile_did, now)
        .await
        .unwrap()
    else {
        panic!("the node answers its offer");
    };
    assert_eq!(offer.payload(), &CustodyPayload::Offer(sample_offer()));
    assert_eq!(
        offer.signer_did(),
        encode_signing_key_did(&fx.pair.identity_b.device_key)
    );
    assert_eq!(offer.recipient_profile_did(), fx.owner_profile_did);

    let request = fx.request(1, now, now + 3_600);
    assert_eq!(
        fx.owner
            .deliver(&fx.owner_profile_did, &request, now)
            .await
            .unwrap(),
        CustodyDeliveryOutcome::Delivered
    );
    assert_eq!(
        fx.node_handler.calls(),
        vec![
            CustodyMessageType::OfferQuery,
            CustodyMessageType::NodeRequest
        ]
    );
    assert!(fx
        .node_handler
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|(_, signer)| *signer == fx.owner_did));

    // A replay settles again with a receipt and never reaches the handler.
    assert_eq!(
        fx.owner
            .deliver(&fx.owner_profile_did, &request, now + 1)
            .await
            .unwrap(),
        CustodyDeliveryOutcome::Delivered
    );
    assert_eq!(fx.node_handler.calls().len(), 2);
}

#[tokio::test]
async fn only_an_accepted_contact_from_its_profile_endpoint_reaches_the_handler() {
    let temp = tempfile::tempdir().unwrap();
    let fx = custody_pair(temp.path(), true).await;
    let now = crate::auth::now_ts();
    let deliver = |message: &[u8], source: &str| {
        fx.node
            .receive(CustodyProviderOp::Deliver, message, source, now)
    };

    // The control: the contact, from its Profile endpoint.
    let first = fx.request(1, now, now + 3_600);
    let Ok(CustodyReply::Receipt(receipt)) = deliver(&first, &fx.owner_did) else {
        panic!("the contact's request is accepted");
    };
    // An idempotent replay returns the stored receipt.
    assert_eq!(
        deliver(&first, &fx.owner_did),
        Ok(CustodyReply::Receipt(receipt))
    );
    assert_eq!(fx.node_handler.calls().len(), 1);

    // The same valid message from an endpoint that is not the Profile's.
    let second = fx.request(2, now, now + 3_600);
    let elsewhere = encode_signing_key_did(&generate_keypair().0);
    assert_eq!(
        deliver(&second, &elsewhere),
        Err(CustodyRefusal::NOT_CONTACT)
    );

    // A custody-enabled Home that is not a contact, from its own endpoint.
    let network = fx.pair.service_b.network_profile();
    let (stranger, stranger_did) = stranger_message(&network, &fx.node_profile_did, now);
    assert_eq!(
        deliver(&stranger, &stranger_did),
        Err(CustodyRefusal::NOT_CONTACT)
    );

    // The contact's message addressed to a Profile this Home does not host.
    let owner_profile = crate::collaboration_profile_authority::load_profile_authority(
        &temp.path().join("a"),
        &fx.pair.identity_a.principal_id,
        &fx.pair.identity_a.localhost_root,
    )
    .unwrap()
    .unwrap();
    let elsewhere_profile = encode_signing_key_did(&generate_keypair().0);
    let misaddressed = prepare_custody_message(
        &fx.pair.identity_a.device_key,
        &network,
        &owner_profile,
        &elsewhere_profile,
        &node_request(3),
        now,
        now + 3_600,
    )
    .unwrap();
    assert_eq!(
        deliver(&misaddressed, &fx.owner_did),
        Err(CustodyRefusal::NOT_CONTACT)
    );

    // Each op carries only its own message types.
    let query = fx.query(now);
    assert_eq!(
        deliver(&query, &fx.owner_did),
        Err(CustodyRefusal::INVALID_REQUEST)
    );
    assert_eq!(
        fx.node
            .receive(CustodyProviderOp::Query, &second, &fx.owner_did, now),
        Err(CustodyRefusal::INVALID_REQUEST)
    );

    // Revoking the node admin's passkey ends the Runtime-owned context.
    crate::auth::revoke_passkey_binding(
        &temp.path().join("b"),
        &fx.pair.identity_b.proof_binding_id,
        now,
    )
    .unwrap();
    assert_eq!(
        deliver(&second, &fx.owner_did),
        Err(CustodyRefusal::UNAVAILABLE)
    );

    assert_eq!(
        fx.node_handler.calls(),
        vec![CustodyMessageType::NodeRequest]
    );
}

#[tokio::test]
async fn a_sender_without_the_custody_scope_needs_an_update() {
    let temp = tempfile::tempdir().unwrap();
    let fx = custody_pair(temp.path(), false).await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let now = crate::auth::now_ts();

    // The owner enabled custody messages, but the node still holds its
    // older Profile: the signer has no custody scope there.
    let request = fx.request(1, now, now + 3_600);
    assert_eq!(
        fx.node
            .receive(CustodyProviderOp::Deliver, &request, &fx.owner_did, now),
        Err(CustodyRefusal::NEEDS_UPDATE)
    );
    assert_eq!(
        fx.owner
            .deliver(&fx.owner_profile_did, &request, now)
            .await
            .unwrap(),
        CustodyDeliveryOutcome::Refused("needs_update".to_string())
    );
    // Seen from the node, the owner cannot sign an offer, so there is
    // nothing to ask.
    assert_eq!(
        fx.node
            .query_offer(&fx.node_profile_did, &fx.owner_profile_did, now)
            .await
            .unwrap(),
        CustodyQueryOutcome::Refused("needs_update".to_string())
    );
    assert!(fx.node_handler.calls().is_empty());
}

#[tokio::test]
async fn the_handler_answers_or_refuses_and_a_refusal_is_not_remembered() {
    let temp = tempfile::tempdir().unwrap();
    let fx = custody_pair(temp.path(), true).await;
    let now = crate::auth::now_ts();
    let request = fx.request(1, now, now + 3_600);
    let query = fx.query(now);

    // The default handler offers nothing and takes nothing.
    fx.node.set_handler(Arc::new(NotOfferingCustodyHandler));
    assert_eq!(
        fx.node
            .receive(CustodyProviderOp::Query, &query, &fx.owner_did, now),
        Err(CustodyRefusal::NOT_OFFERING)
    );
    assert_eq!(
        fx.node
            .receive(CustodyProviderOp::Deliver, &request, &fx.owner_did, now),
        Err(CustodyRefusal::REFUSED)
    );

    fx.node.set_handler(fx.node_handler.clone());
    fx.node_handler
        .refuse_with(Some(CustodyDeclineCode::NotAdmin.into()));
    assert_eq!(
        fx.node
            .receive(CustodyProviderOp::Deliver, &request, &fx.owner_did, now)
            .unwrap_err()
            .code(),
        "not_admin"
    );
    fx.node_handler.refuse_with(None);
    assert!(matches!(
        fx.node
            .receive(CustodyProviderOp::Deliver, &request, &fx.owner_did, now),
        Ok(CustodyReply::Receipt(_))
    ));
    let Ok(CustodyReply::Offer(offer)) =
        fx.node
            .receive(CustodyProviderOp::Query, &query, &fx.owner_did, now)
    else {
        panic!("the node answers with a signed offer");
    };
    let node_profile = fx
        .pair
        .store_a
        .accepted_profile(&fx.node_profile_did)
        .unwrap()
        .unwrap();
    let owner_profile = crate::collaboration_profile_authority::load_profile_authority(
        &temp.path().join("a"),
        &fx.pair.identity_a.principal_id,
        &fx.pair.identity_a.localhost_root,
    )
    .unwrap()
    .unwrap();
    let verified = verify_custody_message(
        &offer,
        &fx.pair.service_a.network_profile(),
        &node_profile,
        Some(&owner_profile),
        CustodyMessageType::Offer,
        now,
    )
    .unwrap();
    assert_eq!(verified.payload(), &CustodyPayload::Offer(sample_offer()));
    // A handler code that is not a wire code goes out as a plain refusal.
    assert_eq!(CustodyRefusal::new("Not Admin").code(), "refused");
}

#[tokio::test]
async fn the_capability_must_name_the_invoked_op() {
    let source = encode_signing_key_did(&generate_keypair().0);
    let invocation = |op: &str, capability_op: &str| {
        serde_json::json!({
            "schema": "elastos.provider.invocation/v1",
            "source": CUSTODY_MESSAGE_PROVIDER_SCHEME,
            "target": CUSTODY_MESSAGE_PROVIDER_SCHEME,
            "op": op,
            "capability": format!(
                "provider:{0}->{0}:{1}",
                CUSTODY_MESSAGE_PROVIDER_SCHEME, capability_op
            ),
            "transport": "carrier-provider-plane",
            "transfer": "json",
            "carrier": { "source_endpoint_did": source },
        })
    };
    for op in ["query", "deliver"] {
        let (parsed, authenticated) =
            validate_custody_runtime_invocation(Some(&invocation(op, op))).unwrap();
        assert_eq!(parsed.as_str(), op);
        assert_eq!(authenticated, source);
    }
    assert!(validate_custody_runtime_invocation(Some(&invocation("query", "deliver"))).is_err());
    assert!(validate_custody_runtime_invocation(Some(&invocation("deliver", "query"))).is_err());
    assert!(
        validate_custody_runtime_invocation(Some(&invocation("announce", "announce"))).is_err()
    );
    let mut caller_asserted = invocation("query", "query");
    caller_asserted["carrier"]["peer_did"] = serde_json::json!(source);
    assert!(validate_custody_runtime_invocation(Some(&caller_asserted)).is_err());
    let mut missing = invocation("query", "query");
    missing["carrier"] = serde_json::Value::Null;
    assert!(validate_custody_runtime_invocation(Some(&missing)).is_err());

    // The request body must name the same op as the invocation.
    let (trusted, _) = generate_keypair();
    let network = crate::collaboration_discovery_runtime::tests::signed_profile(
        "elastos.community.test",
        &trusted,
        vec![],
    );
    let service = CollaborationCustodyMessageService::new(
        generate_keypair().0,
        network,
        Arc::new(ProviderRegistry::new()),
    )
    .await
    .unwrap();
    let provider = CollaborationCustodyMessageProvider {
        inner: service.inner.clone(),
    };
    let request = serde_json::json!({
        "op": "query",
        "message": encode(b"{}"),
        "_runtime_invocation": invocation("deliver", "deliver"),
    });
    assert!(provider.send_raw(&request).await.is_err());
}

#[tokio::test]
async fn an_offline_recipient_is_retried_until_it_takes_the_message_or_it_expires() {
    let temp = tempfile::tempdir().unwrap();
    let fx = custody_pair(temp.path(), true).await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let now = crate::auth::now_ts();

    fx.use_carrier(Some(Arc::new(UnreachableCarrier))).await;
    let first = fx.request(1, now, now + 3_600);
    assert_eq!(
        fx.owner
            .send("request:1", &fx.owner_profile_did, first.clone(), now)
            .await
            .unwrap(),
        CustodyOutboxState::Pending
    );
    assert!(fx.owner.deliver_pending(now + 1).await.is_err());
    assert_eq!(
        fx.owner.outbox_state("request:1", now + 1),
        Some(CustodyOutboxState::Pending)
    );
    // Queuing the same message again changes nothing.
    fx.owner
        .enqueue("request:1", &fx.owner_profile_did, first, now + 1)
        .unwrap();

    // The recipient comes back: the next pass delivers it.
    fx.use_carrier(None).await;
    fx.owner.deliver_pending(now + 60).await.unwrap();
    assert_eq!(
        fx.owner.outbox_state("request:1", now + 60),
        Some(CustodyOutboxState::Delivered)
    );
    assert_eq!(
        fx.node_handler.calls(),
        vec![CustodyMessageType::NodeRequest]
    );

    // An item the recipient never takes within its lifetime shows as
    // expired and is never delivered afterwards.
    fx.use_carrier(Some(Arc::new(UnreachableCarrier))).await;
    let second = fx.request(2, now, now + 120);
    fx.owner
        .enqueue("request:2", &fx.owner_profile_did, second, now)
        .unwrap();
    assert!(fx.owner.deliver_pending(now + 61).await.is_err());
    assert_eq!(
        fx.owner.outbox_state("request:2", now + 120),
        Some(CustodyOutboxState::Expired)
    );
    fx.use_carrier(None).await;
    fx.owner.deliver_pending(now + 200).await.unwrap();
    assert_eq!(
        fx.owner.outbox_state("request:2", now + 200),
        Some(CustodyOutboxState::Expired)
    );
    assert_eq!(fx.node_handler.calls().len(), 1);
    assert_eq!(fx.owner.outbox_state("request:unknown", now), None);

    // A message the recipient refuses is settled as refused.
    fx.node_handler
        .refuse_with(Some(CustodyDeclineCode::AlreadyServing.into()));
    let third = fx.request(3, now, now + 3_600);
    assert_eq!(
        fx.owner
            .send("request:3", &fx.owner_profile_did, third, now + 200)
            .await
            .unwrap(),
        CustodyOutboxState::Refused("already_serving".to_string())
    );
}

#[tokio::test]
async fn the_outbox_is_bounded_and_settled_items_make_room() {
    let temp = tempfile::tempdir().unwrap();
    let fx = custody_pair(temp.path(), true).await;
    let now = crate::auth::now_ts();
    for index in 0..MAX_CUSTODY_OUTBOX_ITEMS {
        let envelope = fx.request(index as u8, now, now + 120);
        fx.owner
            .enqueue(
                &format!("request:{index}"),
                &fx.owner_profile_did,
                envelope,
                now,
            )
            .unwrap();
    }
    let overflow = fx.request(200, now, now + 120);
    assert!(fx
        .owner
        .enqueue("request:overflow", &fx.owner_profile_did, overflow, now)
        .is_err());

    // Once the queued items' lifetimes end they no longer hold their slots.
    let later = now + 121;
    let fresh = fx.request(201, later, later + 120);
    fx.owner
        .enqueue("request:overflow", &fx.owner_profile_did, fresh, later)
        .unwrap();
    assert_eq!(
        fx.owner.outbox_state("request:overflow", later),
        Some(CustodyOutboxState::Pending)
    );

    // Only a deliverable message for an accepted contact is queued.
    let query = fx.query(now);
    assert!(fx
        .owner
        .enqueue("query", &fx.owner_profile_did, query, now)
        .is_err());
}
