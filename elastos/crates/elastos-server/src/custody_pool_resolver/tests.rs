//! Plan B T4.3: known pools, the resolver's sources and the Carrier route of
//! a pool call.

use super::*;

use std::collections::VecDeque;
use std::sync::Mutex;

use elastos_protected_content_contracts::test_fixtures::{
    key_envelope_for, pool_bundle, pool_descriptor_with, pool_did, runtime_issuer, signing_key,
};
use elastos_protected_content_contracts::{
    CustodyEpochIssuerKeyV1, Digest32, EncryptedContentIdentityV1, PoolAddressAnyV1, PoolAddressV1,
    PoolAddressV2, PoolDidV1, PoolMemberRouteV1, ServePolicyV1, PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES,
};
use x_wing::kem::Decapsulator as _;
use x_wing::KeyExport as _;

use crate::protected_content_config::tests::{owner_only_dir, safe_ancestor_tempdir};

const NOW: u64 = 2_000_000_000;

fn xwing(seed: u8) -> [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
    let secret = x_wing::DecapsulationKey::from([seed; x_wing::DECAPSULATION_KEY_SIZE]);
    secret.encapsulation_key().to_bytes().into()
}

/// A ticketless v3 descriptor (item 10, #388 A2), as a member's `describe`
/// answers.
fn descriptor(sequence: u64) -> SignedPoolDescriptorAnyV1 {
    pool_descriptor_with(
        &pool_bundle(xwing, NOW),
        sequence,
        ServePolicyV1::DEFAULT,
        None,
        runtime_issuer(0x43),
        NOW,
    )
    .into()
}

const BOOTSTRAP_DID: &str = "did:key:z6MkPoolNode01";

fn bootstrap() -> PoolMemberRouteV2 {
    PoolMemberRouteV2::new(BOOTSTRAP_DID.to_string()).unwrap()
}

fn address_for(pool: PoolDidV1) -> String {
    crate::custody_pool_descriptor::encode_pool_address(
        &PoolAddressV2::new(pool, bootstrap()).unwrap(),
    )
    .unwrap()
}

/// A historical v1 address whose bootstrap carries a ticket, in the text
/// form an older Home wrote.
fn v1_address_with_ticket(pool: PoolDidV1) -> String {
    let address = PoolAddressV1::new(
        pool,
        PoolMemberRouteV1::new(BOOTSTRAP_DID.to_string(), Some("v1-ticket".to_string())).unwrap(),
    )
    .unwrap();
    format!(
        "{}{}",
        crate::custody_pool_descriptor::POOL_ADDRESS_TEXT_PREFIX,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(address.canonical_bytes().unwrap())
    )
}

fn other_pool() -> PoolDidV1 {
    PoolDidV1::from_issuer(
        CustodyEpochIssuerKeyV1::new(signing_key(0x72).verifying_key().to_bytes()).unwrap(),
    )
}

fn data_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("home");
    owner_only_dir(&data_dir);
    (dir, data_dir)
}

/// Answers `describe` from a script and records each call.
#[derive(Default)]
struct FakeTransport {
    answers: Mutex<VecDeque<Result<Value, PoolTransportError>>>,
    calls: Mutex<Vec<(PoolMemberRouteV2, &'static str, Value)>>,
}

impl FakeTransport {
    fn answering(answers: Vec<Result<Value, PoolTransportError>>) -> Self {
        Self {
            answers: Mutex::new(answers.into()),
            calls: Mutex::default(),
        }
    }

    fn describing(descriptors: &[SignedPoolDescriptorAnyV1]) -> Self {
        Self::answering(
            descriptors
                .iter()
                .map(|descriptor| {
                    Ok(serde_json::json!({
                        "descriptor_b64": base64::engine::general_purpose::STANDARD
                            .encode(descriptor.canonical_bytes().unwrap()),
                    }))
                })
                .collect(),
        )
    }
}

#[async_trait::async_trait]
impl PoolSessionTransport for &FakeTransport {
    async fn call(
        &self,
        route: &PoolMemberRouteV2,
        op: &'static str,
        _class: PoolCallClass,
        body: Value,
    ) -> Result<Value, PoolTransportError> {
        self.calls.lock().unwrap().push((route.clone(), op, body));
        self.answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(PoolTransportError::Unreachable))
    }
}

fn refusal_code(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<CustodyRefusal>()
        .map(CustodyRefusal::code)
        .unwrap_or("not a refusal")
}

#[tokio::test]
async fn known_pool_add_verifies_and_stores() {
    let (_dir, data_dir) = data_dir();
    let transport = FakeTransport::describing(&[descriptor(1), descriptor(4)]);
    let client = PoolSessionClient::new(&transport);
    let address = address_for(pool_did());

    let write = crate::custody_consent::lock_custody_writes().await;
    let view = add_known_pool_with(&write, &data_dir, &client, &address, NOW)
        .await
        .unwrap();
    assert_eq!(view.pool, pool_did().to_did_key().unwrap());
    assert_eq!(view.address, address);
    assert_eq!(view.sequence, 1);
    assert_eq!(view.members, 3);
    assert_eq!(view.servers, 3);
    assert_eq!(view.fetched_at, NOW);
    // The bootstrap member was asked `describe` for this pool.
    {
        let calls = transport.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, bootstrap());
        assert_eq!(calls[0].1, POOL_OP_DESCRIBE);
        assert_eq!(calls[0].2["pool"], pool_did().to_did_key().unwrap());
    }
    assert_eq!(known_pools(&data_dir).unwrap(), vec![view]);

    // Adding the same pool again replaces its descriptor; it is kept once.
    let view = add_known_pool_with(&write, &data_dir, &client, &address, NOW + 10)
        .await
        .unwrap();
    assert_eq!(view.sequence, 4);
    assert_eq!(known_pools(&data_dir).unwrap(), vec![view]);
    drop(write);

    // The known source hands the stored descriptor to the resolver.
    let source = KnownPoolSource::new(data_dir.clone(), Arc::new(ProviderRegistry::new()));
    let key_envelope = key_envelope_for(
        &pool_bundle(xwing, NOW),
        &EncryptedContentIdentityV1::new(Digest32::new([0x2b; 32]), 4096).unwrap(),
    );
    assert_eq!(source.candidates(&key_envelope).await, vec![descriptor(4)]);
}

#[tokio::test]
async fn known_pool_add_refuses_a_descriptor_for_another_pool() {
    let (_dir, data_dir) = data_dir();
    let write = crate::custody_consent::lock_custody_writes().await;

    // The address names another pool; its member answers with this one's.
    let transport = FakeTransport::describing(&[descriptor(1)]);
    let client = PoolSessionClient::new(&transport);
    let error = add_known_pool_with(&write, &data_dir, &client, &address_for(other_pool()), NOW)
        .await
        .unwrap_err();
    assert_eq!(refusal_code(&error), "pool_invalid");

    // The other refusals of S4-Q13.
    let error = add_known_pool_with(&write, &data_dir, &client, "elastos-pool:garbage", NOW)
        .await
        .unwrap_err();
    assert_eq!(refusal_code(&error), "bad_address");
    let unreachable = FakeTransport::answering(vec![Err(PoolTransportError::Unreachable)]);
    let error = add_known_pool_with(
        &write,
        &data_dir,
        &PoolSessionClient::new(&unreachable),
        &address_for(pool_did()),
        NOW,
    )
    .await
    .unwrap_err();
    assert_eq!(refusal_code(&error), "pool_unreachable");
    // A descriptor past its window does not verify.
    let stale = FakeTransport::describing(&[descriptor(1)]);
    let error = add_known_pool_with(
        &write,
        &data_dir,
        &PoolSessionClient::new(&stale),
        &address_for(pool_did()),
        NOW + 200_000,
    )
    .await
    .unwrap_err();
    assert_eq!(refusal_code(&error), "pool_invalid");

    assert!(known_pools(&data_dir).unwrap().is_empty());
    assert!(!known_pools_path(&data_dir).exists());
}

#[tokio::test]
async fn known_pools_file_is_owner_only_and_bounded() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_dir, data_dir) = data_dir();
    let write = crate::custody_consent::lock_custody_writes().await;
    let transport = FakeTransport::describing(&[descriptor(1)]);
    add_known_pool_with(
        &write,
        &data_dir,
        &PoolSessionClient::new(&transport),
        &address_for(pool_did()),
        NOW,
    )
    .await
    .unwrap();
    let path = known_pools_path(&data_dir);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // 32 pools are the limit: a 33rd is refused and nothing changes.
    let filler = KnownPoolEntry {
        address: "elastos-pool:filler".to_string(),
        descriptor_b64: String::new(),
        fetched_at: NOW,
    };
    let full = KnownPoolsFile {
        schema: KNOWN_POOLS_SCHEMA.to_string(),
        pools: vec![filler.clone(); MAX_KNOWN_POOLS],
    };
    store_known_pools(&write, &data_dir, &full).unwrap();
    let before = std::fs::read(&path).unwrap();
    let transport = FakeTransport::describing(&[descriptor(1)]);
    let error = add_known_pool_with(
        &write,
        &data_dir,
        &PoolSessionClient::new(&transport),
        &address_for(pool_did()),
        NOW,
    )
    .await
    .unwrap_err();
    assert_eq!(refusal_code(&error), "too_many_pools");
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let over = KnownPoolsFile {
        schema: KNOWN_POOLS_SCHEMA.to_string(),
        pools: vec![filler; MAX_KNOWN_POOLS + 1],
    };
    assert_eq!(
        refusal_code(&store_known_pools(&write, &data_dir, &over).unwrap_err()),
        "too_many_pools"
    );

    // A file over its byte bound, or readable by others, is refused on read.
    write_owner_only_bytes(&path, &vec![b' '; MAX_KNOWN_POOLS_FILE_BYTES + 1]).unwrap();
    assert!(known_pools(&data_dir).is_err());
    store_known_pools(&write, &data_dir, &full).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(known_pools(&data_dir).is_err());
}

#[tokio::test]
async fn resolver_sources_order_own_served_known() {
    let (_dir, data_dir) = data_dir();
    let registry = Arc::new(ProviderRegistry::new());
    let names = home_pool_sources(&data_dir, registry.clone())
        .iter()
        .map(|source| source.name())
        .collect::<Vec<_>>();
    assert_eq!(names, ["own", "served", "known"]);

    // With no pool of its own and none served, a known pool resolves.
    let write = crate::custody_consent::lock_custody_writes().await;
    let transport = FakeTransport::describing(&[descriptor(2)]);
    add_known_pool_with(
        &write,
        &data_dir,
        &PoolSessionClient::new(&transport),
        &address_for(pool_did()),
        NOW,
    )
    .await
    .unwrap();
    drop(write);
    let key_envelope = key_envelope_for(
        &pool_bundle(xwing, NOW),
        &EncryptedContentIdentityV1::new(Digest32::new([0x2b; 32]), 4096).unwrap(),
    );
    let resolved = home_pool_resolver(&data_dir, registry)
        .resolve(&key_envelope, &[], NOW)
        .await
        .unwrap();
    assert_eq!(resolved.source, "known");
    assert_eq!(resolved.descriptor.sequence(), 2);
}

/// Item 10: a buyer reaches every member of a resolved pool by its peer DID
/// through Carrier discovery, with a bounded answer wait; nothing in the
/// descriptor names a ticket.
#[test]
fn buyer_routes_every_member_by_peer_did() {
    let verified = descriptor(1).verify(NOW).unwrap();
    let buyer = KeptCardTickets::default();
    for member in verified.members() {
        for (class, wait) in [
            (PoolCallClass::Control, POOL_CONTROL_REPLY_WAIT_MS),
            (PoolCallClass::Read, POOL_READ_REPLY_WAIT_MS),
        ] {
            match carrier_route_for(member.route(), class, &buyer) {
                ProviderCarrierRoute::PeerDid {
                    peer_did,
                    timeout_ms,
                    reply_wait_ms,
                } => {
                    assert_eq!(peer_did, member.route().peer_did());
                    assert_eq!(timeout_ms, Some(POOL_CONNECT_TIMEOUT_MS));
                    assert_eq!(reply_wait_ms, Some(wait));
                }
                other => panic!("a buyer route is a peer DID: {other:?}"),
            }
        }
    }
}

/// A pool member that kept another member's node card dials that card's
/// ticket, still naming the peer and bounding the answer wait (S4-Q7); a
/// member without a kept card is reached by its peer DID.
#[test]
fn pool_member_dials_a_kept_card_and_bounds_its_answer_wait() {
    let carded = PoolMemberRouteV2::new("did:key:z6MkPoolNode02".to_string()).unwrap();
    let kept = KeptCardTickets::from([(
        "did:key:z6MkPoolNode02".to_string(),
        "card-ticket".to_string(),
    )]);
    match carrier_route_for(&carded, PoolCallClass::Control, &kept) {
        ProviderCarrierRoute::ConnectTicket {
            connect_ticket,
            peer_did,
            timeout_ms,
            reply_wait_ms,
        } => {
            assert_eq!(connect_ticket, "card-ticket");
            assert_eq!(peer_did.as_deref(), Some("did:key:z6MkPoolNode02"));
            assert_eq!(timeout_ms, Some(POOL_CONNECT_TIMEOUT_MS));
            assert_eq!(reply_wait_ms, Some(POOL_CONTROL_REPLY_WAIT_MS));
        }
        other => panic!("a kept-card route: {other:?}"),
    }
    assert!(matches!(
        carrier_route_for(&bootstrap(), PoolCallClass::Read, &kept),
        ProviderCarrierRoute::PeerDid { .. }
    ));
    // No verified route: nothing was sent. Anything else after an acting op
    // may have acted; `describe` never acts.
    let unavailable = ProviderError::Unavailable("no route".into());
    let timed_out = ProviderError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "wait"));
    assert_eq!(
        pool_call_failure("session.open", &unavailable),
        PoolTransportError::Unreachable
    );
    assert_eq!(
        pool_call_failure("session.open", &timed_out),
        PoolTransportError::NoExactResult
    );
    assert_eq!(
        pool_call_failure(POOL_OP_DESCRIBE, &timed_out),
        PoolTransportError::Unreachable
    );
}

/// Item 10: the address this Home writes is the v2 form, with the bootstrap
/// member's peer DID only. A historical v1 address with a ticket still
/// adds its pool, and the ticket is never used: the bootstrap is asked by
/// its peer DID.
#[tokio::test]
async fn pool_address_carries_no_ticket() {
    let written = address_for(pool_did());
    match crate::custody_pool_descriptor::parse_pool_address(&written).unwrap() {
        PoolAddressAnyV1::V2(address) => {
            assert_eq!(address.bootstrap(), &bootstrap());
        }
        PoolAddressAnyV1::V1(_) => panic!("writers emit the v2 address"),
    }

    let (_dir, data_dir) = data_dir();
    let write = crate::custody_consent::lock_custody_writes().await;
    let transport = FakeTransport::describing(&[descriptor(1)]);
    let legacy = v1_address_with_ticket(pool_did());
    add_known_pool_with(
        &write,
        &data_dir,
        &PoolSessionClient::new(&transport),
        &legacy,
        NOW,
    )
    .await
    .unwrap();
    let calls = transport.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, bootstrap());
    assert!(!calls[0].2.to_string().contains("v1-ticket"));
}

fn describe_answer(descriptor: &SignedPoolDescriptorAnyV1) -> Result<Value, PoolTransportError> {
    Ok(serde_json::json!({
        "descriptor_b64": base64::engine::general_purpose::STANDARD
            .encode(descriptor.canonical_bytes().unwrap()),
    }))
}

/// Answers every `describe` with `answer`, but only after `release`;
/// `entered` fires when a call arrives.
struct PausedTransport {
    answer: Value,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl PoolSessionTransport for &PausedTransport {
    async fn call(
        &self,
        _route: &PoolMemberRouteV2,
        _op: &'static str,
        _class: PoolCallClass,
        _body: Value,
    ) -> Result<Value, PoolTransportError> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(self.answer.clone())
    }
}

async fn add_answering(
    data_dir: &Path,
    address: &str,
    descriptor: SignedPoolDescriptorAnyV1,
) -> KnownPoolView {
    let write = crate::custody_consent::lock_custody_writes().await;
    let transport = FakeTransport::describing(&[descriptor]);
    add_known_pool_with(
        &write,
        data_dir,
        &PoolSessionClient::new(&transport),
        address,
        NOW,
    )
    .await
    .unwrap()
}

/// T43-F1: a refresh whose `describe` was paused while an Add stored a
/// newer descriptor rechecks the current entry under the lock and keeps the
/// newer one; an Add of an older descriptor keeps it too.
#[tokio::test]
async fn known_pool_refresh_keeps_a_newer_descriptor_stored_meanwhile() {
    let (_dir, data_dir) = data_dir();
    let address = address_for(pool_did());
    add_answering(&data_dir, &address, descriptor(1)).await;

    let paused = PausedTransport {
        answer: describe_answer(&descriptor(3)).unwrap(),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    };
    let client = PoolSessionClient::new(&paused);
    let concurrent_add = async {
        paused.entered.notified().await;
        assert_eq!(
            add_answering(&data_dir, &address, descriptor(5))
                .await
                .sequence,
            5
        );
        paused.release.notify_one();
    };
    let (replaced, ()) = tokio::join!(refresh_known_pools(&data_dir, &client, NOW), concurrent_add);
    assert_eq!(replaced.unwrap(), 0, "the older answer replaces nothing");
    let kept = known_pools(&data_dir).unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].sequence, 5);

    // The same monotonic rule on Add: an older answer keeps the newer entry.
    let view = add_answering(&data_dir, &address, descriptor(2)).await;
    assert_eq!(view.sequence, 5);
    assert_eq!(known_pools(&data_dir).unwrap(), vec![view]);
}

/// T43-F2: after the kept descriptor expired, its members' peer DIDs stay
/// discovery hints. With the bootstrap offline, a reachable member's newer
/// descriptor that verifies at now and is the pool's replaces it, and
/// resolution recovers. A hint's stale answer is never taken.
#[tokio::test]
async fn known_pool_refresh_after_expiry_reaches_a_kept_member() {
    let (_dir, data_dir) = data_dir();
    let address = address_for(pool_did());
    add_answering(&data_dir, &address, descriptor(1)).await;

    let later = NOW + 86_400 + 100;
    let bundle = pool_bundle(xwing, later);
    let renewed: SignedPoolDescriptorAnyV1 = pool_descriptor_with(
        &bundle,
        2,
        ServePolicyV1::DEFAULT,
        None,
        runtime_issuer(0x43),
        later,
    )
    .into();
    let key_envelope = key_envelope_for(
        &bundle,
        &EncryptedContentIdentityV1::new(Digest32::new([0x2b; 32]), 4096).unwrap(),
    );
    let registry = Arc::new(ProviderRegistry::new());
    assert!(home_pool_resolver(&data_dir, registry.clone())
        .resolve(&key_envelope, &[], later)
        .await
        .is_err());

    // A member answering a descriptor that does not verify at now is skipped.
    let stale = FakeTransport::answering(vec![
        Err(PoolTransportError::Unreachable),
        describe_answer(&descriptor(2)),
    ]);
    let replaced = refresh_known_pools(&data_dir, &PoolSessionClient::new(&stale), later)
        .await
        .unwrap();
    assert_eq!(replaced, 0);

    let transport = FakeTransport::answering(vec![
        Err(PoolTransportError::Unreachable),
        describe_answer(&renewed),
    ]);
    let replaced = refresh_known_pools(&data_dir, &PoolSessionClient::new(&transport), later)
        .await
        .unwrap();
    assert_eq!(replaced, 1);
    {
        let calls = transport.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, bootstrap());
        assert_ne!(calls[1].0, bootstrap(), "the bootstrap is asked once");
        assert!(descriptor(1)
            .verify(NOW)
            .unwrap()
            .members()
            .iter()
            .any(|member| member.route() == &calls[1].0));
    }
    let resolved = home_pool_resolver(&data_dir, registry)
        .resolve(&key_envelope, &[], later)
        .await
        .unwrap();
    assert_eq!(resolved.source, "known");
    assert_eq!(resolved.descriptor.sequence(), 2);
}

// ---------------------------------------------------------------------------
// Buyer content holders: the members of the pools this Home uses
// ---------------------------------------------------------------------------

/// Keeps the fixture pool (verified until `NOW + 1 day`) as the one pool this
/// Home uses, and answers its members' peer DIDs. Carrier's tests use it too.
pub(crate) async fn keep_fixture_known_pool_for_test(data_dir: &Path) -> Vec<String> {
    let kept = descriptor(1);
    let write = crate::custody_consent::lock_custody_writes().await;
    keep_known_pool_for_test(&write, data_dir, &address_for(pool_did()), &kept, NOW).unwrap();
    kept.verify(NOW)
        .unwrap()
        .members()
        .iter()
        .map(|member| member.route().peer_did().to_string())
        .collect()
}

/// The time the fixture pool is current at.
pub(crate) const FIXTURE_NOW: u64 = NOW;

#[tokio::test]
async fn a_buyer_with_one_known_pool_lists_its_members_as_holder_candidates() {
    let (_dir, data_dir) = data_dir();
    let members = keep_fixture_known_pool_for_test(&data_dir).await;
    assert!(!members.is_empty());
    assert_eq!(known_pool_member_peer_dids(&data_dir, NOW), members);
}

#[tokio::test]
async fn an_expired_or_unverified_descriptor_contributes_nobody() {
    let (_dir, data_dir) = data_dir();
    keep_fixture_known_pool_for_test(&data_dir).await;
    // Past the descriptor's term: not current, so nobody.
    assert!(known_pool_member_peer_dids(&data_dir, NOW + 30 * 86_400).is_empty());

    // A descriptor whose signature does not verify.
    let (_other_dir, other) = self::data_dir();
    let SignedPoolDescriptorAnyV1::V3(good) = descriptor(1) else {
        panic!("writers emit v3");
    };
    let forged: SignedPoolDescriptorAnyV1 =
        elastos_protected_content_contracts::SignedPoolDescriptorV3::new(
            good.statement().clone(),
            vec![0; good.authority_signature().len()],
        )
        .unwrap()
        .into();
    let write = crate::custody_consent::lock_custody_writes().await;
    keep_known_pool_for_test(&write, &other, &address_for(pool_did()), &forged, NOW).unwrap();
    drop(write);
    assert!(known_pool_member_peer_dids(&other, NOW).is_empty());
}

#[test]
fn holder_candidates_are_bounded_and_unique() {
    let dids = (0..20).map(|index| format!("did:key:z6MkMember{index:02}"));
    let doubled = dids.clone().chain(dids);
    let bounded = bounded_unique_peer_dids(doubled);
    assert_eq!(bounded.len(), MAX_KNOWN_POOL_CONTENT_HOLDERS);
    assert_eq!(MAX_KNOWN_POOL_CONTENT_HOLDERS, 8);
    let unique: std::collections::BTreeSet<_> = bounded.iter().collect();
    assert_eq!(unique.len(), bounded.len());
}

#[test]
fn no_known_pools_means_no_holder_candidates() {
    let (_dir, data_dir) = data_dir();
    assert!(known_pool_member_peer_dids(&data_dir, NOW).is_empty());
}
